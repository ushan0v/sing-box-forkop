package box

import (
	"bytes"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"sync"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
)

// The soft memory limit of the Go runtime follows the memory the system can still give
// (podkop-engine).
//
// Without a limit the collector lets the heap grow to twice its live size before it runs,
// so under load a router with 128 MB meets the OOM killer, and the proxy and its DNS go
// down with it. The limit is
//
//	the memory of Go now + the memory the system can still give - the pages of our code
//
// The system can still give MemAvailable of /proc/meminfo (free memory and reclaimable
// cache; the kernel keeps its own watermarks out of it) or, in a cgroup with a memory
// limit, the limit minus the usage plus the file cache the cgroup can reclaim (its tmpfs
// and shared memory cannot be reclaimed without swap), whichever is less. Both count the
// resident pages of our binary as reclaimable cache, but evicting our own code means
// reading it back from flash, so the most of them ever resident is kept out (the most, so
// that eviction does not raise the limit). The limit is thus the memory of Go at which the
// system would have to start evicting our code. Our own allocations do not move it (the
// memory of Go grows by what the system loses); memory that others take or give back
// does, and when others leave the system less than our code, the limit drops below the
// memory Go holds by the shortfall, so that the collector and the scavenger give back
// garbage and free pages. It never drops below what they cannot give back (the live heap
// and the memory of the runtime itself) plus the smallest heap goal of the runtime (4 MiB
// at GOGC=100, runtime/mgcpacer.go): with less room the collector would run again on the
// first allocation after every cycle and free nothing. It is computed again after every
// garbage collection, which the runtime runs at least every two minutes. GOMEMLIMIT or
// experimental.debug.memory_limit set by hand switch it off.

type memoryFiles struct {
	meminfo    string
	status     string
	cgroup     string
	cgroupRoot string
}

var systemMemoryFiles = memoryFiles{
	meminfo:    "/proc/meminfo",
	status:     "/proc/self/status",
	cgroup:     "/proc/self/cgroup",
	cgroupRoot: "/sys/fs/cgroup",
}

type memoryLimiter struct {
	files    memoryFiles
	logger   log.ContextLogger
	buffer   []byte // the files are read into it: a computation after every collection allocates next to nothing
	samples  []metrics.Sample
	fileHigh uint64
	updates  chan struct{}
	done     chan struct{}
	access   sync.Mutex
	limit    uint64
	closed   bool
}

// The limit belongs to the process, while a reload keeps the old instance alive beside the
// new one: they share one limiter, and it lifts the limit when the last of them stops.
var sharedMemoryLimit struct {
	access  sync.Mutex
	limiter *memoryLimiter
	users   int
}

// startMemoryLimit sets the limit and keeps it following the system; the returned function
// stops that and lifts the limit.
func startMemoryLimit(logger log.ContextLogger, options option.DebugOptions) func() {
	shared := &sharedMemoryLimit
	shared.access.Lock()
	defer shared.access.Unlock()
	if os.Getenv("GOMEMLIMIT") != "" || options.MemoryLimit.Value() != 0 {
		// The limit set by hand is already in force; the limiter would overwrite it, and
		// lift it once the old instance stops.
		if shared.limiter != nil {
			shared.limiter.stop()
			shared.limiter = nil
		}
		return func() {}
	}
	if shared.limiter == nil {
		limiter := newMemoryLimiter(systemMemoryFiles)
		limiter.logger = logger
		limit, known := limiter.compute(readGoMemory(limiter.samples))
		if !known {
			logger.Debug("memory limit: the available memory is unknown, no limit set")
			return func() {}
		}
		limiter.limit = limit
		debug.SetMemoryLimit(int64(limit))
		logger.Info("memory limit ", byteformats.FormatMemoryBytes(limit), ", following the available memory")
		go limiter.loop()
		limiter.armGC()
		shared.limiter = limiter
		shared.users = 0
	}
	shared.users++
	limiter := shared.limiter
	return func() {
		shared.access.Lock()
		defer shared.access.Unlock()
		if shared.limiter != limiter {
			return
		}
		shared.users--
		if shared.users == 0 {
			limiter.close()
			shared.limiter = nil
		}
	}
}

func newMemoryLimiter(files memoryFiles) *memoryLimiter {
	return &memoryLimiter{
		files:   files,
		buffer:  make([]byte, 8192),
		samples: newGoMemorySamples(),
		updates: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
}

func (l *memoryLimiter) compute(memory goMemory) (uint64, bool) {
	available := int64(math.MaxInt64)
	known := false
	if memAvailable, loaded := l.readValue(l.files.meminfo, "MemAvailable:"); loaded {
		available = int64(memAvailable * 1024)
		known = true
	}
	if cgroupAvailable, loaded := l.cgroupAvailable(); loaded {
		available = min(available, int64(cgroupAvailable))
		known = true
	}
	if !known {
		return 0, false
	}
	if resident, loaded := l.readValue(l.files.status, "RssFile:"); loaded {
		l.fileHigh = max(l.fileHigh, resident*1024)
	}
	limit := int64(memory.held) + available - int64(l.fileHigh)
	return uint64(max(limit, int64(memory.floor))), true
}

func (l *memoryLimiter) loop() {
	for {
		select {
		case <-l.updates:
			limit, known := l.compute(readGoMemory(l.samples))
			l.access.Lock()
			if known && !l.closed && limit != l.limit {
				l.limit = limit
				debug.SetMemoryLimit(int64(limit))
			}
			l.access.Unlock()
		case <-l.done:
			return
		}
	}
}

func (l *memoryLimiter) close() {
	if l.stop() {
		debug.SetMemoryLimit(math.MaxInt64)
	}
}

// stop stops following the system and leaves the limit as it is.
func (l *memoryLimiter) stop() bool {
	l.access.Lock()
	defer l.access.Unlock()
	if l.closed {
		return false
	}
	l.closed = true
	close(l.done)
	return true
}

func (l *memoryLimiter) isClosed() bool {
	l.access.Lock()
	defer l.access.Unlock()
	return l.closed
}

// gcSentinel is collected by every garbage collection; its finalizer asks for an update and
// sets up the next one. It holds a pointer, so it is never a tiny allocation, whose
// finalizer may not run.
type gcSentinel struct {
	limiter *memoryLimiter
}

func (l *memoryLimiter) armGC() {
	runtime.SetFinalizer(&gcSentinel{limiter: l}, func(sentinel *gcSentinel) {
		if sentinel.limiter.isClosed() {
			return
		}
		select {
		case sentinel.limiter.updates <- struct{}{}:
		default:
		}
		sentinel.limiter.armGC()
	})
}

// goMemory is the memory the limit is compared with (all the runtime maps, less the heap
// memory given back to the system) and the lowest limit worth setting: what the collector
// and the scavenger cannot give back (all but the free heap pages and the dead objects)
// plus the smallest heap goal of the runtime.
type goMemory struct {
	held  uint64
	floor uint64
}

func newGoMemorySamples() []metrics.Sample {
	return []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/gc/heap/live:bytes"},
		{Name: "/gc/gogc:percent"},
	}
}

// heapMinimum is the smallest heap goal of the runtime at GOGC=100 (runtime/mgcpacer.go);
// it scales with GOGC.
const heapMinimum = 4 << 20

func readGoMemory(samples []metrics.Sample) goMemory {
	metrics.Read(samples)
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	free, objects, live := samples[2].Value.Uint64(), samples[3].Value.Uint64(), samples[4].Value.Uint64()
	gcPercent := samples[5].Value.Uint64()
	if gcPercent == 0 || gcPercent > 1<<20 { // the collector is off: the limit alone starts it
		gcPercent = 100
	}
	held := total - min(total, released)
	reclaimable := free + objects - min(objects, live)
	return goMemory{held: held, floor: held - min(held, reclaimable) + heapMinimum*gcPercent/100}
}

// read reads a small file of /proc or /sys into the limiter's buffer.
func (l *memoryLimiter) read(path string) ([]byte, bool) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	n, err := io.ReadFull(file, l.buffer)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, false
	}
	return l.buffer[:n], true
}

// readValue reads the number after key at the start of a line ("MemAvailable:  1234 kB",
// "file 4096").
func (l *memoryLimiter) readValue(path string, key string) (uint64, bool) {
	content, loaded := l.read(path)
	if !loaded {
		return 0, false
	}
	return findValue(content, key)
}

func findValue(content []byte, key string) (uint64, bool) {
	for len(content) > 0 {
		line := content
		if end := bytes.IndexByte(content, '\n'); end >= 0 {
			line, content = content[:end], content[end+1:]
		} else {
			content = nil
		}
		if len(line) <= len(key) || string(line[:len(key)]) != key {
			continue
		}
		fields := bytes.Fields(line[len(key):])
		if len(fields) == 0 {
			return 0, false
		}
		value, err := strconv.ParseUint(string(fields[0]), 10, 64)
		return value, err == nil
	}
	return 0, false
}

// cgroupAvailable is the least room left under the memory limits of our cgroup and its
// parents: the memory controller of cgroup v1 when the hierarchy has one (a hybrid
// hierarchy keeps it there), else cgroup v2.
func (l *memoryLimiter) cgroupAvailable() (uint64, bool) {
	content, loaded := l.read(l.files.cgroup)
	if !loaded {
		return 0, false
	}
	var directory, limitFile, usageFile, cacheKey, sharedKey string
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte{'\n'}) {
		parts := bytes.SplitN(line, []byte{':'}, 3)
		if len(parts) != 3 {
			continue
		}
		if string(parts[0]) == "0" && len(parts[1]) == 0 {
			if directory == "" {
				directory, limitFile, usageFile, cacheKey, sharedKey = filepath.Join(l.files.cgroupRoot, string(parts[2])), "memory.max", "memory.current", "file", "shmem"
			}
			continue
		}
		for _, controller := range bytes.Split(parts[1], []byte{','}) {
			if string(controller) == "memory" {
				directory, limitFile, usageFile, cacheKey, sharedKey = filepath.Join(l.files.cgroupRoot, "memory", string(parts[2])), "memory.limit_in_bytes", "memory.usage_in_bytes", "total_cache", "total_shmem"
			}
		}
	}
	if directory == "" {
		return 0, false
	}
	available, limited := uint64(math.MaxUint64), false
	root := filepath.Clean(l.files.cgroupRoot)
	for {
		limit, limitLoaded := l.readCgroupValue(filepath.Join(directory, limitFile))
		usage, usageLoaded := l.readCgroupValue(filepath.Join(directory, usageFile))
		if limitLoaded && usageLoaded && limit < 1<<62 { // v1 reports no limit as a value near 2^63
			var reclaimable uint64
			if stat, statLoaded := l.read(filepath.Join(directory, "memory.stat")); statLoaded {
				cache, _ := findValue(stat, cacheKey+" ")
				shared, _ := findValue(stat, sharedKey+" ")
				reclaimable = cache - min(cache, shared)
			}
			available = min(available, limit-min(limit, usage-min(usage, reclaimable)))
			limited = true
		}
		if directory == root || len(directory) <= len(root) {
			break
		}
		directory = filepath.Dir(directory)
	}
	return available, limited
}

func (l *memoryLimiter) readCgroupValue(path string) (uint64, bool) {
	content, loaded := l.read(path)
	if !loaded {
		return 0, false
	}
	text := string(bytes.TrimSpace(content))
	if text == "max" {
		return math.MaxUint64, true
	}
	value, err := strconv.ParseUint(text, 10, 64)
	return value, err == nil
}
