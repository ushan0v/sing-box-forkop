package box

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"

	"github.com/stretchr/testify/require"
)

const mebibyte = 1 << 20

type fakeMemory struct {
	t     *testing.T
	files memoryFiles
}

func newFakeMemory(t *testing.T) *fakeMemory {
	directory := t.TempDir()
	return &fakeMemory{t: t, files: memoryFiles{
		meminfo:    filepath.Join(directory, "meminfo"),
		status:     filepath.Join(directory, "status"),
		cgroup:     filepath.Join(directory, "cgroup"),
		cgroupRoot: filepath.Join(directory, "fs"),
	}}
}

func (m *fakeMemory) write(path string, content string) {
	require.NoError(m.t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(m.t, os.WriteFile(path, []byte(content), 0o644))
}

func (m *fakeMemory) system(availableKB, fileKB uint64) {
	m.write(m.files.meminfo, "MemTotal:  126000 kB\nMemFree:   20000 kB\nMemAvailable:   "+itoa(availableKB)+" kB\n")
	m.write(m.files.status, "Name:\tsing-box\nVmRSS:\t40000 kB\nRssAnon:\t15000 kB\nRssFile:\t"+itoa(fileKB)+" kB\n")
}

func itoa(value uint64) string {
	return strconv.FormatUint(value, 10)
}

// A router without a cgroup: the memory of Go plus MemAvailable, less the most of our code
// ever resident, which stays out when the kernel evicts some of it.
func TestMemoryLimitSystem(t *testing.T) {
	memory := newFakeMemory(t)
	memory.system(60*1024, 22*1024)
	memory.write(memory.files.cgroup, "0::/\n")
	limiter := newMemoryLimiter(memory.files)
	held := goMemory{held: 15 * mebibyte, floor: 5 * mebibyte}

	limit, known := limiter.compute(held)
	require.True(t, known)
	require.Equal(t, uint64(53*mebibyte), limit)

	memory.system(60*1024, 10*1024) // part of our code was evicted
	limit, _ = limiter.compute(held)
	require.Equal(t, uint64(53*mebibyte), limit, "eviction of our code raised the limit")

	// others took memory and left the system less than our code: the limit drops below
	// the memory Go holds by the shortfall, down to what cannot be given back
	memory.system(18*1024, 22*1024)
	limit, _ = limiter.compute(held)
	require.Equal(t, uint64(11*mebibyte), limit)
	memory.system(2*1024, 22*1024)
	limit, _ = limiter.compute(held)
	require.Equal(t, uint64(5*mebibyte), limit, "the limit went below the floor")
}

// In a cgroup with a limit the room under it, with the file cache the cgroup can reclaim,
// counts when it is less, and the tightest of the cgroup and its parents wins.
func TestMemoryLimitCgroup(t *testing.T) {
	memory := newFakeMemory(t)
	memory.system(1024*1024, 22*1024)
	memory.write(memory.files.cgroup, "0::/services/sing-box\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "services/sing-box/memory.max"), "max\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "services/sing-box/memory.current"), "41943040\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "services/memory.max"), "167772160\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "services/memory.current"), "104857600\n")
	limiter := newMemoryLimiter(memory.files)
	held := goMemory{held: 15 * mebibyte}

	limit, known := limiter.compute(held)
	require.True(t, known)
	require.Equal(t, uint64(53*mebibyte), limit) // 15 + (160 - 100) - 22

	memory.write(filepath.Join(memory.files.cgroupRoot, "services/memory.stat"), "anon 73400320\nfile 31457280\n")
	limit, _ = limiter.compute(held)
	require.Equal(t, uint64(83*mebibyte), limit) // 15 + (160 - 100 + 30) - 22
}

// cgroup v1: no limit is reported as a value near 2^63; the cache is total_cache.
func TestMemoryLimitCgroupV1(t *testing.T) {
	memory := newFakeMemory(t)
	memory.system(60*1024, 22*1024)
	memory.write(memory.files.cgroup, "4:memory:/\n1:cpu,cpuacct:/\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "memory/memory.limit_in_bytes"), "9223372036854771712\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "memory/memory.usage_in_bytes"), "52428800\n")
	limiter := newMemoryLimiter(memory.files)
	held := goMemory{held: 15 * mebibyte}
	limit, _ := limiter.compute(held)
	require.Equal(t, uint64(53*mebibyte), limit)

	memory.write(filepath.Join(memory.files.cgroupRoot, "memory/memory.limit_in_bytes"), "83886080\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "memory/memory.stat"), "cache 1\ntotal_cache 10485760\n")
	limit, _ = limiter.compute(held)
	require.Equal(t, uint64(33*mebibyte), limit) // 15 + (80 - 50 + 10) - 22
}

// The memory Go holds, as the runtime reports it, and its part that cannot be given back.
func TestReadGoMemory(t *testing.T) {
	memory := readGoMemory(newGoMemorySamples())
	require.Positive(t, memory.held)
	require.Greater(t, memory.floor, uint64(heapMinimum), "no room above what cannot be given back")
}

// A hybrid hierarchy keeps the memory controller in cgroup v1: its limit counts, not the
// unified hierarchy without a memory limit. tmpfs and shared memory are not reclaimable.
func TestMemoryLimitCgroupHybrid(t *testing.T) {
	memory := newFakeMemory(t)
	memory.system(1024*1024, 22*1024)
	memory.write(memory.files.cgroup, "0::/system.slice/sing-box.service\n5:memory:/system.slice/sing-box.service\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "memory/system.slice/sing-box.service/memory.limit_in_bytes"), "134217728\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "memory/system.slice/sing-box.service/memory.usage_in_bytes"), "104857600\n")
	memory.write(filepath.Join(memory.files.cgroupRoot, "memory/system.slice/sing-box.service/memory.stat"), "cache 1\ntotal_cache 31457280\ntotal_shmem 20971520\n")
	limiter := newMemoryLimiter(memory.files)
	limit, known := limiter.compute(goMemory{held: 15 * mebibyte})
	require.True(t, known)
	require.Equal(t, uint64(31*mebibyte), limit) // 15 + (128 - 100 + (30 - 20)) - 22
}

// Nothing to read: no limit.
func TestMemoryLimitUnknown(t *testing.T) {
	memory := newFakeMemory(t)
	limiter := newMemoryLimiter(memory.files)
	_, known := limiter.compute(goMemory{held: 15 * mebibyte})
	require.False(t, known)
}

// A limit set by hand switches the automatic one off; otherwise it is set, and lifted on
// close.
func TestMemoryLimitStart(t *testing.T) {
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(-1))
	logger := log.NewNOPFactory().Logger()

	t.Setenv("GOMEMLIMIT", "off")
	before := debug.SetMemoryLimit(-1)
	startMemoryLimit(logger, option.DebugOptions{})()
	require.Equal(t, before, debug.SetMemoryLimit(-1))

	t.Setenv("GOMEMLIMIT", "")
	if _, known := newMemoryLimiter(systemMemoryFiles).readValue(systemMemoryFiles.meminfo, "MemAvailable:"); !known {
		t.Skip("no /proc/meminfo")
	}
	stop := startMemoryLimit(logger, option.DebugOptions{})
	require.Less(t, debug.SetMemoryLimit(-1), before)
	stop()
	require.Equal(t, before, debug.SetMemoryLimit(-1))
}

// Across a reload the old instance stops after the new one started: the limit stays until
// the last of them stops, and a limit the new one sets by hand outlives the old one.
func TestMemoryLimitShared(t *testing.T) {
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(-1))
	logger := log.NewNOPFactory().Logger()
	t.Setenv("GOMEMLIMIT", "")
	if _, known := newMemoryLimiter(systemMemoryFiles).readValue(systemMemoryFiles.meminfo, "MemAvailable:"); !known {
		t.Skip("no /proc/meminfo")
	}
	before := debug.SetMemoryLimit(-1)

	stopOld := startMemoryLimit(logger, option.DebugOptions{})
	stopNew := startMemoryLimit(logger, option.DebugOptions{})
	stopOld()
	require.Less(t, debug.SetMemoryLimit(-1), before)
	stopNew()
	require.Equal(t, before, debug.SetMemoryLimit(-1))

	var byHand byteformats.MemoryBytes
	require.NoError(t, byHand.UnmarshalJSON([]byte(`"96MB"`)))
	stopOld = startMemoryLimit(logger, option.DebugOptions{})
	debug.SetMemoryLimit(64 * mebibyte)
	stopNew = startMemoryLimit(logger, option.DebugOptions{MemoryLimit: &byHand})
	stopOld()
	require.Equal(t, int64(64*mebibyte), debug.SetMemoryLimit(-1))
	stopNew()
	require.Equal(t, int64(64*mebibyte), debug.SetMemoryLimit(-1))
}
