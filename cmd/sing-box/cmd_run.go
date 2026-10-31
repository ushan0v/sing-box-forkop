package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	runtimeDebug "runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/service"

	"github.com/spf13/cobra"
)

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run service",
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	mainCommand.AddCommand(commandRun)
}

type OptionsEntry struct {
	content []byte
	path    string
	options option.Options
}

func readConfigAt(path string) (*OptionsEntry, error) {
	var (
		configContent []byte
		err           error
	)
	if path == "stdin" {
		configContent, err = io.ReadAll(os.Stdin)
	} else {
		configContent, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, E.Cause(err, "read config at ", path)
	}
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, configContent)
	if err != nil {
		return nil, E.Cause(err, "decode config at ", path)
	}
	return &OptionsEntry{
		content: configContent,
		path:    path,
		options: options,
	}, nil
}

func readConfig() ([]*OptionsEntry, error) {
	var optionsList []*OptionsEntry
	for _, path := range configPaths {
		optionsEntry, err := readConfigAt(path)
		if err != nil {
			return nil, err
		}
		optionsList = append(optionsList, optionsEntry)
	}
	for _, directory := range configDirectories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, E.Cause(err, "read config directory at ", directory)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") || entry.IsDir() {
				continue
			}
			optionsEntry, err := readConfigAt(filepath.Join(directory, entry.Name()))
			if err != nil {
				return nil, err
			}
			optionsList = append(optionsList, optionsEntry)
		}
	}
	sort.Slice(optionsList, func(i, j int) bool {
		return optionsList[i].path < optionsList[j].path
	})
	return optionsList, nil
}

func readConfigAndMerge() (option.Options, error) {
	optionsList, err := readConfig()
	if err != nil {
		return option.Options{}, err
	}
	return mergeOptionsList(optionsList)
}

func mergeOptionsList(optionsList []*OptionsEntry) (option.Options, error) {
	if len(optionsList) == 1 {
		return optionsList[0].options, nil
	}
	var (
		mergedMessage json.RawMessage
		err           error
	)
	for _, options := range optionsList {
		mergedMessage, err = badjson.MergeJSON(globalCtx, options.options.RawMessage, mergedMessage, false)
		if err != nil {
			return option.Options{}, E.Cause(err, "merge config at ", options.path)
		}
	}
	var mergedOptions option.Options
	err = mergedOptions.UnmarshalJSONContext(globalCtx, mergedMessage)
	if err != nil {
		return option.Options{}, E.Cause(err, "unmarshal merged config")
	}
	return mergedOptions, nil
}

func create(options option.Options) (*box.Box, context.CancelFunc, error) {
	if disableColor {
		if options.Log == nil {
			options.Log = &option.LogOptions{}
		}
		options.Log.DisableColor = true
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(globalCtx))
	instance, err := box.New(box.Options{
		Context:                    ctx,
		Options:                    options,
		NetworkNamespaceHolderArgs: []string{"/proc/self/exe", commandNetnsHolder.Use},
	})
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "create service")
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(osSignals)
		close(osSignals)
	}()
	startCtx, finishStart := context.WithCancel(context.Background())
	go func() {
		_, loaded := <-osSignals
		if loaded {
			cancel()
			closeMonitor(startCtx)
		}
	}()
	err = instance.Start()
	finishStart()
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "start service")
	}
	return instance, cancel, nil
}

func run() error {
	optionsList, err := readConfig()
	if err != nil {
		return err
	}
	options, err := mergeOptionsList(optionsList)
	if err != nil {
		return err
	}
	err = runInUserNamespaceIfNeeded(options, optionsList)
	if err != nil {
		return err
	}
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(osSignals)
	running, err := startService(options)
	if err != nil {
		return err
	}
	for {
		osSignal := <-osSignals
		if osSignal != syscall.SIGHUP {
			running.close()
			return nil
		}
		err = checkForReload()
		if err == nil {
			options, err = readConfigAndMerge()
		}
		if err != nil {
			log.Error(E.Cause(err, "reload service"))
			continue
		}
		err = running.reload(options)
		if err != nil {
			return err
		}
	}
}

// reloadDrainTimeout bounds how long the instance a reload replaced keeps its connections.
const reloadDrainTimeout = 30 * time.Second

// runningService is the instance serving and the one a reload replaced, which keeps the
// connections it has until they end.
type runningService struct {
	instance *box.Box
	cancel   context.CancelFunc
	retiring *retiringInstance
}

func startService(options option.Options) (*runningService, error) {
	instance, cancel, err := create(options)
	if err != nil {
		return nil, err
	}
	runtimeDebug.FreeOSMemory()
	return &runningService{instance: instance, cancel: cancel}, nil
}

// reload starts an instance of options beside the serving one, which hands its listeners
// over and keeps its connections; without the memory for both, it restarts instead. An
// error leaves nothing running.
func (s *runningService) reload(options option.Options) error {
	s.retiring.close()
	s.retiring = nil
	if !roomForReload() {
		log.Warn("reload service: too little memory to keep the connections, restarting")
		err := closeInstance(s.instance, s.cancel)
		if err != nil {
			log.Error(E.Cause(err, "close service"))
		}
		runtimeDebug.FreeOSMemory()
		s.instance, s.cancel, err = create(options)
		if err != nil {
			return err
		}
		runtimeDebug.FreeOSMemory()
		return nil
	}
	err := s.instance.Release()
	if err != nil {
		log.Warn(E.Cause(err, "release service"))
	}
	instance, cancel, err := create(options)
	if err != nil {
		closeInstance(s.instance, s.cancel)
		return err
	}
	err = s.instance.CloseReleasedListeners()
	if err != nil {
		log.Warn(E.Cause(err, "close released listeners"))
	}
	s.retiring = retire(s.instance, s.cancel)
	s.instance, s.cancel = instance, cancel
	return nil
}

func (s *runningService) close() {
	s.retiring.close()
	err := closeInstance(s.instance, s.cancel)
	if err != nil {
		log.Error(E.Cause(err, "sing-box did not closed properly"))
	}
}

func closeInstance(instance *box.Box, cancel context.CancelFunc) error {
	cancel()
	closeCtx, closed := context.WithCancel(context.Background())
	go closeMonitor(closeCtx)
	err := instance.Close()
	closed()
	return err
}

type retiringInstance struct {
	instance  *box.Box
	cancel    context.CancelFunc
	closeOnce sync.Once
	closed    chan struct{}
}

func retire(instance *box.Box, cancel context.CancelFunc) *retiringInstance {
	retiring := &retiringInstance{instance: instance, cancel: cancel, closed: make(chan struct{})}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		deadline := time.Now().Add(reloadDrainTimeout)
		for instance.ConnectionCount() > 0 && time.Now().Before(deadline) {
			select {
			case <-retiring.closed:
				return
			case <-ticker.C:
			}
		}
		retiring.close()
	}()
	return retiring
}

func (r *retiringInstance) close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		err := closeInstance(r.instance, r.cancel)
		if err != nil {
			log.Error(E.Cause(err, "close replaced service"))
		}
		close(r.closed)
		runtimeDebug.FreeOSMemory()
	})
}

// roomForReload tells whether the system can give a new instance about what the serving one
// holds, with room for the collector, while both are alive.
var roomForReload = func() bool {
	content, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(content), "\n") {
		value, found := strings.CutPrefix(line, "MemAvailable:")
		if !found {
			continue
		}
		available, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(value), " kB"), 10, 64)
		if err != nil {
			return true
		}
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return available*1024 >= stats.HeapInuse*3/2
	}
	return true
}

// A check builds the configuration and closes it unstarted, which leaves running what a component
// starts while built, such as a WireGuard endpoint's netstack; a reload checks in its own process.
func checkForReload() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"check", "--disable-color"}
	for _, path := range configPaths {
		args = append(args, "--config", path)
	}
	for _, directory := range configDirectories {
		args = append(args, "--config-directory", directory)
	}
	output, err := exec.Command(executable, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	message := lines[len(lines)-1]
	if strings.HasPrefix(message, "FATAL[") {
		_, message, _ = strings.Cut(message, "] ")
	}
	if message == "" {
		return err
	}
	return E.New(message)
}

func closeMonitor(ctx context.Context) {
	time.Sleep(C.FatalStopTimeout)
	select {
	case <-ctx.Done():
		return
	default:
	}
	log.Fatal("sing-box did not close!")
}
