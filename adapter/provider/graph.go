package provider

import (
	"reflect"
	"sort"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
)

// FilterInvalidOutbounds removes chains that depend on an entry which was
// present in the source but could not be imported.
func FilterInvalidOutbounds(outbounds []option.Outbound, invalidTags map[string]bool) []option.Outbound {
	invalid := make(map[string]bool, len(invalidTags))
	for tag := range invalidTags {
		invalid[tag] = true
	}
	knownTags := make(map[string]string, len(outbounds)+len(invalid))
	for tag := range invalid {
		knownTags[tag] = tag
	}
	byTag := make(map[string]int, len(outbounds))
	for index, outbound := range outbounds {
		if outbound.Tag == "" {
			continue
		}
		knownTags[outbound.Tag] = outbound.Tag
		if _, exists := byTag[outbound.Tag]; !exists {
			byTag[outbound.Tag] = index
		}
	}
	dependencies := make([][]string, len(outbounds))
	for index, outbound := range outbounds {
		dependencies[index] = rewriteOutboundReferences(cloneOptions(outbound.Options), knownTags)
	}
	const (
		visiting = iota + 1
		valid
		invalidState
	)
	states := make([]uint8, len(outbounds))
	var isValid func(int) bool
	isValid = func(index int) bool {
		switch states[index] {
		case visiting, invalidState:
			return false
		case valid:
			return true
		}
		states[index] = visiting
		for _, dependency := range dependencies[index] {
			if invalid[dependency] {
				states[index] = invalidState
				return false
			}
			if dependencyIndex, internal := byTag[dependency]; internal && !isValid(dependencyIndex) {
				states[index] = invalidState
				return false
			}
		}
		states[index] = valid
		return true
	}
	result := make([]option.Outbound, 0, len(outbounds))
	for index, outbound := range outbounds {
		if isValid(index) {
			result = append(result, outbound)
		}
	}
	return result
}

type preparedOutbound struct {
	source       option.Outbound
	runtime      option.Outbound
	tag          string
	dependencies []string
	position     int
}

func prepareOutbounds(providerTag string, outbounds []option.Outbound, outboundDetour string) ([]preparedOutbound, error) {
	tags := make(map[string]string, len(outbounds))
	for _, outbound := range outbounds {
		if outbound.Tag != "" {
			tags[outbound.Tag] = F.ToString(providerTag, "/", outbound.Tag)
		}
	}

	prepared := make([]preparedOutbound, 0, len(outbounds))
	for index, source := range outbounds {
		runtime := source
		runtime.Tag = tags[source.Tag]
		if runtime.Tag == "" {
			runtime.Tag = F.ToString(providerTag, "/", index)
		}
		runtime.Options = cloneOptions(source.Options)
		applyDefaultDetour(runtime.Options, outboundDetour)
		dependencies := rewriteOutboundReferences(runtime.Options, tags)
		prepared = append(prepared, preparedOutbound{
			source:       source,
			runtime:      runtime,
			tag:          runtime.Tag,
			dependencies: dependencies,
			position:     index,
		})
	}
	return sortOutbounds(prepared)
}

func applyDefaultDetour(options any, detour string) {
	if detour == "" {
		return
	}
	dialer, loaded := options.(option.DialerOptionsWrapper)
	if !loaded {
		return
	}
	dialerOptions := dialer.TakeDialerOptions()
	if dialerOptions.Detour != "" {
		return
	}
	dialerOptions.Detour = detour
	dialer.ReplaceDialerOptions(dialerOptions)
}

func sourceOrder(outbounds []preparedOutbound) []preparedOutbound {
	result := append([]preparedOutbound(nil), outbounds...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].position < result[j].position })
	return result
}

func cloneOptions(options any) any {
	value := reflect.ValueOf(options)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return options
	}
	cloned := reflect.New(value.Elem().Type())
	cloned.Elem().Set(value.Elem())
	result := cloned.Interface()
	switch outbound := result.(type) {
	case *option.VLESSOutboundOptions:
		outbound.Transport = cloneV2RayTransport(outbound.Transport)
	case *option.VMessOutboundOptions:
		outbound.Transport = cloneV2RayTransport(outbound.Transport)
	case *option.TrojanOutboundOptions:
		outbound.Transport = cloneV2RayTransport(outbound.Transport)
	}
	return result
}

func cloneV2RayTransport(transport *option.V2RayTransportOptions) *option.V2RayTransportOptions {
	if transport == nil {
		return nil
	}
	cloned := *transport
	if transport.XHTTPOptions.Download != nil {
		download := *transport.XHTTPOptions.Download
		cloned.XHTTPOptions.Download = &download
	}
	return &cloned
}

func rewriteOutboundReferences(options any, tags map[string]string) []string {
	var dependencies []string
	addDependency := func(tag string) string {
		qualified, internal := tags[tag]
		if !internal || tag == "" {
			return tag
		}
		for _, dependency := range dependencies {
			if dependency == qualified {
				return qualified
			}
		}
		dependencies = append(dependencies, qualified)
		return qualified
	}
	if dialer, loaded := options.(option.DialerOptionsWrapper); loaded {
		dialerOptions := dialer.TakeDialerOptions()
		dialerOptions.Detour = addDependency(dialerOptions.Detour)
		dialer.ReplaceDialerOptions(dialerOptions)
	}
	switch outbound := options.(type) {
	case *option.FairQueueOutboundOptions:
		outbound.Outbound = addDependency(outbound.Outbound)
	case *option.MASQUEOutboundOptions:
		outbound.Profile.Detour = addDependency(outbound.Profile.Detour)
	}
	switch outbound := options.(type) {
	case *option.VLESSOutboundOptions:
		rewriteXHTTPDownloadDetour(outbound.Transport, addDependency)
	case *option.VMessOutboundOptions:
		rewriteXHTTPDownloadDetour(outbound.Transport, addDependency)
	case *option.TrojanOutboundOptions:
		rewriteXHTTPDownloadDetour(outbound.Transport, addDependency)
	}
	return dependencies
}

func rewriteXHTTPDownloadDetour(transport *option.V2RayTransportOptions, rewrite func(string) string) {
	if transport == nil || transport.Type != "xhttp" || transport.XHTTPOptions.Download == nil {
		return
	}
	transport.XHTTPOptions.Download.Detour = rewrite(transport.XHTTPOptions.Download.Detour)
}

func sortOutbounds(outbounds []preparedOutbound) ([]preparedOutbound, error) {
	byTag := make(map[string]preparedOutbound, len(outbounds))
	for _, outbound := range outbounds {
		byTag[outbound.tag] = outbound
	}
	state := make(map[string]uint8, len(outbounds))
	result := make([]preparedOutbound, 0, len(outbounds))
	var visit func(string) error
	visit = func(tag string) error {
		switch state[tag] {
		case 1:
			return E.New("circular provider outbound dependency at ", tag)
		case 2:
			return nil
		}
		state[tag] = 1
		outbound := byTag[tag]
		for _, dependency := range outbound.dependencies {
			if _, internal := byTag[dependency]; internal {
				if err := visit(dependency); err != nil {
					return err
				}
			}
		}
		state[tag] = 2
		result = append(result, outbound)
		return nil
	}
	for _, outbound := range outbounds {
		if err := visit(outbound.tag); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func affectedOutbounds(oldOutbounds, newOutbounds []preparedOutbound) map[string]bool {
	oldByTag := make(map[string]preparedOutbound, len(oldOutbounds))
	newByTag := make(map[string]preparedOutbound, len(newOutbounds))
	for _, outbound := range oldOutbounds {
		oldByTag[outbound.tag] = outbound
	}
	for _, outbound := range newOutbounds {
		newByTag[outbound.tag] = outbound
	}
	affected := make(map[string]bool)
	for tag, oldOutbound := range oldByTag {
		newOutbound, loaded := newByTag[tag]
		if !loaded || !reflect.DeepEqual(oldOutbound.source, newOutbound.source) {
			affected[tag] = true
		}
	}
	for tag := range newByTag {
		if _, loaded := oldByTag[tag]; !loaded {
			affected[tag] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, graph := range [][]preparedOutbound{oldOutbounds, newOutbounds} {
			for _, outbound := range graph {
				if affected[outbound.tag] {
					continue
				}
				for _, dependency := range outbound.dependencies {
					if affected[dependency] {
						affected[outbound.tag] = true
						changed = true
						break
					}
				}
			}
		}
	}
	return affected
}

type batchOutboundManager interface {
	adapter.OutboundManager
	Started() bool
	SwapBatch(expectedOld map[string]adapter.Outbound, candidates []adapter.Outbound) (map[string]adapter.Outbound, error)
}

type stagedOutboundManager struct {
	adapter.OutboundManager
	candidates map[string]adapter.Outbound
}

func (m *stagedOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	if outbound := m.candidates[tag]; outbound != nil {
		return outbound, true
	}
	return m.OutboundManager.Outbound(tag)
}

func (a *Adapter) replaceOutbounds(oldOutbounds, newOutbounds []preparedOutbound) ([]adapter.Outbound, error) {
	if manager, loaded := a.outbound.(batchOutboundManager); loaded && manager.Started() {
		return a.replaceStartedOutbounds(manager, oldOutbounds, newOutbounds)
	}
	return nil, a.replaceUnstartedOutbounds(oldOutbounds, newOutbounds)
}

func (a *Adapter) replaceStartedOutbounds(manager batchOutboundManager, oldOutbounds, newOutbounds []preparedOutbound) ([]adapter.Outbound, error) {
	affected := affectedOutbounds(oldOutbounds, newOutbounds)
	expectedOld := make(map[string]adapter.Outbound)
	for _, outbound := range oldOutbounds {
		if affected[outbound.tag] {
			current, loaded := a.outbound.Outbound(outbound.tag)
			if !loaded {
				return nil, E.New("provider outbound not found: ", outbound.tag)
			}
			expectedOld[outbound.tag] = current
		}
	}
	var candidatesToBuild []preparedOutbound
	for _, outbound := range newOutbounds {
		if affected[outbound.tag] {
			candidatesToBuild = append(candidatesToBuild, outbound)
		}
	}
	if len(expectedOld)+len(candidatesToBuild) == 0 {
		return nil, nil
	}
	registry := service.FromContext[adapter.OutboundRegistry](a.ctx)
	if registry == nil {
		return nil, E.New("missing outbound registry")
	}
	staged := &stagedOutboundManager{OutboundManager: a.outbound, candidates: make(map[string]adapter.Outbound)}
	stagedCtx := service.ExtendContext(a.ctx)
	stagedCtx = service.ContextWith[adapter.OutboundManager](stagedCtx, staged)
	var candidates []adapter.Outbound
	for _, prepared := range candidatesToBuild {
		candidate, err := registry.CreateOutbound(
			adapter.WithContext(stagedCtx, &adapter.InboundContext{Outbound: prepared.tag}),
			a.router,
			a.logFactory.NewLogger(F.ToString("outbound/", prepared.runtime.Type, "[", prepared.tag, "]")),
			prepared.tag,
			prepared.runtime.Type,
			prepared.runtime.Options,
		)
		if err != nil {
			closeOutboundsReverse(candidates)
			return nil, E.Cause(err, "create provider outbound candidate ", prepared.tag)
		}
		candidates = append(candidates, candidate)
		staged.candidates[prepared.tag] = candidate
	}
	for _, stage := range adapter.ListStartStages {
		for _, candidate := range candidates {
			if err := adapter.LegacyStart(candidate, stage); err != nil {
				closeOutboundsReverse(candidates)
				return nil, E.Cause(err, stage, " provider outbound candidate ", candidate.Tag())
			}
		}
	}
	oldByTag, err := manager.SwapBatch(expectedOld, candidates)
	if err != nil {
		closeOutboundsReverse(candidates)
		return nil, err
	}
	oldToClose := make([]adapter.Outbound, 0, len(oldByTag))
	for index := len(oldOutbounds) - 1; index >= 0; index-- {
		if oldOutbound := oldByTag[oldOutbounds[index].tag]; oldOutbound != nil {
			oldToClose = append(oldToClose, oldOutbound)
		}
	}
	return oldToClose, nil
}

func closeOutboundsReverse(outbounds []adapter.Outbound) {
	for index := len(outbounds) - 1; index >= 0; index-- {
		common.Close(outbounds[index])
	}
}

func (a *Adapter) replaceUnstartedOutbounds(oldOutbounds, newOutbounds []preparedOutbound) error {
	affected := affectedOutbounds(oldOutbounds, newOutbounds)
	removed := make(map[string]bool)
	for index := len(oldOutbounds) - 1; index >= 0; index-- {
		outbound := oldOutbounds[index]
		if !affected[outbound.tag] {
			continue
		}
		if err := a.outbound.Remove(outbound.tag); err != nil {
			return E.Errors(E.Cause(err, "remove provider outbound ", outbound.tag), a.restoreOutbounds(oldOutbounds, removed))
		}
		removed[outbound.tag] = true
	}

	oldByTag := make(map[string]preparedOutbound, len(oldOutbounds))
	for _, outbound := range oldOutbounds {
		oldByTag[outbound.tag] = outbound
	}
	var created []preparedOutbound
	for _, outbound := range newOutbounds {
		if _, existed := oldByTag[outbound.tag]; existed && !affected[outbound.tag] {
			continue
		}
		if err := a.createOutbound(outbound); err != nil {
			return E.Errors(E.Cause(err, "create provider outbound ", outbound.tag), a.rollbackOutbounds(created, oldOutbounds, removed))
		}
		created = append(created, outbound)
	}
	return nil
}

func (a *Adapter) createOutbound(outbound preparedOutbound) error {
	return a.outbound.Create(
		adapter.WithContext(a.ctx, &adapter.InboundContext{Outbound: outbound.tag}),
		a.router,
		a.logFactory.NewLogger(F.ToString("outbound/", outbound.runtime.Type, "[", outbound.tag, "]")),
		outbound.tag,
		outbound.runtime.Type,
		outbound.runtime.Options,
	)
}

func (a *Adapter) rollbackOutbounds(created, oldOutbounds []preparedOutbound, removed map[string]bool) error {
	var rollbackErr error
	for index := len(created) - 1; index >= 0; index-- {
		if err := a.outbound.Remove(created[index].tag); err != nil {
			rollbackErr = E.Errors(rollbackErr, E.Cause(err, "remove new provider outbound ", created[index].tag))
		}
	}
	return E.Errors(rollbackErr, a.restoreOutbounds(oldOutbounds, removed))
}

func (a *Adapter) restoreOutbounds(oldOutbounds []preparedOutbound, removed map[string]bool) error {
	var restoreErr error
	for _, outbound := range oldOutbounds {
		if !removed[outbound.tag] {
			continue
		}
		if err := a.createOutbound(outbound); err != nil {
			restoreErr = E.Errors(restoreErr, E.Cause(err, "restore provider outbound ", outbound.tag))
		}
	}
	return restoreErr
}
