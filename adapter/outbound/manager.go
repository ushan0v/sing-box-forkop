package outbound

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	logger                  log.ContextLogger
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	started                 bool
	stage                   adapter.StartStage
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	dependByTag             map[string][]string
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(logger logger.ContextLogger, registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		logger:        logger,
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		dependByTag:   make(map[string][]string),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	if stage == adapter.StartStateStart {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
		outbounds := m.outbounds
		m.access.Unlock()
		return m.startOutbounds(append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	} else {
		outbounds := m.outbounds
		m.access.Unlock()
		for _, outbound := range outbounds {
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			done := adapter.LogElapsed(m.logger, stage, " ", name)
			err := adapter.LegacyStart(outbound, stage)
			done()
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
		}
	}
	return nil
}

func (m *Manager) startOutbounds(outbounds []adapter.Outbound) error {
	monitor := taskmonitor.New(m.logger, C.StartTimeout)
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			if starter, isStarter := outboundToStart.(adapter.Lifecycle); isStarter {
				done := adapter.LogElapsed(m.logger, "start ", name)
				monitor.Start("start ", name)
				err := starter.Start(adapter.StartStateStart)
				monitor.Finish()
				done()
				if err != nil {
					return E.Cause(err, "start ", name)
				}
			} else if starter, isStarter := outboundToStart.(interface {
				Start() error
			}); isStarter {
				done := adapter.LogElapsed(m.logger, "start ", name)
				monitor.Start("start ", name)
				err := starter.Start()
				monitor.Finish()
				done()
				if err != nil {
					return E.Cause(err, "start ", name)
				}
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			m.access.Lock()
			problemOutbound := m.outboundByTag[problemOutboundTag]
			m.access.Unlock()
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

func (m *Manager) Close() error {
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	outbounds := m.outbounds
	m.outbounds = nil
	m.access.Unlock()
	var err error
	for _, outbound := range outbounds {
		if closer, isCloser := outbound.(io.Closer); isCloser {
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			done := adapter.LogElapsed(m.logger, "close ", name)
			monitor.Start("close ", name)
			err = E.Append(err, closer.Close(), func(err error) error {
				return E.Cause(err, "close ", name)
			})
			monitor.Finish()
			done()
		}
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Started() bool {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.started
}

func (m *Manager) SwapBatch(expectedOld map[string]adapter.Outbound, candidates []adapter.Outbound) (map[string]adapter.Outbound, error) {
	m.access.Lock()
	defer m.access.Unlock()
	removeSet := make(map[string]bool, len(expectedOld))
	for tag, expected := range expectedOld {
		if current := m.outboundByTag[tag]; current == nil || current != expected {
			return nil, E.New("outbound changed before batch swap: ", tag)
		}
		removeSet[tag] = true
	}
	candidateByTag := make(map[string]adapter.Outbound, len(candidates))
	for _, candidate := range candidates {
		tag := candidate.Tag()
		if tag == "" || candidateByTag[tag] != nil {
			return nil, E.New("invalid duplicate outbound candidate: ", tag)
		}
		if _, loaded := m.outboundByTag[tag]; loaded && !removeSet[tag] {
			return nil, E.New("outbound already exists: ", tag)
		}
		candidateByTag[tag] = candidate
	}
	for tag := range removeSet {
		for _, dependent := range m.dependByTag[tag] {
			if !removeSet[dependent] {
				return nil, E.New("outbound[", tag, "] is depended by ", dependent)
			}
		}
	}
	for _, candidate := range candidates {
		for _, dependency := range candidate.Dependencies() {
			if candidateByTag[dependency] != nil {
				continue
			}
			if _, loaded := m.outboundByTag[dependency]; loaded && !removeSet[dependency] {
				continue
			}
			if m.endpoint == nil {
				return nil, E.New("outbound dependency not found: ", dependency)
			}
			if _, loaded := m.endpoint.Get(dependency); !loaded {
				return nil, E.New("outbound dependency not found: ", dependency)
			}
		}
	}

	oldOutbounds := make(map[string]adapter.Outbound, len(expectedOld))
	for tag := range removeSet {
		oldOutbound := m.outboundByTag[tag]
		oldOutbounds[tag] = oldOutbound
		for _, dependency := range oldOutbound.Dependencies() {
			m.dependByTag[dependency] = common.Filter(m.dependByTag[dependency], func(it string) bool { return it != tag })
			if len(m.dependByTag[dependency]) == 0 {
				delete(m.dependByTag, dependency)
			}
		}
		delete(m.outboundByTag, tag)
	}
	remainingCandidates := make(map[string]adapter.Outbound, len(candidateByTag))
	for tag, candidate := range candidateByTag {
		remainingCandidates[tag] = candidate
	}
	updatedOutbounds := make([]adapter.Outbound, 0, len(m.outbounds)-len(removeSet)+len(candidates))
	for _, current := range m.outbounds {
		if !removeSet[current.Tag()] {
			updatedOutbounds = append(updatedOutbounds, current)
			continue
		}
		if candidate := remainingCandidates[current.Tag()]; candidate != nil {
			updatedOutbounds = append(updatedOutbounds, candidate)
			delete(remainingCandidates, current.Tag())
		}
	}
	for _, candidate := range candidates {
		if remainingCandidates[candidate.Tag()] != nil {
			updatedOutbounds = append(updatedOutbounds, candidate)
		}
		m.outboundByTag[candidate.Tag()] = candidate
		for _, dependency := range candidate.Dependencies() {
			m.dependByTag[dependency] = append(m.dependByTag[dependency], candidate.Tag())
		}
	}
	m.outbounds = updatedOutbounds
	if m.defaultOutbound != nil && removeSet[m.defaultOutbound.Tag()] {
		m.defaultOutbound = candidateByTag[m.defaultOutbound.Tag()]
	}
	if candidate := candidateByTag[m.defaultTag]; candidate != nil {
		m.defaultOutbound = candidate
	}
	if m.defaultOutbound == nil && len(m.outbounds) > 0 {
		m.defaultOutbound = m.outbounds[0]
	}
	return oldOutbounds, nil
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	defer m.access.Unlock()
	outbound, found := m.outboundByTag[tag]
	if !found {
		return os.ErrInvalid
	}
	dependBy := m.dependByTag[tag]
	if len(dependBy) > 0 {
		return E.New("outbound[", tag, "] is depended by ", strings.Join(dependBy, ", "))
	}
	delete(m.outboundByTag, tag)
	index := common.Index(m.outbounds, func(it adapter.Outbound) bool {
		return it == outbound
	})
	if index == -1 {
		panic("invalid inbound index")
	}
	m.outbounds = append(m.outbounds[:index], m.outbounds[index+1:]...)
	started := m.started
	if m.defaultOutbound == outbound {
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
			m.logger.Notice("updated default outbound to ", m.defaultOutbound.Tag())
		} else {
			m.defaultOutbound = nil
		}
	}
	dependencies := outbound.Dependencies()
	for _, dependency := range dependencies {
		if len(m.dependByTag[dependency]) == 1 {
			delete(m.dependByTag, dependency)
		} else {
			m.dependByTag[dependency] = common.Filter(m.dependByTag[dependency], func(it string) bool {
				return it != tag
			})
		}
	}
	if started {
		return common.Close(outbound)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	if m.started {
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			done := adapter.LogElapsed(m.logger, stage, " ", name)
			err = adapter.LegacyStart(outbound, stage)
			done()
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
		}
	}
	m.access.Lock()
	defer m.access.Unlock()
	if existsOutbound, loaded := m.outboundByTag[tag]; loaded {
		if m.started {
			err = common.Close(existsOutbound)
			if err != nil {
				return E.Cause(err, "close outbound/", existsOutbound.Type(), "[", existsOutbound.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.outbounds, func(it adapter.Outbound) bool {
			return it == existsOutbound
		})
		if existsIndex == -1 {
			panic("invalid inbound index")
		}
		m.outbounds = append(m.outbounds[:existsIndex], m.outbounds[existsIndex+1:]...)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	dependencies := outbound.Dependencies()
	for _, dependency := range dependencies {
		m.dependByTag[dependency] = append(m.dependByTag[dependency], tag)
	}
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
		if m.started {
			m.logger.Notice("updated default outbound to ", outbound.Tag())
		}
	}
	return nil
}
