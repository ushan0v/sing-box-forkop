package bandwidth

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.BandwidthLimiterOutboundOptions](registry, C.TypeBandwidthLimiter, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx         context.Context
	outbound    adapter.OutboundManager
	connection  adapter.ConnectionManager
	logger      logger.ContextLogger
	strategy    BandwidthStrategy
	outboundTag string
	detour      adapter.Outbound
	router      *route.Router
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BandwidthLimiterOutboundOptions) (adapter.Outbound, error) {
	if options.Strategy == "" {
		return nil, E.New("missing strategy")
	}
	if options.Route.Final == "" {
		return nil, E.New("missing final outbound")
	}
	var strategy BandwidthStrategy
	var err error
	switch options.Strategy {
	case "users":
		usersStrategies := make(map[string]BandwidthStrategy, len(options.Users))
		for _, user := range options.Users {
			userStrategy, err := CreateStrategy(user.Strategy, user.Mode, user.ConnectionType, options.Speed.Value(), options.FlowKeys)
			if err != nil {
				return nil, err
			}
			usersStrategies[user.Name] = userStrategy
		}
		strategy = NewUsersBandwidthStrategy(usersStrategies)
	case "manager":
		strategy = NewManagerBandwidthStrategy()
	default:
		strategy, err = CreateStrategy(options.Strategy, options.Mode, options.ConnectionType, options.Speed.Value(), options.FlowKeys)
		if err != nil {
			return nil, err
		}
	}
	logFactory := service.FromContext[log.Factory](ctx)
	r := route.NewRouter(ctx, logFactory, options.Route, option.DNSOptions{})
	err = r.Initialize(options.Route.Rules, options.Route.RuleSet)
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:     outbound.NewAdapter(C.TypeBandwidthLimiter, tag, nil, []string{}),
		ctx:         ctx,
		outbound:    service.FromContext[adapter.OutboundManager](ctx),
		connection:  service.FromContext[adapter.ConnectionManager](ctx),
		logger:      logger,
		strategy:    strategy,
		outboundTag: options.Route.Final,
		router:      r,
	}
	return outbound, nil
}

func (h *Outbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (h *Outbound) Start() error {
	detour, loaded := h.outbound.Outbound(h.outboundTag)
	if !loaded {
		return E.New("outbound not found: ", h.outboundTag)
	}
	h.detour = detour
	for _, stage := range []adapter.StartStage{adapter.StartStateStart, adapter.StartStatePostStart, adapter.StartStateStarted} {
		err := h.router.Start(stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := h.detour.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	wrappedConn, err := h.strategy.wrapConn(ctx, conn, adapter.ContextFrom(ctx), true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return wrappedConn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.detour.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	wrappedConn, err := h.strategy.wrapPacketConn(ctx, conn, adapter.ContextFrom(ctx), true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return wrappedConn, nil
}

func (h *Outbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	wrappedConn, err := h.strategy.wrapConn(ctx, conn, &metadata, false)
	if err != nil {
		h.logger.ErrorContext(ctx, err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	h.router.RouteConnectionEx(ctx, wrappedConn, metadata, onClose)
	return
}

func (h *Outbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	packetConn, err := h.strategy.wrapPacketConn(ctx, bufio.NewNetPacketConn(conn), &metadata, false)
	if err != nil {
		h.logger.ErrorContext(ctx, err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	h.router.RoutePacketConnectionEx(ctx, bufio.NewPacketConn(packetConn), metadata, onClose)
	return
}

func (h *Outbound) GetStrategy() BandwidthStrategy {
	return h.strategy
}
