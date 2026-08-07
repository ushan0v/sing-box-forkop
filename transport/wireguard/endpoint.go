package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"

	"go4.org/netipx"
)

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	tunDevice      Device
	natDevice      NatDevice
	device         *device.Device
	allowedIPs     *device.AllowedIPs
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	privateKey := hex.EncodeToString(privateKeyBytes)
	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	if options.Amnezia != nil && options.Amnezia.HeaderProtectionKey != "" {
		headerProtectionKey, err := base64.StdEncoding.DecodeString(options.Amnezia.HeaderProtectionKey)
		if err != nil {
			return nil, E.Cause(err, "decode header protection key")
		}
		if len(headerProtectionKey) != 32 {
			return nil, E.New("invalid header protection key length")
		}
		ipcConf += "\nheader_protection_key=" + hex.EncodeToString(headerProtectionKey)
	}
	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsDomain() {
			peer.destination = rawPeer.Endpoint
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		peer.publicKeyHex = hex.EncodeToString(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		peers = append(peers, peer)
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	deviceOptions := DeviceOptions{
		Context:        options.Context,
		Logger:         options.Logger,
		System:         options.System,
		Handler:        options.Handler,
		UDPTimeout:     options.UDPTimeout,
		ICMPTimeout:    options.ICMPTimeout,
		CreateDialer:   options.CreateDialer,
		Name:           options.Name,
		MTU:            options.MTU,
		Address:        options.Address,
		AllowedAddress: allowedAddresses,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	natDevice, isNatDevice := tunDevice.(NatDevice)
	if !isNatDevice {
		natDevice = NewNATDevice(options.Context, options.Logger, tunDevice)
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
		tunDevice:      tunDevice,
		natDevice:      natDevice,
	}, nil
}

func (e *Endpoint) Start(resolve bool) error {
	if common.Any(e.peers, func(peer peerConfig) bool {
		return !peer.endpoint.IsValid() && peer.destination.IsDomain()
	}) {
		if !resolve {
			return nil
		}
		for peerIndex, peer := range e.peers {
			if peer.endpoint.IsValid() || !peer.destination.IsDomain() {
				continue
			}
			destinationAddress, err := e.options.ResolvePeer(peer.destination.Fqdn)
			if err != nil {
				return E.Cause(err, "resolve endpoint domain for peer[", peerIndex, "]: ", peer.destination)
			}
			e.peers[peerIndex].endpoint = netip.AddrPortFrom(destinationAddress, peer.destination.Port)
		}
	} else if resolve {
		return nil
	}
	var bind conn.Bind
	wgListener, isWgListener := common.Cast[dialer.WireGuardListener](e.options.Dialer)
	if isWgListener {
		bind = conn.NewDefaultBind(wgListener.WireGuardControl())
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
		)
		if len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
			isConnect = true
			connectAddr = e.peers[0].endpoint
		}
		bind = NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr)
	}
	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	var deviceInput Device
	if e.natDevice != nil {
		deviceInput = e.natDevice
	} else {
		deviceInput = e.tunDevice
	}
	wgDevice := device.NewDevice(e.options.Context, deviceInput, bind, logger, e.options.Workers, e.options.PreallocatedBuffersPerPool, e.options.DisablePauses)
	e.tunDevice.SetDevice(wgDevice)
	var ipcConf strings.Builder
	ipcConf.WriteString(e.ipcConf)
	if e.options.Amnezia != nil {
		if e.options.Amnezia.JC > 0 {
			ipcConf.WriteString("\njc=" + strconv.Itoa(e.options.Amnezia.JC))
		}
		if e.options.Amnezia.JMin > 0 {
			ipcConf.WriteString("\njmin=" + strconv.Itoa(e.options.Amnezia.JMin))
		}
		if e.options.Amnezia.JMax > 0 {
			ipcConf.WriteString("\njmax=" + strconv.Itoa(e.options.Amnezia.JMax))
		}
		if e.options.Amnezia.S1 > 0 {
			ipcConf.WriteString("\ns1=" + strconv.Itoa(e.options.Amnezia.S1))
		}
		if e.options.Amnezia.S2 > 0 {
			ipcConf.WriteString("\ns2=" + strconv.Itoa(e.options.Amnezia.S2))
		}
		if e.options.Amnezia.S3 > 0 {
			ipcConf.WriteString("\ns3=" + strconv.Itoa(e.options.Amnezia.S3))
		}
		if e.options.Amnezia.S4 > 0 {
			ipcConf.WriteString("\ns4=" + strconv.Itoa(e.options.Amnezia.S4))
		}
		if e.options.Amnezia.H1 != nil {
			ipcConf.WriteString("\nh1=" + e.options.Amnezia.H1.String())
		}
		if e.options.Amnezia.H2 != nil {
			ipcConf.WriteString("\nh2=" + e.options.Amnezia.H2.String())
		}
		if e.options.Amnezia.H3 != nil {
			ipcConf.WriteString("\nh3=" + e.options.Amnezia.H3.String())
		}
		if e.options.Amnezia.H4 != nil {
			ipcConf.WriteString("\nh4=" + e.options.Amnezia.H4.String())
		}
		if e.options.Amnezia.I1 != "" {
			ipcConf.WriteString("\ni1=" + e.options.Amnezia.I1)
		}
		if e.options.Amnezia.I2 != "" {
			ipcConf.WriteString("\ni2=" + e.options.Amnezia.I2)
		}
		if e.options.Amnezia.I3 != "" {
			ipcConf.WriteString("\ni3=" + e.options.Amnezia.I3)
		}
		if e.options.Amnezia.I4 != "" {
			ipcConf.WriteString("\ni4=" + e.options.Amnezia.I4)
		}
		if e.options.Amnezia.I5 != "" {
			ipcConf.WriteString("\ni5=" + e.options.Amnezia.I5)
		}
		writeRange := func(name string, value *badoption.Range[uint32]) {
			if value != nil && (value.From > 0 || value.To > 0) {
				ipcConf.WriteString("\n" + name + "=" + value.String())
			}
		}
		writeRange("content_padding_addition", e.options.Amnezia.ContentPaddingAddition)
		writeRange("rekey_after_time", e.options.Amnezia.RekeyAfterTime)
		writeRange("rekey_timeout", e.options.Amnezia.RekeyTimeout)
		writeRange("reject_after_time", e.options.Amnezia.RejectAfterTime)
		writeRange("keepalive_timeout", e.options.Amnezia.KeepaliveTimeout)
		writeRange("max_handshake_attempts", e.options.Amnezia.MaxHandshakeAttempts)
	}
	for _, peer := range e.peers {
		ipcConf.WriteString(peer.GenerateIpcLines())
	}
	err = wgDevice.IpcSet(ipcConf.String())
	if err != nil {
		wgDevice.Close()
		return E.Cause(err, "setup wireguard: \n", ipcConf.String())
	}
	e.device = wgDevice
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	e.allowedIPs = (*device.AllowedIPs)(unsafe.Pointer(reflect.Indirect(reflect.ValueOf(wgDevice)).FieldByName("allowedips").UnsafeAddr()))
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) Close() error {
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
		e.pauseCallback = nil
	}
	if e.device != nil {
		e.device.Down()
		e.device.Close()
		e.device = nil
	}
	return nil
}

func (e *Endpoint) Lookup(address netip.Addr) *device.Peer {
	if e.allowedIPs == nil {
		return nil
	}
	return e.allowedIPs.Lookup(address.AsSlice())
}

func (e *Endpoint) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	if e.natDevice == nil {
		return nil, os.ErrInvalid
	}
	return e.natDevice.CreateDestination(metadata, routeContext, timeout)
}

func (e *Endpoint) onPauseUpdated(event int) {
	switch event {
	case pause.EventDevicePaused, pause.EventNetworkPause:
		e.device.Down()
	case pause.EventDeviceWake, pause.EventNetworkWake:
		e.device.Up()
	}
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       *badoption.Range[uint32]
}

func (c peerConfig) GenerateIpcLines() string {
	var ipcLines strings.Builder
	ipcLines.WriteString("\npublic_key=" + c.publicKeyHex)
	if c.endpoint.IsValid() {
		ipcLines.WriteString("\nendpoint=" + c.endpoint.String())
	}
	if c.preSharedKeyHex != "" {
		ipcLines.WriteString("\npreshared_key=" + c.preSharedKeyHex)
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines.WriteString("\nallowed_ip=" + allowedIP.String())
	}
	if c.keepalive != nil && (c.keepalive.From > 0 || c.keepalive.To > 0) {
		ipcLines.WriteString("\npersistent_keepalive_interval=" + c.keepalive.String())
	}
	return ipcLines.String()
}
