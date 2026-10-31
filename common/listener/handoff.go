package listener

import (
	"context"
	"net"
	"os"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// A reload starts the new instance beside the old one. A listener of the new one takes over
// the socket the old one gave up at its address instead of binding the address again, so the
// address never stops accepting and what waits in the socket's queue is not lost.

// Owner is the instance the listeners made within its context belong to.
type Owner struct {
	_ byte // zero-sized values may share an address
}

type ownerKey struct{}

func ContextWithOwner(ctx context.Context) (context.Context, *Owner) {
	owner := new(Owner)
	return context.WithValue(ctx, ownerKey{}, owner), owner
}

type socketKey struct {
	network string
	address string
	netns   string
}

// socketOptions are what a socket keeps from its making: one made with other options is not
// taken over. Controls a caller adds cannot be compared, so such a socket never is.
type socketOptions struct {
	bindInterface string
	routingMark   uint32
	reuseAddr     bool
	tproxy        bool
	fastOpen      bool
	multipath     bool
	fragment      bool
	foreign       bool
}

type heldSocket struct {
	owner    *Owner
	listener *Listener
	options  socketOptions
	released bool
}

var sockets = struct {
	access sync.Mutex
	held   map[socketKey]*heldSocket
}{held: make(map[socketKey]*heldSocket)}

// Release gives up the sockets of the owner's listeners: they go on accepting until a
// listener of another instance takes them over.
func (o *Owner) Release() {
	sockets.access.Lock()
	defer sockets.access.Unlock()
	for _, socket := range sockets.held {
		if socket.owner == o {
			socket.released = true
		}
	}
}

// CloseReleased closes the sockets the owner gave up that no listener took over.
func (o *Owner) CloseReleased() error {
	sockets.access.Lock()
	defer sockets.access.Unlock()
	var errors []error
	for key, socket := range sockets.held {
		if socket.owner == o && socket.released {
			delete(sockets.held, key)
			errors = append(errors, socket.close(key.network))
		}
	}
	return E.Errors(errors...)
}

func (s *heldSocket) close(network string) error {
	s.listener.shutdown.Store(true)
	if network == N.NetworkTCP {
		return s.listener.tcpListener.Close()
	}
	return s.listener.udpConn.Close()
}

func (s *heldSocket) file(network string) (*os.File, error) {
	var socket interface{ File() (*os.File, error) }
	if network == N.NetworkTCP {
		socket = s.listener.tcpListener.(interface{ File() (*os.File, error) })
	} else {
		socket = s.listener.udpConn
	}
	return socket.File()
}

func socketOwner(ctx context.Context) *Owner {
	owner, _ := ctx.Value(ownerKey{}).(*Owner)
	return owner
}

// takeOver returns a duplicate of the socket another instance gave up at key, and stops that
// one using it; it returns nil when the caller has to bind the address.
func takeOver(key socketKey, options socketOptions) *os.File {
	sockets.access.Lock()
	defer sockets.access.Unlock()
	socket := sockets.held[key]
	if socket == nil || !socket.released {
		return nil
	}
	delete(sockets.held, key)
	var file *os.File
	if socket.options == options && !options.foreign {
		file, _ = socket.file(key.network)
	}
	_ = socket.close(key.network)
	return file
}

func (l *Listener) hold(key socketKey, options socketOptions) {
	owner := socketOwner(l.ctx)
	if owner == nil {
		return
	}
	sockets.access.Lock()
	defer sockets.access.Unlock()
	sockets.held[key] = &heldSocket{owner: owner, listener: l, options: options}
}

func (l *Listener) unhold() {
	sockets.access.Lock()
	defer sockets.access.Unlock()
	for key, socket := range sockets.held {
		if socket.listener == l {
			delete(sockets.held, key)
		}
	}
}

// keepAliveListener accepts with the keep-alive of the listen options, where a listener made
// from a file would use the defaults of Go.
type keepAliveListener struct {
	*net.TCPListener
	config net.KeepAliveConfig
}

func (l *keepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetKeepAliveConfig(l.config)
	return conn, nil
}
