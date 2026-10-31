package vless

import (
	"context"
	"net"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

// encrypt puts VLESS Encryption on a connection the transport has just made; without
// the setting the connection is returned as it is (podkop-engine).
//
// The handshake takes a bare connection and nothing to end it by: it writes its hello in
// pieces with pauses between them and then waits for the server's part. A server that
// has gone silent would hold it, and with it a URL test or a dial that was given up
// long ago, for as long as TCP itself waits. So the connection is closed when the dial is
// cancelled, and when a handshake has taken the time a TLS one is given. Closing, not a
// deadline on the connection: not every transport takes a deadline back once it passed.
func (h *vlessDialer) encrypt(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if h.encryption == nil {
		return conn, nil
	}
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	encrypted, err := h.encryption.Handshake(conn)
	if !stop() {
		// the connection was closed above: what the handshake returned is of no use
		return nil, E.Cause(ctx.Err(), "VLESS Encryption handshake")
	}
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "VLESS Encryption handshake")
	}
	return encrypted, nil
}

// decrypt takes VLESS Encryption off a connection a client has just made, under the TLS
// and the transport it came through; without the setting the connection is returned as it
// is. The server's handshake waits for the client's hello with nothing to end it by, so a
// client that never sends one is cut off as encrypt cuts a silent server.
func (h *Inbound) decrypt(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if h.decryption == nil {
		return conn, nil
	}
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	decrypted, err := h.decryption.Handshake(conn, nil)
	if !stop() {
		return nil, E.Cause(ctx.Err(), "VLESS Encryption handshake")
	}
	if err != nil {
		return nil, E.Cause(err, "VLESS Encryption handshake")
	}
	return decrypted, nil
}
