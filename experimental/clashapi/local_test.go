package clashapi

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestIsLocalControllerRequest(t *testing.T) {
	for _, remote := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		request := httptest.NewRequest("GET", "/", nil)
		request.RemoteAddr = remote
		if !isLocalControllerRequest(request) {
			t.Fatalf("expected %s to be local", remote)
		}
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		local, ok := address.(*net.IPNet)
		if !ok || local.IP.IsLoopback() {
			continue
		}
		request := httptest.NewRequest("GET", "/", nil)
		request.RemoteAddr = net.JoinHostPort(local.IP.String(), "1234")
		if !isLocalControllerRequest(request) {
			t.Fatalf("expected interface address %s to be local", local.IP)
		}
		break
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	if isLocalControllerRequest(request) {
		t.Fatal("expected documentation address to be rejected")
	}
}
