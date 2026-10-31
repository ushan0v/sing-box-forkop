package encryption

// What client.go, common.go and server.go took from Xray's own packages (podkop-engine).

import (
	"crypto/rand"
	"math/big"
	"runtime"

	"golang.org/x/sys/cpu"
)

// hasAESGCMHardware tells whether AES-GCM is done by the processor: the client seals
// with it then, and with ChaCha20-Poly1305 otherwise. The server tries both. The
// conditions are the ones of crypto/tls (cipher_suites.go) and of Xray.
var hasAESGCMHardware = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) || (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64") ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH) ||
	runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"

// randBetween returns a random number from the half-open range, as crypto.RandBetween of
// Xray does: the lengths and pauses of the padding.
func randBetween(from int64, to int64) int64 {
	if from > to {
		from, to = to, from
	}
	if d := to - from; d == 0 || d == 1 {
		return from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}
