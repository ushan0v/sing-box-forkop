package encryption

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Prefix is how the setting of VLESS Encryption begins, in a configuration of Xray and
// in a share link ("encryption=").
const Prefix = "mlkem768x25519plus"

// maxPaddingPause is the most the pauses of a padding may add up to, in milliseconds: an
// outbound gives a handshake 15 s (C.TCPTimeout), the padding of Xray's default 111 ms.
const maxPaddingPause = 10000

// NewClient reads the client's setting of VLESS Encryption as Xray writes it:
//
//	mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>[.<padding>...].<key>[.<key>...]
//
// The mode says how the handshake looks on the wire (as it is, with the public key
// XORed, or all of it as random bytes); 0rtt lets later connections reuse the keys of the
// first for as long as the server allows; the padding, when given, is segments of
// "probability-from-to" (lengths and pauses in turn); a key is base64url of 32 bytes
// (X25519) or 1184 bytes (ML-KEM-768), one per server on the way. The rules are those of
// infra/conf/vless.go of Xray.
//
// What is wrong with a setting is said without repeating any of it: a setting comes out of
// a share link as well, and the message about a refused link must not carry a piece of
// the link.
func NewClient(spec string) (*ClientInstance, error) {
	parts := strings.Split(spec, ".")
	if len(parts) < 4 || parts[0] != Prefix {
		return nil, errors.New("not a setting of VLESS Encryption: " + Prefix + ".<mode>.<1rtt|0rtt>.<key> is expected")
	}
	xorMode, err := readMode(parts[1])
	if err != nil {
		return nil, err
	}
	var seconds uint32
	switch parts[2] {
	case "1rtt":
	case "0rtt":
		seconds = 1
	default:
		return nil, errors.New("unknown handshake: 1rtt or 0rtt is expected")
	}
	padding, keys, err := readPaddingAndKeys(parts[3:], 1184, "a key is base64url of 32 bytes (X25519) or 1184 bytes (ML-KEM-768)")
	if err != nil {
		return nil, err
	}
	client := new(ClientInstance)
	err = client.Init(keys, xorMode, seconds, padding)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// NewServer reads the server's setting of VLESS Encryption, "decryption" in Xray:
//
//	mlkem768x25519plus.<native|xorpub|random>.<seconds>s[.<padding>...].<key>[.<key>...]
//
// The mode is the client's; the seconds, a number or a range "from-to", say how long a
// client may reuse the keys of a handshake for the next connection (0-RTT), 0s never; the
// padding is the client's form; a key is the private one, base64url of 32 bytes (X25519)
// or of the 64-byte seed of an ML-KEM-768 key, one per server on the way. The rules are
// those of infra/conf/vless.go of Xray. Like NewClient, it repeats no piece of a setting.
//
// The instance holds the keys of 0-RTT sessions until Close.
func NewServer(spec string) (*ServerInstance, error) {
	parts := strings.Split(spec, ".")
	if len(parts) < 4 || parts[0] != Prefix {
		return nil, errors.New("not a setting of VLESS Encryption: " + Prefix + ".<mode>.<seconds>s.<key> is expected")
	}
	xorMode, err := readMode(parts[1])
	if err != nil {
		return nil, err
	}
	var secondsFrom, secondsTo int64
	seconds := strings.SplitN(strings.TrimSuffix(parts[2], "s"), "-", 2)
	for i, value := range seconds {
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil || number < 0 {
			return nil, errors.New("invalid ticket lifetime: seconds such as 600s or 300-600s are expected")
		}
		if i == 0 {
			secondsFrom = number
		} else {
			secondsTo = number
		}
	}
	padding, keys, err := readPaddingAndKeys(parts[3:], 64, "a key is base64url of 32 bytes (X25519) or of the 64-byte seed of an ML-KEM-768 key")
	if err != nil {
		return nil, err
	}
	server := new(ServerInstance)
	err = server.Init(keys, xorMode, secondsFrom, secondsTo, padding)
	if err != nil {
		return nil, err
	}
	return server, nil
}

func readMode(value string) (uint32, error) {
	switch value {
	case "native":
		return 0, nil
	case "xorpub":
		return 1, nil
	case "random":
		return 2, nil
	}
	return 0, errors.New("unknown mode: native, xorpub or random is expected")
}

// readPaddingAndKeys reads what follows the handshake: the segments of the padding, then
// the keys, each of 32 bytes (X25519) or of the length ML-KEM-768 gives that side.
func readPaddingAndKeys(parts []string, mlkemLength int, keyMessage string) (string, [][]byte, error) {
	var (
		padding []string
		keys    [][]byte
	)
	for _, part := range parts {
		if len(part) < 20 {
			// a segment of the padding: they come before the keys
			if len(keys) > 0 {
				return "", nil, errors.New("a padding segment after a key")
			}
			padding = append(padding, part)
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || (len(key) != 32 && len(key) != mlkemLength) {
			return "", nil, errors.New(keyMessage)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return "", nil, errors.New("no key")
	}
	// the padding is read here first: the errors of ParsePadding repeat the segment
	var paddingLens, paddingGaps [][3]int
	if ParsePadding(strings.Join(padding, "."), &paddingLens, &paddingGaps) != nil {
		return "", nil, errors.New("invalid padding: segments of probability-from-to are expected, lengths and pauses in turn, the first length 35 or more, 65553 bytes in all at most")
	}
	// The handshake sleeps through the pauses between the pieces of its padding, and
	// nothing can wake it: pauses longer than a handshake may take would hold a dial past
	// its deadline, on the client and on the server that answers it alike.
	var pause int
	for _, gap := range paddingGaps {
		longest := max(gap[1], gap[2])
		if longest > maxPaddingPause {
			pause = maxPaddingPause + 1
			break
		}
		pause += max(longest, 0)
	}
	if pause > maxPaddingPause {
		return "", nil, errors.New("the pauses of the padding add up to more than 10 s")
	}
	return strings.Join(padding, "."), keys, nil
}
