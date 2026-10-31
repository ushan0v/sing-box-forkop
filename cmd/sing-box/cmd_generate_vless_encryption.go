package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"os"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

func init() {
	commandGenerate.AddCommand(commandGenerateVLESSEncryptionKeyPair)
}

// The private key goes into a server's "decryption", the public one into its clients'
// "encryption", as the keys of Xray's vlessenc: X25519 by default, or ML-KEM-768, whose
// public key makes a share link longer than 1.5 KB.
var commandGenerateVLESSEncryptionKeyPair = &cobra.Command{
	Use:       "vless-encryption-keypair [x25519|mlkem768]",
	Short:     "Generate VLESS Encryption key pair",
	Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
	ValidArgs: []string{"x25519", "mlkem768"},
	Run: func(cmd *cobra.Command, args []string) {
		kind := "x25519"
		if len(args) > 0 {
			kind = args[0]
		}
		err := generateVLESSEncryptionKey(kind)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func generateVLESSEncryptionKey(kind string) error {
	var privateKey, publicKey []byte
	switch kind {
	case "x25519":
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privateKey, publicKey = key.Bytes(), key.PublicKey().Bytes()
	case "mlkem768":
		key, err := mlkem.GenerateKey768()
		if err != nil {
			return err
		}
		// the seed, which the server reads back as the key
		privateKey, publicKey = key.Bytes(), key.EncapsulationKey().Bytes()
	default:
		return E.New("unknown key type: ", kind)
	}
	os.Stdout.WriteString("PrivateKey: " + base64.RawURLEncoding.EncodeToString(privateKey) + "\n")
	os.Stdout.WriteString("PublicKey: " + base64.RawURLEncoding.EncodeToString(publicKey) + "\n")
	return nil
}
