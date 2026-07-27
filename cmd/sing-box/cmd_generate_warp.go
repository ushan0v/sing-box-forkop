package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var generateWARPProfileJSON bool

var commandGenerateWARPProfile = &cobra.Command{
	Use:   "warp-profile",
	Short: "Generate a Cloudflare WARP profile",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithTimeout(cmd.Context(), 40*time.Second)
		defer cancel()
		if err := generateWARPProfile(ctx, generateWARPProfileJSON); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerateWARPProfile.Flags().BoolVar(&generateWARPProfileJSON, "json", false, "output JSON")
	commandGenerate.AddCommand(commandGenerateWARPProfile)
}

func generateWARPProfile(ctx context.Context, jsonOutput bool) error {
	generated, err := cloudflare.GenerateWARPProfile(ctx)
	if err != nil {
		return err
	}
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(generated)
	}
	_, err = fmt.Fprintf(os.Stdout, "ID: %s\nAuthToken: %s\nPrivateKey: %s\n", generated.ID, generated.AuthToken, generated.PrivateKey)
	return err
}
