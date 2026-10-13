package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/config"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
)

func mcpTokenCmd(args []string, stdout, stderr io.Writer) int {
	path, code, ok := configFlag("mcp-token", args, stderr)
	if !ok {
		return code
	}
	err := issueMCPToken(path, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func issueMCPToken(path string, out io.Writer) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.RelayURL == "" {
		return fmt.Errorf("mcp-token requires relay.url")
	}
	sec, err := security.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return err
	}
	secret, err := sec.MCPLinkSecret()
	if err != nil {
		return err
	}
	client, err := relay.New(cfg.RelayURL)
	if err != nil {
		return err
	}
	token, hash, err := relay.NewMCPToken()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.RegisterMCPLink(ctx, sec.MacID(), secret); err != nil {
		return err
	}
	if err := client.RegisterMCPToken(ctx, sec.MacID(), secret, hash); err != nil {
		return err
	}
	// The plaintext token is not saved; only this successful issuance prints it.
	_, err = fmt.Fprintln(out, token)
	return err
}
