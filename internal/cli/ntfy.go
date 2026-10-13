package cli

import (
	"fmt"
	"io"

	"github.com/ZeroCool0388/daemon-doctor/internal/config"
)

func ntfySetupCmd(args []string, stdout, stderr io.Writer) int {
	path, code, ok := configFlag("ntfy-setup", args, stderr)
	if !ok {
		return code
	}
	link, err := config.SetupNtfy(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	// Explicit output is the subscribe credential; it is not copied to logs.
	if _, err := fmt.Fprintln(stdout, link); err != nil {
		fmt.Fprintln(stderr, "error: could not print subscribe link")
		return 1
	}
	return 0
}
