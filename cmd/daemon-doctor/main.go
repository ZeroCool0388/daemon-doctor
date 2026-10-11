package main

import (
	"os"

	"github.com/ZeroCool0388/daemon-doctor/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
