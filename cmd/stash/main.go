package main

import (
	"os"

	"github.com/carabiner-dev/stash/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
