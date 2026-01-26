// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/stash/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// Print the error to stderr before exiting
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
