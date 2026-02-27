// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	deadropcmd "github.com/carabiner-dev/deadrop/pkg/cmd"
	"github.com/spf13/cobra"
)

// AddAuth adds the auth command and its subcommands to the parent.
func AddAuth(parent *cobra.Command) {
	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with Carabiner",
		Long: `Manage authentication with Carabiner.

The auth commands help you log in and out of the Carabiner ecosystem.
Login obtains a Carabiner identity token that is used by stash for service-specific tokens.`,
	}

	// Expose deadrop commands directly
	deadropcmd.AddLogin(authCmd)
	deadropcmd.AddLogout(authCmd)
	deadropcmd.AddToken(authCmd)

	parent.AddCommand(authCmd)
}
