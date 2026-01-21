// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

// PublicKeyUploadOptions

var _ command.OptionsSet = (*PublicKeyUploadOptions)(nil)

// PublicKeyUploadOptions holds the options for the publickey upload command.
type PublicKeyUploadOptions struct{}

var defaultPublicKeyUploadOptions = &PublicKeyUploadOptions{}

func (o *PublicKeyUploadOptions) Validate() error {
	return nil
}

func (o *PublicKeyUploadOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PublicKeyUploadOptions) AddFlags(cmd *cobra.Command) {}

// PublicKeyListOptions

var _ command.OptionsSet = (*PublicKeyListOptions)(nil)

// PublicKeyListOptions holds the options for the publickey list command.
type PublicKeyListOptions struct {
	JSON bool
}

var defaultPublicKeyListOptions = &PublicKeyListOptions{
	JSON: false,
}

func (o *PublicKeyListOptions) Validate() error {
	return nil
}

func (o *PublicKeyListOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PublicKeyListOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.JSON, "json", false, "Output as JSON")
}

// PublicKeyDeleteOptions

var _ command.OptionsSet = (*PublicKeyDeleteOptions)(nil)

// PublicKeyDeleteOptions holds the options for the publickey delete command.
type PublicKeyDeleteOptions struct{}

var defaultPublicKeyDeleteOptions = &PublicKeyDeleteOptions{}

func (o *PublicKeyDeleteOptions) Validate() error {
	return nil
}

func (o *PublicKeyDeleteOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PublicKeyDeleteOptions) AddFlags(cmd *cobra.Command) {}

// AddPublicKeyCommand adds the publickey command and its subcommands to the parent.
func AddPublicKeyCommand(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:     "publickey",
		Aliases: []string{"key", "pk"},
		Short:   "Manage public keys",
		Long:    `Upload, list, and delete public keys used for attestation verification.`,
	}

	addPublicKeyUploadCommand(cmd)
	addPublicKeyListCommand(cmd)
	addPublicKeyDeleteCommand(cmd)

	parent.AddCommand(cmd)
}

// addPublicKeyUploadCommand adds the publickey upload command.
func addPublicKeyUploadCommand(parent *cobra.Command) {
	opts := defaultPublicKeyUploadOptions
	cmd := &cobra.Command{
		Use:   "upload <key-file>",
		Short: "Upload a public key",
		Long: `Upload a public key to Stash for attestation verification.

The key file should be in PEM format.

Examples:
  # Upload a public key
  stash publickey upload key.pem

  # Upload from stdin
  cat key.pem | stash publickey upload -`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			keyPath := args[0]

			// Get client
			c, cleanup, err := getClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Read key file
			var keyData []byte
			if keyPath == "-" {
				keyData, err = os.ReadFile(os.Stdin.Name())
			} else {
				keyData, err = os.ReadFile(keyPath)
			}
			if err != nil {
				return fmt.Errorf("reading key file: %w", err)
			}

			// Upload key
			fmt.Printf("Uploading public key...\n")
			keyID, err := c.UploadPublicKey(cmd.Context(), keyData)
			if err != nil {
				return fmt.Errorf("uploading public key: %w", err)
			}

			fmt.Printf("✓ Public key uploaded successfully\n")
			fmt.Printf("Key ID: %s\n", keyID)

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// addPublicKeyListCommand adds the publickey list command.
func addPublicKeyListCommand(parent *cobra.Command) {
	opts := defaultPublicKeyListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List public keys",
		Long: `List all public keys stored in Stash for your organization.

Examples:
  # List all public keys
  stash publickey list

  # List as JSON
  stash publickey list --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			// Get client
			c, cleanup, err := getClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// List keys
			keys, err := c.ListPublicKeys(cmd.Context())
			if err != nil {
				return fmt.Errorf("listing public keys: %w", err)
			}

			// Output as JSON
			if opts.JSON {
				data, err := json.MarshalIndent(keys, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			// Output as table
			if len(keys) == 0 {
				fmt.Println("No public keys found")
				return nil
			}

			fmt.Printf("Found %d public key(s)\n\n", len(keys))

			for i, key := range keys {
				fmt.Printf("%d. %s\n", i+1, key.KeyID)
				fmt.Printf("   Algorithm: %s\n", key.Algorithm)
				fmt.Printf("   Created:   %s\n", key.CreatedAt.Format("2006-01-02 15:04:05"))
				fmt.Println()
			}

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// addPublicKeyDeleteCommand adds the publickey delete command.
func addPublicKeyDeleteCommand(parent *cobra.Command) {
	opts := defaultPublicKeyDeleteOptions
	cmd := &cobra.Command{
		Use:   "delete <key-id>",
		Short: "Delete a public key",
		Long: `Delete a public key from Stash.

Examples:
  # Delete a public key
  stash publickey delete abc123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			keyID := args[0]

			// Get client
			c, cleanup, err := getClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Delete key
			fmt.Printf("Deleting public key %s...\n", keyID)
			if err := c.DeletePublicKey(cmd.Context(), keyID); err != nil {
				return fmt.Errorf("deleting public key: %w", err)
			}

			fmt.Println("✓ Public key deleted successfully")

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
