package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	publicKeyJSON bool
)

// NewPublicKeyCommand creates the publickey command with subcommands.
func NewPublicKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "publickey",
		Aliases: []string{"key", "pk"},
		Short:   "Manage public keys",
		Long:    `Upload, list, and delete public keys used for attestation verification.`,
	}

	cmd.AddCommand(newPublicKeyUploadCommand())
	cmd.AddCommand(newPublicKeyListCommand())
	cmd.AddCommand(newPublicKeyDeleteCommand())

	return cmd
}

// newPublicKeyUploadCommand creates the publickey upload command.
func newPublicKeyUploadCommand() *cobra.Command {
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
		RunE: runPublicKeyUpload,
	}

	return cmd
}

func runPublicKeyUpload(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	keyPath := args[0]

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

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
	keyID, err := c.UploadPublicKey(ctx, keyData)
	if err != nil {
		return fmt.Errorf("uploading public key: %w", err)
	}

	fmt.Printf("✓ Public key uploaded successfully\n")
	fmt.Printf("Key ID: %s\n", keyID)

	return nil
}

// newPublicKeyListCommand creates the publickey list command.
func newPublicKeyListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List public keys",
		Long: `List all public keys stored in Stash for your organization.

Examples:
  # List all public keys
  stash publickey list

  # List as JSON
  stash publickey list --json`,
		RunE: runPublicKeyList,
	}

	cmd.Flags().BoolVar(&publicKeyJSON, "json", false, "Output as JSON")

	return cmd
}

func runPublicKeyList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// List keys
	keys, err := c.ListPublicKeys(ctx)
	if err != nil {
		return fmt.Errorf("listing public keys: %w", err)
	}

	// Output as JSON
	if publicKeyJSON {
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
}

// newPublicKeyDeleteCommand creates the publickey delete command.
func newPublicKeyDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <key-id>",
		Short: "Delete a public key",
		Long: `Delete a public key from Stash.

Examples:
  # Delete a public key
  stash publickey delete abc123`,
		Args: cobra.ExactArgs(1),
		RunE: runPublicKeyDelete,
	}

	return cmd
}

func runPublicKeyDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	keyID := args[0]

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// Delete key
	fmt.Printf("Deleting public key %s...\n", keyID)
	if err := c.DeletePublicKey(ctx, keyID); err != nil {
		return fmt.Errorf("deleting public key: %w", err)
	}

	fmt.Println("✓ Public key deleted successfully")

	return nil
}
