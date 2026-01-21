package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

// NewUpdateCommand creates the update command.
func NewUpdateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update <attestation-id>",
		Short: "Update an attestation (not implemented)",
		Long: `Update attestation metadata.

Note: This operation is not currently implemented by the server.

Examples:
  # Attempt to update an attestation
  stash update abc123`,
		Args: cobra.ExactArgs(1),
		RunE: runUpdate,
	}

	return cmd
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	id := args[0]

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// Attempt update (will return NOT_IMPLEMENTED)
	updates := map[string]interface{}{}
	if err := c.UpdateAttestation(ctx, id, updates); err != nil {
		return fmt.Errorf("updating attestation: %w", err)
	}

	fmt.Println("✓ Attestation updated successfully")

	return nil
}
