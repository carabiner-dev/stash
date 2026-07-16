// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/stash/pkg/client"
)

// PolicyPushOptions holds the options for the policy push command.
var _ command.OptionsSet = (*PolicyPushOptions)(nil)

type PolicyPushOptions struct {
	ClientOptions
	Stdin     bool
	Namespace string
}

var defaultPolicyPushOptions = PolicyPushOptions{
	ClientOptions: DefaultClientOptions,
	Stdin:         false,
	Namespace:     "",
}

func (o *PolicyPushOptions) Validate() error {
	return errors.Join(
		o.ClientOptions.Validate(),
	)
}

func (o *PolicyPushOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PolicyPushOptions) AddFlags(cmd *cobra.Command) {
	o.ClientOptions.AddFlags(cmd)
	cmd.Flags().BoolVar(&o.Stdin, "stdin", false, "Read policy documents from stdin")
	cmd.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "Namespace for policies (default: empty)")
}

// PolicyAppendOptions holds the options for the policy append command.
var _ command.OptionsSet = (*PolicyAppendOptions)(nil)

type PolicyAppendOptions struct {
	ClientOptions
	Stdin     bool
	Namespace string
	Lineage   string
}

var defaultPolicyAppendOptions = PolicyAppendOptions{
	ClientOptions: DefaultClientOptions,
	Stdin:         false,
	Namespace:     "",
	Lineage:       "",
}

func (o *PolicyAppendOptions) Validate() error {
	var errs []error
	if o.Lineage == "" {
		errs = append(errs, errors.New("a lineage ID is required (use --lineage)"))
	}
	errs = append(errs, o.ClientOptions.Validate())
	return errors.Join(errs...)
}

func (o *PolicyAppendOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PolicyAppendOptions) AddFlags(cmd *cobra.Command) {
	o.ClientOptions.AddFlags(cmd)
	cmd.Flags().BoolVar(&o.Stdin, "stdin", false, "Read the policy document from stdin")
	cmd.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "Namespace for the policy (default: empty)")
	cmd.Flags().StringVar(&o.Lineage, "lineage", "", "Lineage ID to append the new version to (required)")
}

// PolicyGetOptions holds the options for the policy get command.
var _ command.OptionsSet = (*PolicyGetOptions)(nil)

type PolicyGetOptions struct {
	ClientOptions
	Namespace string
	Lineage   string
	Version   int64
	Raw       bool
}

var defaultPolicyGetOptions = PolicyGetOptions{
	ClientOptions: DefaultClientOptions,
	Namespace:     "",
	Lineage:       "",
	Version:       0,
	Raw:           false,
}

func (o *PolicyGetOptions) Validate() error {
	var errs []error
	if o.Lineage == "" {
		errs = append(errs, errors.New("a lineage ID is required (use --lineage)"))
	}
	errs = append(errs, o.ClientOptions.Validate())
	return errors.Join(errs...)
}

func (o *PolicyGetOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PolicyGetOptions) AddFlags(cmd *cobra.Command) {
	o.ClientOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "Namespace for the policy (default: empty)")
	cmd.Flags().StringVar(&o.Lineage, "lineage", "", "Lineage ID to read (required)")
	cmd.Flags().Int64Var(&o.Version, "version", -1, "Version to read (0-based; default: latest)")
	cmd.Flags().BoolVar(&o.Raw, "raw", false, "Print only the raw stored policy document")
}

// AddPolicy adds the policy command and its subcommands to the parent.
func AddPolicy(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage policy lineages",
		Long: `Push, append, and read append-only policy lineages.

A policy lineage — keyed by (org, namespace, lineage id) — is an append-only
sequence of policy documents; versions are 0-based.`,
	}

	addPolicyPushCommand(cmd)
	addPolicyAppendCommand(cmd)
	addPolicyGetCommand(cmd)
	addPolicyDeleteCommand(cmd)

	parent.AddCommand(cmd)
}

// addPolicyPushCommand adds the policy push command.
func addPolicyPushCommand(parent *cobra.Command) {
	opts := defaultPolicyPushOptions
	cmd := &cobra.Command{
		Use:   "push [file...]",
		Short: "Push policy documents to Stash",
		Long: `Push one or more policy documents to the Stash server.

Each document's lineage is derived from its own id. Each file may hold a single
document or several, one per line in JSON Lines format; every document in every
file is uploaded. Inputs larger than the server's per-request limit are uploaded
in batches.

Examples:
  # Push from files
  stash policy push policy1.json policy2.json

  # Push every document in a JSON Lines file
  stash policy push policies.jsonl

  # Push from stdin
  stash policy push --stdin < policy.json`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, err := opts.GetOrg()
			if err != nil {
				return err
			}

			c, cleanup, err := opts.NewClient(cmd.Context(), orgID, opts.Namespace)
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Read policy documents, reusing the JSON Lines splitter used by the
			// attestation push command.
			var policies [][]byte
			if opts.Stdin {
				docs, err := splitAttestations(os.Stdin)
				if err != nil {
					return fmt.Errorf("reading stdin: %w", err)
				}
				policies = docs
			} else {
				if len(args) == 0 {
					return fmt.Errorf("no files specified (use --stdin to read from stdin)")
				}
				for _, path := range args {
					f, err := os.Open(path)
					if err != nil {
						return fmt.Errorf("reading %s: %w", path, err)
					}
					docs, err := splitAttestations(f)
					f.Close() //nolint:errcheck,gosec // read-only file
					if err != nil {
						return fmt.Errorf("reading %s: %w", path, err)
					}
					policies = append(policies, docs...)
				}
			}

			if len(policies) == 0 {
				return errors.New("no policy documents found in input")
			}

			// A jsonl file can hold more than the server accepts per request, so
			// upload in batches and collect the results as one call.
			fmt.Printf("Pushing %d policy document(s) to org %s namespace %q...\n", len(policies), orgID, opts.Namespace)

			var results []*client.PolicyResult
			for batch := range slices.Chunk(policies, maxPushBatch) {
				r, err := c.PushPolicies(cmd.Context(), orgID, opts.Namespace, batch)
				if err != nil {
					return fmt.Errorf("pushing policies: %w", err)
				}
				results = append(results, r...)
			}

			successCount := 0
			for _, result := range results {
				switch {
				case result.Error != "":
					fmt.Printf("Failed: %s\n", result.Error)
				case result.Existed:
					fmt.Printf("Already exists: %s v%d (%s)\n", result.LineageID, result.Version, result.DocumentKind)
					successCount++
				default:
					fmt.Printf("Pushed: %s v%d (%s, hash: %s)\n", result.LineageID, result.Version, result.DocumentKind, result.ContentHash)
					successCount++
				}
			}

			fmt.Printf("\nSuccessfully pushed %d of %d policy document(s)\n", successCount, len(results))

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// addPolicyAppendCommand adds the policy append command.
func addPolicyAppendCommand(parent *cobra.Command) {
	opts := defaultPolicyAppendOptions
	cmd := &cobra.Command{
		Use:   "append [file]",
		Short: "Append a policy document as the next version of a lineage",
		Long: `Append one policy document as the next version of a named lineage.

The lineage is created if it does not exist. Exactly one document is stored,
read from a file argument or from stdin with --stdin.

Examples:
  # Append a document from a file
  stash policy append --lineage my-policy policy.json

  # Append from stdin
  stash policy append --lineage my-policy --stdin < policy.json`,
		Args: cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, err := opts.GetOrg()
			if err != nil {
				return err
			}

			c, cleanup, err := opts.NewClient(cmd.Context(), orgID, opts.Namespace)
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Read exactly one document, from stdin or the single file argument.
			var policy []byte
			switch {
			case opts.Stdin:
				policy, err = os.ReadFile(os.Stdin.Name())
				if err != nil {
					return fmt.Errorf("reading stdin: %w", err)
				}
			case len(args) == 1:
				policy, err = os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("reading %s: %w", args[0], err)
				}
			default:
				return fmt.Errorf("a policy document is required (pass a file or use --stdin)")
			}

			fmt.Printf("Appending to lineage %q in org %s namespace %q...\n", opts.Lineage, orgID, opts.Namespace)

			result, err := c.AppendPolicy(cmd.Context(), orgID, opts.Namespace, opts.Lineage, policy)
			if err != nil {
				return fmt.Errorf("appending policy: %w", err)
			}

			switch {
			case result.Error != "":
				return fmt.Errorf("appending policy: %s", result.Error)
			case result.Existed:
				fmt.Printf("Already exists: %s v%d (%s)\n", result.LineageID, result.Version, result.DocumentKind)
			default:
				fmt.Printf("Appended: %s v%d (%s, hash: %s)\n", result.LineageID, result.Version, result.DocumentKind, result.ContentHash)
			}

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// addPolicyGetCommand adds the policy get command.
func addPolicyGetCommand(parent *cobra.Command) {
	opts := defaultPolicyGetOptions
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a policy version from Stash",
		Long: `Get a version of a policy lineage from the Stash server.

By default the latest version is returned; pass --version to read a specific
0-based version. By default the metadata is printed; pass --raw to print only
the raw stored document.

Examples:
  # Get the latest version of a lineage
  stash policy get --lineage my-policy

  # Get a specific version
  stash policy get --lineage my-policy --version 2

  # Get only the raw stored document
  stash policy get --lineage my-policy --raw`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, err := opts.GetOrg()
			if err != nil {
				return err
			}

			c, cleanup, err := opts.NewClient(cmd.Context(), orgID, opts.Namespace)
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// A nil version reads the latest; only pass a version when the flag
			// was set, since 0 is a valid explicit version.
			var version *int64
			if cmd.Flags().Changed("version") {
				v := opts.Version
				version = &v
			}

			policy, raw, err := c.GetPolicy(cmd.Context(), orgID, opts.Namespace, opts.Lineage, version)
			if err != nil {
				return fmt.Errorf("getting policy: %w", err)
			}

			if opts.Raw {
				printIndentedJSON(raw)
				return nil
			}

			if policy == nil {
				return errors.New("no policy returned")
			}

			fmt.Printf("Lineage ID:        %s\n", policy.LineageID)
			fmt.Printf("Version:           %d\n", policy.Version)
			fmt.Printf("Document Kind:     %s\n", policy.DocumentKind)
			fmt.Printf("Content Hash:      %s\n", policy.ContentHash)
			if policy.PredicateType != "" {
				fmt.Printf("Predicate Type:    %s\n", policy.PredicateType)
			}
			fmt.Printf("Signed:            %v\n", policy.Signed)
			fmt.Printf("Validated:         %v\n", policy.Validated)
			if policy.ValidationError != "" {
				fmt.Printf("Validation Error:  %s\n", policy.ValidationError)
			}
			if len(policy.SignerIdentities) > 0 {
				fmt.Printf("Signer Identities: %v\n", policy.SignerIdentities)
			}
			fmt.Printf("Created At:        %s\n", policy.CreatedAt.Format("2006-01-02 15:04:05 MST"))

			if len(raw) > 0 {
				fmt.Println("\n=== Raw Policy ===")
				printIndentedJSON(raw)
			}

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// PolicyDeleteOptions holds the options for the policy delete command.
var _ command.OptionsSet = (*PolicyDeleteOptions)(nil)

type PolicyDeleteOptions struct {
	ClientOptions
	Namespace string
	Lineage   string
	Version   int64
}

var defaultPolicyDeleteOptions = PolicyDeleteOptions{
	ClientOptions: DefaultClientOptions,
	Namespace:     "",
	Lineage:       "",
	Version:       -1,
}

func (o *PolicyDeleteOptions) Validate() error {
	var errs []error
	if o.Lineage == "" {
		errs = append(errs, errors.New("a lineage ID is required (use --lineage)"))
	}
	errs = append(errs, o.ClientOptions.Validate())
	return errors.Join(errs...)
}

func (o *PolicyDeleteOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PolicyDeleteOptions) AddFlags(cmd *cobra.Command) {
	o.ClientOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "Namespace for the policy (default: empty)")
	cmd.Flags().StringVar(&o.Lineage, "lineage", "", "Lineage ID to delete from (required)")
	cmd.Flags().Int64Var(&o.Version, "version", -1, "Version to delete (0-based); omit to delete the whole lineage")
}

// addPolicyDeleteCommand adds the policy delete command.
func addPolicyDeleteCommand(parent *cobra.Command) {
	opts := defaultPolicyDeleteOptions
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a policy lineage or version from Stash",
		Long: `Delete a whole policy lineage, or one version of it.

By default the whole lineage (every version) is deleted; pass --version to
delete only that 0-based version. Deleting the current head makes the previous
version the lineage's latest.

Examples:
  # Delete a whole lineage
  stash policy delete --lineage my-policy

  # Delete only version 3
  stash policy delete --lineage my-policy --version 3`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, err := opts.GetOrg()
			if err != nil {
				return err
			}

			c, cleanup, err := opts.NewClient(cmd.Context(), orgID, opts.Namespace)
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// A nil version deletes the whole lineage; only pass a version when
			// the flag was set, since 0 is a valid explicit version.
			var version *int64
			if cmd.Flags().Changed("version") {
				v := opts.Version
				version = &v
			}

			deleted, err := c.DeletePolicy(cmd.Context(), orgID, opts.Namespace, opts.Lineage, version)
			if err != nil {
				return fmt.Errorf("deleting policy: %w", err)
			}

			if version != nil {
				fmt.Printf("Deleted version %d of lineage %s\n", *version, opts.Lineage)
			} else {
				fmt.Printf("Deleted lineage %s (%d version(s))\n", opts.Lineage, deleted)
			}
			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
