// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"fmt"

	"github.com/carabiner-dev/stash/pkg/client"
)

// ExampleNewRepositoryClient demonstrates creating a repository client.
func ExampleNewRepositoryClient() {
	// Create a Stash client (gRPC or REST)
	stashClient := client.NewClient("https://stash.example.com", "your-bearer-token")

	// Wrap it with the repository client for attestation framework compatibility
	repo := client.NewRepositoryClient(stashClient, "my-org", "default")

	fmt.Printf("Repository client created for org: my-org, namespace: default\n")
	_ = repo // Use the repo in your application

	// Output:
	// Repository client created for org: my-org, namespace: default
}
