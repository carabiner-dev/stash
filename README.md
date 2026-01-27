# Stash

Stash is a client and library for attestation storage, providing tools for managing cryptographic attestations in software supply chain security workflows.

## Features

- **Batch Attestation Management**: Upload, retrieve, list, and delete attestations
- **Digital Signature Verification**: Verify attestation signatures against stored public keys
- **Advanced Filtering**: Query attestations by predicate type, subject characteristics, signer identity, and more
- **Content-based Addressing**: Reference attestations by ID, content hash, or predicate hash
- **Public Key Management**: Store and manage public keys for attestation verification
- **Flexible Output**: JSON or human-readable formatting

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/carabiner-dev/stash.git
cd stash

# Build the CLI
make build

# Install to $GOPATH/bin
make install
```

### Using Go Install

```bash
go install github.com/carabiner-dev/stash/cmd/stash@latest
```

## CLI Tool

The `stash` CLI provides a command-line interface for interacting with a Stash server.

### Configuration

Configure the CLI using environment variables, flags, or configuration files:

- **Server URL**: Set via `STASH_URL` environment variable or `--url` flag (default: `http://localhost:8080`)
- **Authentication Token**: Set via `STASH_TOKEN` environment variable, `--token` flag, or store in `~/.stash/token`

Configuration precedence: CLI flags > environment variables > config files

### Commands

#### Push Attestations

Push one or more attestation files to the server:

```bash
# Push from files
stash push attestation1.json attestation2.json

# Push from stdin
cat attestation.json | stash push --stdin

# Push multiple files with pattern
stash push attestations/*.json
```

Supports batch uploads of up to 100 attestations at once.

#### Get Attestations

Retrieve attestations by ID or hash:

```bash
# Get full attestation with metadata
stash get <attestation-id>

# Get only raw attestation JSON
stash get <attestation-id> --raw

# Get only predicate JSON
stash get <attestation-id> --predicate

# Query by content hash
stash get sha256:a1b2c3d4...

# Output as JSON
stash get <attestation-id> --json
```

#### List Attestations

Query attestations with filtering and pagination:

```bash
# List all attestations
stash list

# Filter by predicate type
stash list --predicate-type "https://slsa.dev/provenance/v1"

# Filter by subject name (exact match)
stash list --subject.name "my-artifact"

# Filter by subject name (regex)
stash list --subject-regex.name "my-.*"

# Filter by subject URI
stash list --subject-regex.uri "pkg:.*"

# Filter by subject digest
stash list --subject.digest.algorithm sha256 --subject.digest.value a1b2c3...

# Filter by signer identity
stash list --signer "user@example.com"

# Filter by validation status
stash list --signed --validated

# Pagination
stash list --limit 50 --cursor <next-cursor>

# JSON output
stash list --json
```

#### Delete Attestations

Remove attestations by ID or hash:

```bash
stash delete <attestation-id>
stash delete sha256:a1b2c3d4...
```

#### Verify Attestations

Verify attestation signatures against stored public keys:

```bash
stash verify <attestation-id>
```

#### Public Key Management

Manage public keys for attestation verification:

```bash
# Upload a public key
stash publickey upload key.pem

# List public keys
stash publickey list
stash publickey list --json

# Get specific public key
stash publickey get <key-id>

# Delete public key
stash publickey delete <key-id>
```

#### Version

Display version information:

```bash
stash version
```

## Client Library

The `pkg/client` package provides a Go client library for programmatic interaction with a Stash server.

### Installation

```bash
go get github.com/carabiner-dev/stash/pkg/client
```

### Usage

#### Initialize Client

```go
import (
    "github.com/carabiner-dev/stash/pkg/client"
    "github.com/carabiner-dev/stash/pkg/client/config"
)

// Create configuration
cfg := &config.Config{
    BaseURL: "https://stash.example.com",
    Token:   "your-auth-token",
}

// Initialize client
stashClient := client.NewClient(cfg)
```

#### Upload Attestations

```go
attestations := []map[string]interface{}{
    {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": []map[string]interface{}{
            {
                "name": "my-artifact",
                "digest": map[string]string{
                    "sha256": "a1b2c3d4...",
                },
            },
        },
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": map[string]interface{}{
            "buildDefinition": map[string]interface{}{
                "buildType": "https://example.com/build/v1",
            },
        },
    },
}

ctx := context.Background()
response, err := stashClient.UploadAttestations(ctx, attestations)
if err != nil {
    log.Fatalf("Upload failed: %v", err)
}

for _, att := range response.Attestations {
    fmt.Printf("Uploaded: %s\n", att.ID)
}
```

#### Retrieve Attestations

```go
// Get full attestation
attestation, err := stashClient.GetAttestation(ctx, "attestation-id")

// Get raw attestation JSON only
rawJSON, err := stashClient.GetAttestationRaw(ctx, "attestation-id")

// Get predicate only
predicate, err := stashClient.GetAttestationPredicate(ctx, "attestation-id")
```

#### List Attestations with Filters

```go
import "github.com/carabiner-dev/stash/pkg/client/filters"

// Create filter options
opts := &filters.ListOptions{
    PredicateType: "https://slsa.dev/provenance/v1",
    Subject: &filters.SubjectFilter{
        Name: "my-artifact",
    },
    Signed:    true,
    Validated: true,
    Limit:     50,
}

response, err := stashClient.ListAttestations(ctx, opts)
if err != nil {
    log.Fatalf("List failed: %v", err)
}

for _, att := range response.Attestations {
    fmt.Printf("ID: %s, Type: %s\n", att.ID, att.PredicateType)
}

// Handle pagination
if response.NextCursor != "" {
    opts.Cursor = response.NextCursor
    // Fetch next page...
}
```

#### Advanced Filtering

```go
// Filter with regex patterns
opts := &filters.ListOptions{
    SubjectRegex: &filters.SubjectRegexFilter{
        Name: "my-.*",
        URI:  "pkg:.*",
    },
    Signer: "user@example.com",
}

// Filter by subject digest
opts := &filters.ListOptions{
    Subject: &filters.SubjectFilter{
        Digest: &filters.DigestFilter{
            Algorithm: "sha256",
            Value:     "a1b2c3d4...",
        },
    },
}
```

#### Delete Attestations

```go
err := stashClient.DeleteAttestation(ctx, "attestation-id")
if err != nil {
    log.Fatalf("Delete failed: %v", err)
}
```

#### Public Key Management

```go
// Upload public key
keyPEM := []byte(`-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----`)

publicKey, err := stashClient.UploadPublicKey(ctx, keyPEM)
if err != nil {
    log.Fatalf("Upload key failed: %v", err)
}

// List public keys
keys, err := stashClient.ListPublicKeys(ctx)

// Get specific key
key, err := stashClient.GetPublicKey(ctx, "key-id")

// Delete key
err = stashClient.DeletePublicKey(ctx, "key-id")
```

### Client Library Features

- **Batch Operations**: Upload up to 100 attestations per request
- **Flexible Filtering**: Support for exact matches, regex patterns, and compound queries
- **Pagination Support**: Cursor-based pagination with configurable limits (up to 1000)
- **Error Handling**: Structured error responses with HTTP status codes
- **Authentication**: Bearer token authentication
- **Timeout Management**: 30-second request timeout
- **JSON Handling**: Automatic marshaling/unmarshaling of attestation data

## Data Models

### Attestation

Attestations include the following metadata:

- **ID**: Unique identifier
- **OrganizationID**: Organization that owns the attestation
- **ContentHash**: SHA-256 hash of the full attestation content
- **PredicateHash**: SHA-256 hash of the predicate portion
- **PredicateType**: Type URI of the predicate (e.g., SLSA provenance)
- **Signed**: Whether the attestation has a signature
- **Validated**: Whether the signature has been validated
- **SignerIdentities**: List of signer identity strings
- **Subjects**: Array of attestation subjects
- **CreatedAt**: Creation timestamp
- **UpdatedAt**: Last update timestamp

### Subject

Each attestation subject contains:

- **Name**: Subject name/identifier
- **Digest**: Algorithm and value (e.g., sha256)
- **URI**: Resource URI (e.g., pkg: URL)
- **DownloadLocation**: Where to download the artifact
- **MediaType**: MIME type
- **Annotations**: Additional key-value metadata

### Public Key

Public keys include:

- **ID**: Unique key identifier
- **Algorithm**: Cryptographic algorithm (e.g., RSA, ECDSA)
- **Key**: PEM-encoded public key data
- **CreatedAt**: Upload timestamp
- **OrganizationID**: Owning organization

## Development

### Build

```bash
# Build binary
make build

# Output: bin/stash
```

### Test

```bash
# Run tests with coverage
make test

# Run linters
make lint
```

### Dependencies

```bash
# Download and tidy dependencies
make deps
```

### Project Structure

```
.
├── cmd/stash/              # CLI entry point
├── internal/cli/           # CLI command implementations
│   ├── root.go
│   ├── upload.go
│   ├── read.go
│   ├── list.go
│   ├── delete.go
│   ├── update.go
│   ├── verify.go
│   └── publickey.go
├── pkg/client/            # Go client library
│   ├── client.go          # HTTP client
│   ├── attestations.go    # Attestation operations
│   ├── publickeys.go      # Public key operations
│   ├── filters.go         # Query filters
│   └── config/            # Configuration management
├── go.mod
├── Makefile
└── LICENSE
```

## Requirements

- Go 1.24.1 or later

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Use Cases

- Managing software supply chain attestations (SLSA provenance)
- Storing and verifying cryptographic proofs of artifact origins
- Organizing attestations by artifact characteristics
- Querying attestation history with complex filtering
- Integrating attestation storage into CI/CD pipelines
