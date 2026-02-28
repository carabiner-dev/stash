package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDeriveOrgFromToken(t *testing.T) {
	tests := []struct {
		name       string
		namespaces []string
		wantOrg    string
		wantErr    bool
	}{
		{
			name: "single org - should derive",
			namespaces: []string{
				"https://stash.dev.carabiner.dev/v1/puerco/*",
			},
			wantOrg: "puerco",
			wantErr: false,
		},
		{
			name: "single org with specific namespace - should derive",
			namespaces: []string{
				"https://stash.dev.carabiner.dev/v1/myorg/production",
			},
			wantOrg: "myorg",
			wantErr: false,
		},
		{
			name: "multiple namespaces same org - should derive",
			namespaces: []string{
				"https://stash.dev.carabiner.dev/v1/myorg/production",
				"https://stash.dev.carabiner.dev/v1/myorg/staging",
			},
			wantOrg: "myorg",
			wantErr: false,
		},
		{
			name: "multiple orgs - cannot derive",
			namespaces: []string{
				"https://stash.dev.carabiner.dev/v1/org1/*",
				"https://stash.dev.carabiner.dev/v1/org2/*",
			},
			wantOrg: "",
			wantErr: false, // Not an error, just can't derive
		},
		{
			name:       "no namespaces - cannot derive",
			namespaces: []string{},
			wantOrg:    "",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock token with the namespaces claim
			token := createMockToken(tt.namespaces)

			// Create a config with a mock token source
			cfg := &Config{
				UseCredentialsManager: true,
				tokenSource: &mockTokenSource{
					token: token,
				},
			}

			// Derive org from token
			org, err := cfg.DeriveOrgFromToken(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveOrgFromToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if org != tt.wantOrg {
				t.Errorf("DeriveOrgFromToken() = %q, want %q", org, tt.wantOrg)
			}
		})
	}
}

// createMockToken creates a JWT-like token with the given namespaces claim
func createMockToken(namespaces []string) string {
	claims := map[string]interface{}{
		"namespaces": namespaces,
		"iss":        "https://auth.dev.carabiner.dev",
		"aud":        "stash",
		"sub":        "user@example.com",
	}

	payload, _ := json.Marshal(claims)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	// Create a fake JWT (header.payload.signature)
	// We only need the payload to be valid for this test
	return "eyJhbGciOiJSUzI1NiJ9." + encodedPayload + ".fake-signature"
}

// mockTokenSource is a mock implementation of TokenSource for testing
type mockTokenSource struct {
	token string
	err   error
}

func (m *mockTokenSource) Token(ctx context.Context) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}
