package client

import (
	"testing"
)

func TestValidateOrgID(t *testing.T) {
	tests := []struct {
		name    string
		orgID   string
		wantErr bool
	}{
		// Valid cases
		{
			name:    "simple lowercase",
			orgID:   "myorg",
			wantErr: false,
		},
		{
			name:    "with hyphens",
			orgID:   "my-org",
			wantErr: false,
		},
		{
			name:    "with numbers",
			orgID:   "org123",
			wantErr: false,
		},
		{
			name:    "with dots (subdomain style)",
			orgID:   "my.org.name",
			wantErr: false,
		},

		// Invalid cases
		{
			name:    "empty string",
			orgID:   "",
			wantErr: true,
		},
		{
			name:    "uppercase letters",
			orgID:   "MyOrg",
			wantErr: true,
		},
		{
			name:    "starts with hyphen",
			orgID:   "-myorg",
			wantErr: true,
		},
		{
			name:    "ends with hyphen",
			orgID:   "myorg-",
			wantErr: true,
		},
		{
			name:    "contains underscore",
			orgID:   "my_org",
			wantErr: true,
		},
		{
			name:    "contains space",
			orgID:   "my org",
			wantErr: true,
		},
		{
			name:    "too long (254 chars)",
			orgID:   "a123456789012345678901234567890123456789012345678901234567890123.a123456789012345678901234567890123456789012345678901234567890123.a123456789012345678901234567890123456789012345678901234567890123.a123456789012345678901234567890123456789012345678901234567890123",
			wantErr: true,
		},
		{
			name:    "label too long (64 chars)",
			orgID:   "a1234567890123456789012345678901234567890123456789012345678901234",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOrgID(tt.orgID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOrgID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
