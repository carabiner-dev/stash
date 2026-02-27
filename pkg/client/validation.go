package client

import (
	"fmt"
	"regexp"
	"strings"
)

// DNS hostname validation rules (RFC 1123):
// - Must be 1-63 characters per label
// - Labels separated by dots
// - Can contain lowercase letters, digits, and hyphens
// - Must start and end with alphanumeric character
// - Total length max 253 characters
var dnsHostnameRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// ValidateOrgID validates that an organization ID conforms to DNS hostname rules.
func ValidateOrgID(orgID string) error {
	if orgID == "" {
		return fmt.Errorf("org ID cannot be empty")
	}

	// Check total length
	if len(orgID) > 253 {
		return fmt.Errorf("org ID exceeds maximum length of 253 characters")
	}

	// Check DNS hostname format
	if !dnsHostnameRegex.MatchString(orgID) {
		return fmt.Errorf("org ID must be a valid DNS hostname (lowercase letters, digits, hyphens, and dots only)")
	}

	// Check label lengths (each part between dots)
	labels := strings.Split(orgID, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("org ID label %q exceeds maximum length of 63 characters", label)
		}
	}

	return nil
}
