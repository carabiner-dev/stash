package client

import (
	"net/url"
	"strings"

	stashv1 "github.com/carabiner-dev/stash/api/carabiner/stash/v1"
)

// protoToAttestation converts a proto Attestation to client Attestation.
func protoToAttestation(pb *stashv1.Attestation) *Attestation {
	if pb == nil {
		return nil
	}

	att := &Attestation{
		ID:               pb.AttestationId,
		ContentHash:      pb.ContentHash,
		PredicateHash:    pb.PredicateHash,
		PredicateType:    pb.PredicateType,
		Signed:           pb.Signed,
		Validated:        pb.Validated,
		ValidationError:  pb.ValidationError,
		SignerIdentities: pb.SignerIdentities,
	}

	if pb.CreatedAt != nil {
		att.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		att.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	if pb.PredicateTimestamp != nil {
		t := pb.PredicateTimestamp.AsTime()
		att.PredicateTimestamp = &t
	}

	// Convert subjects
	att.Subjects = make([]Subject, 0, len(pb.Subjects))
	for _, s := range pb.Subjects {
		// Convert annotations from Any to string (simplified)
		annotations := make(map[string]string)
		for k, v := range s.Annotations {
			if v != nil {
				annotations[k] = string(v.Value)
			}
		}

		// Proto has digest as map, client stores each algo separately
		for algo, value := range s.Digest {
			att.Subjects = append(att.Subjects, Subject{
				Name:             s.Name,
				DigestAlgorithm:  algo,
				DigestValue:      value,
				URI:              s.Uri,
				DownloadLocation: s.DownloadLocation,
				MediaType:        s.MediaType,
				Annotations:      annotations,
			})
		}
	}

	return att
}

// parseAddress extracts host:port and determines if insecure from a URL.
func parseAddress(baseURL string) (address string, insecure bool) {
	// Default values
	insecure = false

	// Parse the URL
	u, err := url.Parse(baseURL)
	if err != nil {
		// Assume it's already in host:port format
		return baseURL, true
	}

	// Determine if insecure based on scheme
	insecure = u.Scheme == "http"

	// Extract host:port
	host := u.Hostname()
	port := u.Port()

	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	return host + ":" + port, insecure
}

// isGRPCAddress checks if an address looks like a gRPC address (host:port without scheme).
func isGRPCAddress(address string) bool {
	return !strings.Contains(address, "://")
}
