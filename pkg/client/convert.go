package client

import (
	"net/url"

	stashv1 "github.com/carabiner-dev/stash/api/carabiner/stash/v1"
)

// protoToAttestation converts a proto Attestation to client Attestation.
func protoToAttestation(pb *stashv1.Attestation) *Attestation {
	if pb == nil {
		return nil
	}

	att := &Attestation{
		ID:               pb.GetAttestationId(),
		OrgID:            "", // TODO: Add to proto definition
		Namespace:        "", // TODO: Add to proto definition
		ContentHash:      pb.GetContentHash(),
		PredicateHash:    pb.GetPredicateHash(),
		PredicateType:    pb.GetPredicateType(),
		Signed:           pb.GetSigned(),
		Validated:        pb.GetValidated(),
		ValidationError:  pb.GetValidationError(),
		SignerIdentities: pb.GetSignerIdentities(),
	}

	if pb.GetCreatedAt() != nil {
		att.CreatedAt = pb.GetCreatedAt().AsTime()
	}
	if pb.GetUpdatedAt() != nil {
		att.UpdatedAt = pb.GetUpdatedAt().AsTime()
	}
	if pb.GetPredicateTimestamp() != nil {
		t := pb.GetPredicateTimestamp().AsTime()
		att.PredicateTimestamp = &t
	}

	// Convert subjects
	att.Subjects = make([]Subject, 0, len(pb.GetSubjects()))
	for _, s := range pb.GetSubjects() {
		// Convert annotations from Any to string (simplified)
		annotations := make(map[string]string)
		for k, v := range s.GetAnnotations() {
			if v != nil {
				annotations[k] = string(v.GetValue())
			}
		}

		// Proto has digest as map, client stores each algo separately
		for algo, value := range s.GetDigest() {
			att.Subjects = append(att.Subjects, Subject{
				Name:             s.GetName(),
				DigestAlgorithm:  algo,
				DigestValue:      value,
				URI:              s.GetUri(),
				DownloadLocation: s.GetDownloadLocation(),
				MediaType:        s.GetMediaType(),
				Annotations:      annotations,
			})
		}
	}

	return att
}

// protoToPolicy converts a proto Policy to a client Policy.
func protoToPolicy(pb *stashv1.Policy) *Policy {
	if pb == nil {
		return nil
	}

	p := &Policy{
		LineageID:        pb.GetLineageId(),
		Version:          pb.GetVersion(),
		DocumentKind:     pb.GetDocumentKind(),
		ContentHash:      pb.GetContentHash(),
		PredicateType:    pb.GetPredicateType(),
		Signed:           pb.GetSigned(),
		Validated:        pb.GetValidated(),
		ValidationError:  pb.GetValidationError(),
		SignerIdentities: pb.GetSignerIdentities(),
	}

	if pb.GetCreatedAt() != nil {
		p.CreatedAt = pb.GetCreatedAt().AsTime()
	}

	return p
}

// protoToPolicyResult converts a proto PolicyResult to a client PolicyResult.
func protoToPolicyResult(pb *stashv1.PolicyResult) *PolicyResult {
	if pb == nil {
		return nil
	}

	return &PolicyResult{
		LineageID:        pb.GetLineageId(),
		Version:          pb.GetVersion(),
		DocumentKind:     pb.GetDocumentKind(),
		ContentHash:      pb.GetContentHash(),
		Signed:           pb.GetSigned(),
		Validated:        pb.GetValidated(),
		SignerIdentities: pb.GetSignerIdentities(),
		Existed:          pb.GetExisted(),
		Error:            pb.GetError(),
	}
}

// parseAddress extracts host:port and determines if insecure from a URL.
func parseAddress(baseURL string) (address string, insecure bool) {
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
