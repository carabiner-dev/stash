// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/envelope"
)

// RepositoryClient wraps a StashClient to implement attestation framework repository interfaces.
// This allows Stash to be used as an attestation.Repository for the Carabiner attestation framework.
//
// It implements:
// - attestation.Fetcher
// - attestation.FetcherBySubject
// - attestation.FetcherByPredicateType
// - attestation.FetcherByPredicateTypeAndSubject
// - attestation.Storer
type RepositoryClient struct {
	client    StashClient
	orgID     string
	namespace string
	parsers   envelope.ParserList
}

// NewRepositoryClient creates a new repository client for the attestation framework.
// The orgID and namespace specify which organization and namespace to operate on.
// If orgID is empty, it will be derived from the bearer token in authenticated requests.
func NewRepositoryClient(client StashClient, orgID, namespace string) *RepositoryClient {
	return &RepositoryClient{
		client:    client,
		orgID:     orgID,
		namespace: namespace,
		parsers:   envelope.Parsers,
	}
}

// Verify interface implementations at compile time.
var _ attestation.Fetcher = (*RepositoryClient)(nil)
var _ attestation.FetcherBySubject = (*RepositoryClient)(nil)
var _ attestation.FetcherByPredicateType = (*RepositoryClient)(nil)
var _ attestation.FetcherByPredicateTypeAndSubject = (*RepositoryClient)(nil)
var _ attestation.Storer = (*RepositoryClient)(nil)

// Fetch retrieves attestations from the repository.
// Implements attestation.Fetcher.
func (r *RepositoryClient) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	// Convert FetchOptions to Stash filters and cursor
	filters, cursor := r.fetchOptionsToStash(opts)

	// List attestations
	result, err := r.client.ListAttestations(ctx, r.orgID, r.namespace, filters, cursor)
	if err != nil {
		return nil, fmt.Errorf("listing attestations: %w", err)
	}

	// Fetch raw attestations and parse into envelopes
	envelopes := make([]attestation.Envelope, 0, len(result.Attestations))
	for _, att := range result.Attestations {
		// Get raw attestation data
		raw, err := r.client.GetAttestationRaw(ctx, r.orgID, r.namespace, att.ID)
		if err != nil {
			return nil, fmt.Errorf("getting raw attestation %s: %w", att.ID, err)
		}

		// Parse into envelope(s)
		envs, err := r.parseRawAttestation(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing attestation %s: %w", att.ID, err)
		}

		envelopes = append(envelopes, envs...)
	}

	return envelopes, nil
}

// FetchBySubject retrieves attestations filtered by subject.
// Implements attestation.FetcherBySubject.
func (r *RepositoryClient) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	if len(subjects) == 0 {
		return r.Fetch(ctx, opts)
	}

	// Convert subjects to filters
	filters, cursor := r.fetchOptionsToStash(opts)
	r.addSubjectFilters(filters, subjects)

	// List attestations with subject filters
	result, err := r.client.ListAttestations(ctx, r.orgID, r.namespace, filters, cursor)
	if err != nil {
		return nil, fmt.Errorf("listing attestations by subject: %w", err)
	}

	// Fetch and parse raw attestations
	envelopes := make([]attestation.Envelope, 0, len(result.Attestations))
	for _, att := range result.Attestations {
		raw, err := r.client.GetAttestationRaw(ctx, r.orgID, r.namespace, att.ID)
		if err != nil {
			return nil, fmt.Errorf("getting raw attestation %s: %w", att.ID, err)
		}

		envs, err := r.parseRawAttestation(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing attestation %s: %w", att.ID, err)
		}

		envelopes = append(envelopes, envs...)
	}

	return envelopes, nil
}

// FetchByPredicateType retrieves attestations filtered by predicate type.
// Implements attestation.FetcherByPredicateType.
func (r *RepositoryClient) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, predicateTypes []attestation.PredicateType) ([]attestation.Envelope, error) {
	if len(predicateTypes) == 0 {
		return r.Fetch(ctx, opts)
	}

	// Stash currently supports filtering by a single predicate type
	// For multiple predicate types, we'll fetch each separately and merge
	var allEnvelopes []attestation.Envelope

	for _, pt := range predicateTypes {
		filters, cursor := r.fetchOptionsToStash(opts)
		filters.PredicateType = string(pt)

		result, err := r.client.ListAttestations(ctx, r.orgID, r.namespace, filters, cursor)
		if err != nil {
			return nil, fmt.Errorf("listing attestations by predicate type %s: %w", pt, err)
		}

		// Fetch and parse raw attestations
		for _, att := range result.Attestations {
			raw, err := r.client.GetAttestationRaw(ctx, r.orgID, r.namespace, att.ID)
			if err != nil {
				return nil, fmt.Errorf("getting raw attestation %s: %w", att.ID, err)
			}

			envs, err := r.parseRawAttestation(raw)
			if err != nil {
				return nil, fmt.Errorf("parsing attestation %s: %w", att.ID, err)
			}

			allEnvelopes = append(allEnvelopes, envs...)
		}
	}

	return allEnvelopes, nil
}

// FetchByPredicateTypeAndSubject retrieves attestations filtered by both predicate type and subject.
// Implements attestation.FetcherByPredicateTypeAndSubject.
func (r *RepositoryClient) FetchByPredicateTypeAndSubject(ctx context.Context, opts attestation.FetchOptions, predicateTypes []attestation.PredicateType, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	if len(predicateTypes) == 0 && len(subjects) == 0 {
		return r.Fetch(ctx, opts)
	}

	if len(predicateTypes) == 0 {
		return r.FetchBySubject(ctx, opts, subjects)
	}

	if len(subjects) == 0 {
		return r.FetchByPredicateType(ctx, opts, predicateTypes)
	}

	// For multiple predicate types, fetch each separately with subject filters
	var allEnvelopes []attestation.Envelope

	for _, pt := range predicateTypes {
		filters, cursor := r.fetchOptionsToStash(opts)
		filters.PredicateType = string(pt)
		r.addSubjectFilters(filters, subjects)

		result, err := r.client.ListAttestations(ctx, r.orgID, r.namespace, filters, cursor)
		if err != nil {
			return nil, fmt.Errorf("listing attestations by predicate type %s and subject: %w", pt, err)
		}

		// Fetch and parse raw attestations
		for _, att := range result.Attestations {
			raw, err := r.client.GetAttestationRaw(ctx, r.orgID, r.namespace, att.ID)
			if err != nil {
				return nil, fmt.Errorf("getting raw attestation %s: %w", att.ID, err)
			}

			envs, err := r.parseRawAttestation(raw)
			if err != nil {
				return nil, fmt.Errorf("parsing attestation %s: %w", att.ID, err)
			}

			allEnvelopes = append(allEnvelopes, envs...)
		}
	}

	return allEnvelopes, nil
}

// Store persists attestations to the repository.
// Implements attestation.Storer.
func (r *RepositoryClient) Store(ctx context.Context, opts attestation.StoreOptions, envelopes []attestation.Envelope) error {
	if len(envelopes) == 0 {
		return nil
	}

	// Convert envelopes to raw bytes
	rawAttestations := make([][]byte, 0, len(envelopes))
	for i, env := range envelopes {
		// Marshal envelope to JSON using standard json.Marshal
		// The concrete envelope types should implement json.Marshaler or be marshalable
		raw, err := r.marshalEnvelope(env)
		if err != nil {
			return fmt.Errorf("marshaling envelope %d: %w", i, err)
		}
		rawAttestations = append(rawAttestations, raw)
	}

	// Upload attestations
	results, err := r.client.UploadAttestations(ctx, r.orgID, r.namespace, rawAttestations)
	if err != nil {
		return fmt.Errorf("uploading attestations: %w", err)
	}

	// Check for errors in individual uploads
	for i, result := range results {
		if result.Error != "" {
			return fmt.Errorf("uploading attestation %d: %s", i, result.Error)
		}
	}

	return nil
}

// marshalEnvelope marshals an envelope to JSON bytes.
// This works by using the underlying concrete type which should be JSON serializable.
func (r *RepositoryClient) marshalEnvelope(env attestation.Envelope) ([]byte, error) {
	// The envelope is typically a concrete type (DSSE, Bundle, etc.) that can be marshaled
	// We rely on Go's json.Marshal to handle the concrete type
	return json.Marshal(env)
}

// fetchOptionsToStash converts attestation.FetchOptions to Stash Filters and Cursor.
func (r *RepositoryClient) fetchOptionsToStash(opts attestation.FetchOptions) (*Filters, *Cursor) {
	filters := &Filters{}
	var cursor *Cursor

	if opts.Limit > 0 {
		cursor = &Cursor{
			Limit: opts.Limit,
		}
	}

	// Note: attestation.FetchOptions.Query is not directly convertible to Stash filters
	// If Query is set, additional filtering logic would be needed here
	// For now, we rely on the specific Fetch* methods to set appropriate filters

	return filters, cursor
}

// addSubjectFilters adds subject filters to the Stash Filters based on attestation.Subject list.
// For multiple subjects, we currently use the first subject's data.
// TODO: Support multiple subject filters or fetching in batches.
func (r *RepositoryClient) addSubjectFilters(filters *Filters, subjects []attestation.Subject) {
	if len(subjects) == 0 {
		return
	}

	// Use the first subject for filtering
	// Note: Stash currently supports filtering by a single subject at a time
	subject := subjects[0]

	if subject != nil {
		if name := subject.GetName(); name != "" {
			filters.SubjectName = name
		}

		if uri := subject.GetUri(); uri != "" {
			filters.SubjectURI = uri
		}

		if digest := subject.GetDigest(); len(digest) > 0 {
			filters.SubjectDigest = digest
		}
	}
}

// parseRawAttestation parses raw attestation bytes into envelope(s).
func (r *RepositoryClient) parseRawAttestation(raw []byte) ([]attestation.Envelope, error) {
	reader := bytes.NewReader(raw)
	envelopes, err := r.parsers.Parse(reader)
	if err != nil {
		return nil, fmt.Errorf("parsing raw attestation: %w", err)
	}

	if len(envelopes) == 0 {
		return nil, fmt.Errorf("no envelopes found in raw attestation")
	}

	return envelopes, nil
}
