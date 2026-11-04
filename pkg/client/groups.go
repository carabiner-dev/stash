// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"
)

// DefaultGroupParallelism bounds how many documents of a group are read at
// once when a client sets no Parallelism of its own.
const DefaultGroupParallelism = 8

// PolicyRef names one version of a policy lineage: a nil Version is the
// lineage's head.
type PolicyRef struct {
	OrgID     string
	Namespace string
	LineageID string
	Version   *int64
}

// PolicyDocument is what a group read answers for one PolicyRef.
type PolicyDocument struct {
	Ref    PolicyRef
	Policy *Policy
	Raw    []byte
}

// AttestationRef names one attestation by id.
type AttestationRef struct {
	OrgID     string
	Namespace string
	ID        string
}

// AttestationDocument is what a group read answers for one AttestationRef.
type AttestationDocument struct {
	Ref         AttestationRef
	Attestation *Attestation
	Raw         []byte
	Predicate   []byte
}

// fetchGroup reads every ref with fetch, at most limit at a time, and answers
// the documents in the order of the refs. The first failure fails the group
// and cancels the reads still running.
func fetchGroup[R, D any](ctx context.Context, refs []R, limit int, fetch func(context.Context, R) (D, error)) ([]D, error) {
	if limit <= 0 {
		limit = DefaultGroupParallelism
	}
	out := make([]D, len(refs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	for i, ref := range refs {
		g.Go(func() error {
			doc, err := fetch(gctx, ref)
			if err != nil {
				return fmt.Errorf("reading %v: %w", ref, err)
			}
			out[i] = doc
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

func getPolicies(ctx context.Context, c StashClient, limit int, refs []PolicyRef) ([]*PolicyDocument, error) {
	return fetchGroup(ctx, refs, limit, func(ctx context.Context, ref PolicyRef) (*PolicyDocument, error) {
		policy, raw, err := c.GetPolicy(ctx, ref.OrgID, ref.Namespace, ref.LineageID, ref.Version)
		if err != nil {
			return nil, err
		}
		return &PolicyDocument{Ref: ref, Policy: policy, Raw: raw}, nil
	})
}

func getAttestations(ctx context.Context, c StashClient, limit int, refs []AttestationRef) ([]*AttestationDocument, error) {
	return fetchGroup(ctx, refs, limit, func(ctx context.Context, ref AttestationRef) (*AttestationDocument, error) {
		att, raw, predicate, err := c.GetAttestation(ctx, ref.OrgID, ref.Namespace, ref.ID)
		if err != nil {
			return nil, err
		}
		return &AttestationDocument{Ref: ref, Attestation: att, Raw: raw, Predicate: predicate}, nil
	})
}

// GetPolicies reads a group of policy versions in parallel, Parallelism at a
// time, in the order given.
func (c *GRPCClient) GetPolicies(ctx context.Context, refs []PolicyRef) ([]*PolicyDocument, error) {
	return getPolicies(ctx, c, c.Parallelism, refs)
}

// GetAttestations reads a group of attestations in parallel, Parallelism at
// a time, in the order given.
func (c *GRPCClient) GetAttestations(ctx context.Context, refs []AttestationRef) ([]*AttestationDocument, error) {
	return getAttestations(ctx, c, c.Parallelism, refs)
}

// GetPolicies reads a group of policy versions in parallel, Parallelism at a
// time, in the order given.
func (c *Client) GetPolicies(ctx context.Context, refs []PolicyRef) ([]*PolicyDocument, error) {
	return getPolicies(ctx, c, c.Parallelism, refs)
}

// GetAttestations reads a group of attestations in parallel, Parallelism at
// a time, in the order given.
func (c *Client) GetAttestations(ctx context.Context, refs []AttestationRef) ([]*AttestationDocument, error) {
	return getAttestations(ctx, c, c.Parallelism, refs)
}
