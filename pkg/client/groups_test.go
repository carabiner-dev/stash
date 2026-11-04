// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFetchGroupKeepsOrderAndBoundsParallelism(t *testing.T) {
	t.Parallel()
	refs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var running, peak atomic.Int32
	var mu sync.Mutex
	out, err := fetchGroup(t.Context(), refs, 3, func(_ context.Context, ref int) (string, error) {
		n := running.Add(1)
		mu.Lock()
		if n > peak.Load() {
			peak.Store(n)
		}
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		running.Add(-1)
		return fmt.Sprintf("doc-%d", ref), nil
	})
	require.NoError(t, err)
	for i, doc := range out {
		require.Equal(t, fmt.Sprintf("doc-%d", i), doc)
	}
	require.LessOrEqual(t, peak.Load(), int32(3))
	require.Greater(t, peak.Load(), int32(1), "reads run in parallel")
}

func TestFetchGroupFailsWhole(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	_, err := fetchGroup(t.Context(), []string{"a", "b", "c"}, 0, func(_ context.Context, ref string) (string, error) {
		if ref == "b" {
			return "", boom
		}
		return ref, nil
	})
	require.ErrorIs(t, err, boom)
	require.Contains(t, err.Error(), "b")
}

const org = "acme"

// groupFake answers GetPolicy and GetAttestation from memory; the rest of the
// interface is never called.
type groupFake struct {
	StashClient
	policies     map[string][]byte
	attestations map[string][]byte
}

func (f *groupFake) GetPolicy(_ context.Context, orgID, namespace, lineageID string, version *int64) (*Policy, []byte, error) {
	key := orgID + "/" + namespace + "/" + lineageID
	if version != nil {
		key = fmt.Sprintf("%s@%d", key, *version)
	}
	raw, ok := f.policies[key]
	if !ok {
		return nil, nil, errors.New("policy not found: " + key)
	}
	return &Policy{LineageID: lineageID}, raw, nil
}

func (f *groupFake) GetAttestation(_ context.Context, orgID, namespace, id string) (att *Attestation, raw, predicate []byte, err error) {
	raw, ok := f.attestations[orgID+"/"+namespace+"/"+id]
	if !ok {
		return nil, nil, nil, errors.New("attestation not found: " + id)
	}
	return &Attestation{ID: id}, raw, []byte(`{}`), nil
}

func TestGetPoliciesAndAttestationsGroups(t *testing.T) {
	t.Parallel()
	v2 := int64(2)
	fake := &groupFake{
		policies:     map[string][]byte{"acme//l1": []byte("head"), "acme/project:web/l2@2": []byte("v2")},
		attestations: map[string][]byte{"acme//a1": []byte("att-1"), "acme//a2": []byte("att-2")},
	}
	docs, err := getPolicies(t.Context(), fake, 0, []PolicyRef{
		{OrgID: org, LineageID: "l1"},
		{OrgID: org, Namespace: "project:web", LineageID: "l2", Version: &v2},
	})
	require.NoError(t, err)
	require.Equal(t, "head", string(docs[0].Raw))
	require.Equal(t, "v2", string(docs[1].Raw))
	require.Equal(t, "l2", docs[1].Policy.LineageID)

	atts, err := getAttestations(t.Context(), fake, 0, []AttestationRef{{OrgID: org, ID: "a2"}, {OrgID: org, ID: "a1"}})
	require.NoError(t, err)
	require.Equal(t, "att-2", string(atts[0].Raw))
	require.Equal(t, "att-1", string(atts[1].Raw))

	_, err = getPolicies(t.Context(), fake, 0, []PolicyRef{{OrgID: org, LineageID: "missing"}})
	require.Error(t, err)
}
