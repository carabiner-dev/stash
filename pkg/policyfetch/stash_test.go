// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policyfetch

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	stashclient "github.com/carabiner-dev/stash/pkg/client"
)

const (
	org    = "acme"
	headL1 = "stash://acme/policies/_/l1"
)

func TestParse(t *testing.T) {
	t.Parallel()
	three := int64(3)
	for _, tc := range []struct {
		in   string
		want *Locator
	}{
		{headL1, &Locator{Org: org, LineageID: "l1"}},
		{"stash://acme/policies/project:web/l1@3", &Locator{Org: org, Namespace: "project:web", LineageID: "l1", Version: &three}},
		{"stash://acme/policies/_", &Locator{Org: org}},
		{"stash://acme/attestations/_/x", nil},
		{"stash://acme/policies//l1", nil},
		{"stash://acme/policies/_/l1@three", nil},
		{"stash://acme/policies/_/l1@-1", nil},
		{"https://acme/policies/_/l1", nil},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tc.in)
			if tc.want == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.in, got.String())
		})
	}
}

// fakeStash answers group reads from memory and records the refs it was
// asked, as one call.
type fakeStash struct {
	stashclient.StashClient
	docs  map[string][]byte
	asked [][]stashclient.PolicyRef
}

func (f *fakeStash) GetPolicies(_ context.Context, refs []stashclient.PolicyRef) ([]*stashclient.PolicyDocument, error) {
	f.asked = append(f.asked, refs)
	out := make([]*stashclient.PolicyDocument, 0, len(refs))
	for _, ref := range refs {
		raw, ok := f.docs[(Locator{Org: ref.OrgID, Namespace: ref.Namespace, LineageID: ref.LineageID, Version: ref.Version}).String()]
		if !ok {
			return nil, errors.New("not found: " + ref.LineageID)
		}
		out = append(out, &stashclient.PolicyDocument{Ref: ref, Raw: raw})
	}
	return out, nil
}

func TestFetcher(t *testing.T) {
	t.Parallel()
	stash := &fakeStash{docs: map[string][]byte{
		headL1:                                   []byte(`{"id":"l1"}`),
		"stash://acme/policies/project:web/l2@3": []byte(`{"id":"l2"}`),
	}}
	f := New(WithClient(stash))
	require.True(t, f.Supports(headL1))
	require.False(t, f.Supports("https://example.com/p.json"))

	doc, err := f.Get(t.Context(), headL1)
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"l1"}`, string(doc))

	// A group is one call to the client, which reads it in parallel.
	docs, err := f.GetGroup(t.Context(), []string{"stash://acme/policies/project:web/l2@3", headL1})
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"l2"}`, string(docs[0]))
	require.JSONEq(t, `{"id":"l1"}`, string(docs[1]))
	require.Len(t, stash.asked, 2)
	require.Len(t, stash.asked[1], 2)

	// A locator without a lineage or of another shape is refused before
	// anything is asked.
	_, err = f.Get(t.Context(), "stash://acme/policies/_")
	require.Error(t, err)
	_, err = f.GetGroup(t.Context(), []string{headL1, "stash://acme/nope/_/l1"})
	require.Error(t, err)
	require.Len(t, stash.asked, 2)
}
