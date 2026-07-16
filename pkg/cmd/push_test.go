// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSplitAttestations pins that push accepts both shapes it is given: one
// attestation per file, or a JSON Lines file holding many. The single-file case
// must keep working whether or not the JSON is pretty-printed, which is why
// this splits on JSON values rather than on lines.
func TestSplitAttestations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    int
		mustErr bool
	}{
		{
			name: "a single compact attestation",
			in:   `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","a":1}`,
			want: 1,
		},
		{
			// The common case for a hand-saved attestation: splitting on lines
			// would read this as several broken fragments.
			name: "a single pretty-printed attestation",
			in: `{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {"rawBytes": "AAAA"}
  }
}`,
			want: 1,
		},
		{
			name: "json lines",
			in:   "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n",
			want: 3,
		},
		{
			name: "json lines without a trailing newline",
			in:   "{\"a\":1}\n{\"a\":2}",
			want: 2,
		},
		{
			name: "blank lines between records are insignificant",
			in:   "{\"a\":1}\n\n\n{\"a\":2}\n",
			want: 2,
		},
		{
			name: "pretty-printed records concatenated",
			in:   "{\n  \"a\": 1\n}\n{\n  \"a\": 2\n}\n",
			want: 2,
		},
		{
			name: "empty input yields nothing",
			in:   "",
			want: 0,
		},
		{
			name: "whitespace only yields nothing",
			in:   "\n  \n",
			want: 0,
		},
		{
			name:    "malformed json is reported",
			in:      `{"a":1} not-json`,
			mustErr: true,
		},
		{
			name:    "a truncated record is reported",
			in:      `{"a":`,
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitAttestations(strings.NewReader(tc.in))
			if tc.mustErr {
				if err == nil {
					t.Fatalf("splitAttestations() = %d attestations, want an error", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("splitAttestations(): %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d attestations, want %d", len(got), tc.want)
			}
			// Every record handed to the server must be valid JSON on its own.
			for i, att := range got {
				if !json.Valid(att) {
					t.Errorf("attestation %d is not valid JSON: %s", i, att)
				}
			}
		})
	}
}

// TestSplitAttestationsPreservesRecords checks the records come back whole and
// in order, not merged or truncated at the seams.
func TestSplitAttestationsPreservesRecords(t *testing.T) {
	in := "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n"

	got, err := splitAttestations(strings.NewReader(in))
	if err != nil {
		t.Fatalf("splitAttestations(): %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d attestations, want 3", len(got))
	}

	for i, att := range got {
		var parsed struct {
			N int `json:"n"`
		}
		if err := json.Unmarshal(att, &parsed); err != nil {
			t.Fatalf("attestation %d does not parse: %v", i, err)
		}
		if parsed.N != i+1 {
			t.Errorf("attestation %d carries n=%d, want %d", i, parsed.N, i+1)
		}
	}
}
