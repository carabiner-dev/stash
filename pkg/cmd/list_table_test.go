// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"
	"time"

	"github.com/carabiner-dev/stash/pkg/client"
)

func TestFormatCreated(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.Local)

	for _, tc := range []struct {
		name string
		in   time.Time
		want string
	}{
		{"just now shows the time", now, "12:00:00"},
		{"an hour ago shows the time", now.Add(-time.Hour), "11:00:00"},
		{"just under 24h shows the time", now.Add(-24*time.Hour + time.Second), "12:00:01"},
		{"exactly 24h shows the date", now.Add(-24 * time.Hour), "2026-07-15"},
		{"older shows the date", now.Add(-72 * time.Hour), "2026-07-13"},
		{"zero renders empty", time.Time{}, ""},
		// A clock-skewed server timestamp must not be rendered as a time,
		// which would silently read as "moments ago".
		{"future shows the date", now.Add(48 * time.Hour), "2026-07-18"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := formatCreated(tc.in, now)
			if got != tc.want {
				t.Errorf("formatCreated() = %q, want %q", got, tc.want)
			}
			if len(got) > createdWidth {
				t.Errorf("formatCreated() = %q is %d wide, exceeds the %d-wide column", got, len(got), createdWidth)
			}
		})
	}
}

func TestSubjectSlugs(t *testing.T) {
	for _, tc := range []struct {
		name string
		subs []client.Subject
		want []string
	}{
		{
			name: "digest is preferred",
			subs: []client.Subject{{Name: "artifact", DigestAlgorithm: "sha256", DigestValue: "abc"}},
			want: []string{"sha256:abc"},
		},
		{
			name: "falls back to the name when there is no digest",
			subs: []client.Subject{{Name: "artifact"}},
			want: []string{"artifact"},
		},
		{
			name: "subjects with neither are skipped",
			subs: []client.Subject{{}, {Name: "kept"}},
			want: []string{"kept"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := subjectSlugs(&client.Attestation{Subjects: tc.subs})
			if len(got) != len(tc.want) {
				t.Fatalf("subjectSlugs() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("subjectSlugs()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestBuildListRowsExpansion pins the multi-line layout: extra signers and
// extra subjects each get their own line, and only the first line of an
// attestation repeats the identifying columns.
func TestBuildListRowsExpansion(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.Local)
	atts := []*client.Attestation{{
		ID:               "id-1",
		PredicateType:    "https://slsa.dev/provenance/v1",
		SignerIdentities: []string{"signer-a", "signer-b"},
		Validated:        true,
		CreatedAt:        now.Add(-72 * time.Hour),
		Subjects: []client.Subject{
			{DigestAlgorithm: "sha256", DigestValue: "aaa"},
			{DigestAlgorithm: "sha256", DigestValue: "bbb"},
		},
	}}

	rows := buildListRows(atts, now)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3 (2 signers + 1 extra subject)", len(rows))
	}

	// First line carries everything.
	if rows[0].id != "id-1" || rows[0].identity != "signer-a" || rows[0].subject != "sha256:aaa" {
		t.Errorf("first row = %+v, want the id, first signer and first subject", rows[0])
	}
	if rows[0].verified != markVerified || rows[0].created != "2026-07-13" {
		t.Errorf("first row = %+v, want verified mark and date", rows[0])
	}

	// Second signer: only the identity, so the id is not repeated.
	if rows[1].identity != "signer-b" {
		t.Errorf("second row identity = %q, want signer-b", rows[1].identity)
	}
	if rows[1].id != "" || rows[1].predicateType != "" || rows[1].verified != "" || rows[1].created != "" {
		t.Errorf("second row = %+v, want only the identity populated", rows[1])
	}

	// Extra subject: only the subject.
	if rows[2].subject != "sha256:bbb" {
		t.Errorf("third row subject = %q, want sha256:bbb", rows[2].subject)
	}
	if rows[2].id != "" || rows[2].identity != "" {
		t.Errorf("third row = %+v, want only the subject populated", rows[2])
	}
}

func TestBuildListRowsFallbacks(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.Local)
	rows := buildListRows([]*client.Attestation{{
		ID:        "id-1",
		CreatedAt: now,
	}}, now)

	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].predicateType != "[not defined]" {
		t.Errorf("predicateType = %q, want [not defined]", rows[0].predicateType)
	}
	if rows[0].identity != "[unsigned]" {
		t.Errorf("identity = %q, want [unsigned]", rows[0].identity)
	}
	if rows[0].verified != markUnverified {
		t.Errorf("verified = %q, want %q", rows[0].verified, markUnverified)
	}
}
