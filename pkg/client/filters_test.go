// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"testing"
	"time"
)

// The stored-date bounds travel as RFC 3339 UTC timestamps, and only when set.
func TestFiltersCreatedBoundsToQueryParams(t *testing.T) {
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	until := time.Date(2026, 9, 30, 23, 59, 59, 999000000, time.UTC)

	params := (&Filters{CreatedSince: since, CreatedUntil: until}).toQueryParams(nil)
	if got := params.Get("created_since"); got != "2026-08-31T22:00:00Z" {
		t.Errorf("created_since = %q, want the instant in UTC", got)
	}
	if got := params.Get("created_until"); got != "2026-09-30T23:59:59.999Z" {
		t.Errorf("created_until = %q", got)
	}

	unset := (&Filters{PredicateType: "p"}).toQueryParams(nil)
	if unset.Has("created_since") || unset.Has("created_until") {
		t.Errorf("unset bounds must not be sent: %v", unset)
	}
}
