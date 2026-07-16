// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"time"

	"github.com/carabiner-dev/termtable"

	"github.com/carabiner-dev/stash/pkg/client"
)

const (
	policyHeaderLineage   = "LINEAGE"
	policyHeaderVersion   = "V#"
	policyHeaderKind      = "KIND"
	policyHeaderPredicate = "PREDICATE TYPE"
	policyHeaderSigner    = "SIGNER IDENTITY"
	policyHeaderVerified  = "V"
	policyHeaderCreated   = "CREATED"

	// versionWidth pins the version column: version numbers are short and the
	// header ("V#") sets its floor.
	versionWidth = 4

	// kindWidth fits the longest document kind ("policygroup").
	kindWidth = 11
)

// printPolicyListTable renders the `policy list` table: one row per lineage at
// its latest version. It mirrors the borderless bnd-style layout of the
// attestation list.
func printPolicyListTable(w io.Writer, policies []*client.Policy, now time.Time) {
	t := newListTable()

	// LINEAGE is pinned wide enough for a UUID so a signed lineage id stays
	// copy-pasteable; V#, V and CREATED are pinned to their contents; the two
	// descriptive columns share the rest and clip.
	t.Column(0).Style(fmt.Sprintf("white-space: nowrap; width: %d", uuidWidth))
	t.Column(1).Style(fmt.Sprintf("white-space: nowrap; width: %d", versionWidth))
	t.Column(2).Style(fmt.Sprintf("white-space: nowrap; width: %d", kindWidth))
	// Predicate types are URLs that differ at the END, so clip the head.
	t.Column(3).Style("white-space: nowrap; text-overflow: ellipsis; text-overflow-position: start; flex: 1")
	t.Column(4).Style("white-space: nowrap; width: 1")
	t.Column(5).Style(fmt.Sprintf("white-space: nowrap; width: %d", createdWidth))

	hdr := t.AddHeader(termtable.WithRowBorderBottom(termtable.BorderEdgeSolid))
	for _, title := range []string{
		policyHeaderLineage, policyHeaderVersion, policyHeaderKind,
		policyHeaderPredicate, policyHeaderVerified, policyHeaderCreated,
	} {
		hdr.AddCell(termtable.WithContent(title))
	}

	for _, p := range policies {
		if p == nil {
			continue
		}
		row := t.AddRow()
		row.AddCell(termtable.WithContent(p.LineageID))
		row.AddCell(termtable.WithContent(fmt.Sprintf("%d", p.Version)))
		row.AddCell(termtable.WithContent(p.DocumentKind))
		row.AddCell(termtable.WithContent(policyPredicate(p)))
		row.AddCell(termtable.WithContent(policyVerifiedMark(p)))
		row.AddCell(termtable.WithContent(formatCreated(p.CreatedAt, now)))
	}

	_, _ = t.WriteTo(w) //nolint:errcheck // writing to terminal
}

// printPolicyVersionsTable renders the `policy versions` table: every version of
// one lineage, newest first. The lineage id is the same on every row, so it is
// dropped in favor of a signer column.
func printPolicyVersionsTable(w io.Writer, policies []*client.Policy, now time.Time) {
	t := newListTable()

	t.Column(0).Style(fmt.Sprintf("white-space: nowrap; width: %d", versionWidth))
	t.Column(1).Style(fmt.Sprintf("white-space: nowrap; width: %d", kindWidth))
	// Predicate types differ at the END; signer identities keep their "type::"
	// prefix and tail, losing the middle.
	t.Column(2).Style("white-space: nowrap; text-overflow: ellipsis; text-overflow-position: start; flex: 1")
	t.Column(3).Style("white-space: nowrap; text-overflow: ellipsis; text-overflow-position: middle; flex: 1")
	t.Column(4).Style("white-space: nowrap; width: 1")
	t.Column(5).Style(fmt.Sprintf("white-space: nowrap; width: %d", createdWidth))

	hdr := t.AddHeader(termtable.WithRowBorderBottom(termtable.BorderEdgeSolid))
	for _, title := range []string{
		policyHeaderVersion, policyHeaderKind, policyHeaderPredicate,
		policyHeaderSigner, policyHeaderVerified, policyHeaderCreated,
	} {
		hdr.AddCell(termtable.WithContent(title))
	}

	for _, p := range policies {
		if p == nil {
			continue
		}
		row := t.AddRow()
		row.AddCell(termtable.WithContent(fmt.Sprintf("%d", p.Version)))
		row.AddCell(termtable.WithContent(p.DocumentKind))
		row.AddCell(termtable.WithContent(policyPredicate(p)))
		row.AddCell(termtable.WithContent(policySigner(p)))
		row.AddCell(termtable.WithContent(policyVerifiedMark(p)))
		row.AddCell(termtable.WithContent(formatCreated(p.CreatedAt, now)))
	}

	_, _ = t.WriteTo(w) //nolint:errcheck // writing to terminal
}

// policyPredicate renders the predicate-type column, marking documents that
// carry none.
func policyPredicate(p *client.Policy) string {
	if p.PredicateType == "" {
		return labelNotDefined
	}
	return p.PredicateType
}

// policyVerifiedMark renders the V column: whether the policy's signature was
// verified when it was stored.
func policyVerifiedMark(p *client.Policy) string {
	if p.Validated {
		return markVerified
	}
	return markUnverified
}

// policySigner renders the signer column for a policy version. The server only
// records identities it verified, so an absence means either nothing signed the
// document or a signature did not check out — the two are distinguished the same
// way the attestation list does it.
func policySigner(p *client.Policy) string {
	if len(p.SignerIdentities) > 0 {
		return p.SignerIdentities[0]
	}
	if p.Signed {
		return labelUnverified
	}
	return labelUnsigned
}
