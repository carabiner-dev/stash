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
	listHeaderID        = "ID"
	listHeaderPredicate = "PREDICATE TYPE"
	listHeaderSigner    = "SIGNER IDENTITY"
	listHeaderSubject   = "SUBJECT"
	listHeaderVerified  = "V"
	listHeaderCreated   = "CREATED"

	// uuidWidth is the display width of an attestation UUID. The column is
	// pinned to it so an ID is never clipped: a partial UUID cannot be passed
	// back to `get` or `delete`.
	uuidWidth = 36

	// createdWidth fits both forms formatCreated emits (2006-01-02, 15:04:05).
	createdWidth = 10

	// The descriptive columns deliberately carry no min-width. termtable never
	// overflows the terminal: when the columns' floors do not fit the target it
	// shrinks every column proportionally to its claim, explicit widths
	// included (see distributeShrunkBudget in termtable's layout.go). A floor
	// here would therefore not push the table past the right edge, it would
	// just enlarge these columns' claim on a narrow terminal and take the space
	// out of the ID — clipping the UUID, which must stay copy-pasteable. Better
	// to let the descriptive columns absorb the squeeze.

	markVerified   = "✓"
	markUnverified = "✗"
)

// listBorderSet returns the border glyphs for the list table: horizontal runs
// render as ASCII '-' so the rule under the header reads as a plain underline,
// while verticals and junctions are spaces and never drawn — the table sets
// `border: none` and only the header opts back in via `border-bottom: solid`.
// Mirrors the bnd `ls` conventions.
func listBorderSet() termtable.BorderSet {
	b := termtable.BorderSet{
		Horizontal: '-',
		Vertical:   ' ',
	}
	for i := range b.Joins {
		b.Joins[i] = ' '
	}
	return b
}

// newListTable builds the borderless, full-width table used by `list`.
func newListTable() *termtable.Table {
	return termtable.NewTable(
		termtable.WithBorder(listBorderSet()),
		termtable.WithTargetWidthPercent(100),
		termtable.WithTableStyle("border: none"),
	)
}

// listRow is one rendered line. A single attestation expands to several rows
// when it carries multiple signers or subjects; only the first line repeats the
// columns that identify the attestation, so the eye groups them.
type listRow struct {
	id            string
	predicateType string
	identity      string
	subject       string
	verified      string
	created       string
}

// buildListRows flattens attestations into display rows. Extra signer
// identities and extra subjects each get their own line with the
// already-shown columns blank, following bnd's ls layout.
func buildListRows(atts []*client.Attestation, now time.Time) []listRow {
	var rows []listRow

	for _, att := range atts {
		if att == nil {
			continue
		}

		predType := att.PredicateType
		if predType == "" {
			predType = "[not defined]"
		}

		subjects := subjectSlugs(att)
		if len(subjects) == 0 {
			subjects = []string{""}
		}

		identities := att.SignerIdentities
		if len(identities) == 0 {
			identities = []string{"[unsigned]"}
		}

		for i, id := range identities {
			row := listRow{identity: id}
			if i == 0 {
				row.id = att.ID
				row.predicateType = predType
				row.subject = subjects[0]
				row.verified = verifiedMark(att)
				row.created = formatCreated(att.CreatedAt, now)
			}
			rows = append(rows, row)
		}
		for i := 1; i < len(subjects); i++ {
			rows = append(rows, listRow{subject: subjects[i]})
		}
	}

	return rows
}

// subjectSlugs returns a short identifier for each of an attestation's
// subjects, preferring "algo:value" and falling back to the subject name.
// Subjects with neither are skipped.
func subjectSlugs(att *client.Attestation) []string {
	slugs := make([]string, 0, len(att.Subjects))
	for _, s := range att.Subjects {
		slug := ""
		if s.DigestAlgorithm != "" && s.DigestValue != "" {
			slug = s.DigestAlgorithm + ":" + s.DigestValue
		}
		if slug == "" {
			slug = s.Name
		}
		if slug != "" {
			slugs = append(slugs, slug)
		}
	}
	return slugs
}

// verifiedMark renders the V column: whether the attestation's signature was
// verified when it was stored.
func verifiedMark(att *client.Attestation) string {
	if att.Validated {
		return markVerified
	}
	return markUnverified
}

// formatCreated renders a timestamp for the fixed-width CREATED column. Within
// the last 24 hours the date carries no information the reader doesn't already
// have, and the clock time is what tells recent entries apart, so show that;
// older entries show the date. Both forms fit createdWidth.
func formatCreated(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.Local()
	if d := now.Sub(t); d >= 0 && d < 24*time.Hour {
		return t.Format("15:04:05")
	}
	return t.Format("2006-01-02")
}

// printListTable renders the attestation table to w.
func printListTable(w io.Writer, atts []*client.Attestation, now time.Time) {
	t := newListTable()

	// The ID, V and CREATED columns are pinned to exactly what their contents
	// need; the three descriptive columns share the rest of the terminal and
	// clip with an ellipsis.
	//
	// Where each clips matters: predicate types are URLs that differ at the
	// END (every one starts "https://"), so they lose their head; signer
	// identities keep their "type::" prefix and tail, losing the middle; and
	// subject digests are "algo:value", where the head names the algorithm and
	// the tail is opaque hex, so they lose their tail.
	flex := func(trimPosition string) string {
		return fmt.Sprintf(
			"white-space: nowrap; text-overflow: ellipsis; text-overflow-position: %s; flex: 1",
			trimPosition,
		)
	}

	t.Column(0).Style(fmt.Sprintf("white-space: nowrap; width: %d", uuidWidth))
	t.Column(1).Style(flex("start"))
	t.Column(2).Style(flex("middle"))
	t.Column(3).Style(flex("end"))
	t.Column(4).Style("white-space: nowrap; width: 1")
	t.Column(5).Style(fmt.Sprintf("white-space: nowrap; width: %d", createdWidth))

	hdr := t.AddHeader(termtable.WithRowBorderBottom(termtable.BorderEdgeSolid))
	for _, title := range []string{
		listHeaderID, listHeaderPredicate, listHeaderSigner,
		listHeaderSubject, listHeaderVerified, listHeaderCreated,
	} {
		hdr.AddCell(termtable.WithContent(title))
	}

	for _, r := range buildListRows(atts, now) {
		row := t.AddRow()
		row.AddCell(termtable.WithContent(r.id))
		row.AddCell(termtable.WithContent(r.predicateType))
		row.AddCell(termtable.WithContent(r.identity))
		row.AddCell(termtable.WithContent(r.subject))
		row.AddCell(termtable.WithContent(r.verified))
		row.AddCell(termtable.WithContent(r.created))
	}

	_, _ = t.WriteTo(w) //nolint:errcheck // writing to terminal
}
