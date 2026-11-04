// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package policyfetch reads ampel policy documents from stash by locator, as
// a scheme fetcher for the policy compiler: it has the method set the
// compiler's SchemeFetcher asks for (Supports, Get, GetGroup) without
// importing the compiler, so a program that compiles policies registers a
// Fetcher and the compiler resolves stash locations like any other.
//
// A locator is
//
//	stash://<org>/policies/<namespace>[/<lineage>[@<version>]]
//
// The token resource form stash enforces, stash://<org>/policies/<namespace>,
// is its prefix, so a locator can stand as a resource restriction without
// translating. The lineage is required to fetch; "@<version>" pins a version
// and its absence reads the lineage's head. "_" names the default namespace.
// The server address and the bearer come from the client environment
// (STASH_URL, STASH_TOKEN or the credentials manager), never from the
// locator.
package policyfetch

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	stashclient "github.com/carabiner-dev/stash/pkg/client"
	stashconfig "github.com/carabiner-dev/stash/pkg/client/config"
)

// Scheme is the locator scheme this fetcher handles.
const Scheme = "stash"

const (
	prefix       = Scheme + "://"
	policiesPath = "policies"
)

// Locator is a parsed stash policy locator.
type Locator struct {
	Org       string
	Namespace string
	LineageID string
	// Version is nil for the lineage's head.
	Version *int64
}

// String renders the locator.
func (l Locator) String() string {
	ns := l.Namespace
	if ns == "" {
		ns = "_"
	}
	s := prefix + l.Org + "/" + policiesPath + "/" + ns
	if l.LineageID != "" {
		s += "/" + l.LineageID
	}
	if l.Version != nil {
		s += "@" + strconv.FormatInt(*l.Version, 10)
	}
	return s
}

// Ref is the locator as the stash client reads it.
func (l Locator) Ref() stashclient.PolicyRef {
	return stashclient.PolicyRef{OrgID: l.Org, Namespace: l.Namespace, LineageID: l.LineageID, Version: l.Version}
}

// Parse reads a locator; one without a lineage parses, so a resource
// restriction can be read, but Get refuses it.
func Parse(location string) (*Locator, error) {
	if !strings.HasPrefix(location, prefix) {
		return nil, fmt.Errorf("not a %s locator: %q", Scheme, location)
	}
	rest := strings.TrimPrefix(location, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || len(parts) > 4 || parts[0] == "" || parts[1] != policiesPath || parts[2] == "" {
		return nil, fmt.Errorf("malformed %s locator %q: want %s<org>/%s/<namespace>[/<lineage>[@<version>]]", Scheme, location, prefix, policiesPath)
	}
	l := &Locator{Org: parts[0], Namespace: parts[2]}
	if l.Namespace == "_" {
		l.Namespace = ""
	}
	if len(parts) == 4 {
		lineage, version, pinned := strings.Cut(parts[3], "@")
		if lineage == "" {
			return nil, fmt.Errorf("malformed %s locator %q: empty lineage", Scheme, location)
		}
		l.LineageID = lineage
		if pinned {
			v, err := strconv.ParseInt(version, 10, 64)
			if err != nil || v < 0 {
				return nil, fmt.Errorf("malformed %s locator %q: version %q is not a non-negative integer", Scheme, location, version)
			}
			l.Version = &v
		}
	}
	return l, nil
}

// Options configures the fetcher.
type Options struct {
	// URL is the stash service address and Token the bearer presented to
	// it. When neither is set both come from the stash client environment.
	URL   string
	Token string
	// Parallelism bounds how many documents a group fetch reads at once;
	// zero is the client's default.
	Parallelism int
	// Client overrides the constructed stash client (tests, callers that
	// manage their own connection).
	Client stashclient.StashClient
}

type optFn func(*Options)

// WithURL sets the stash service address.
func WithURL(url string) optFn { return func(o *Options) { o.URL = url } } //nolint:revive // the option type stays unexported, as the collectors do

// WithToken sets the bearer token presented to stash.
func WithToken(token string) optFn { return func(o *Options) { o.Token = token } } //nolint:revive // see WithURL

// WithParallelism bounds a group fetch.
func WithParallelism(n int) optFn { return func(o *Options) { o.Parallelism = n } } //nolint:revive // see WithURL

// WithClient sets a pre-built stash client, overriding URL and Token.
func WithClient(client stashclient.StashClient) optFn { //nolint:revive // see WithURL
	return func(o *Options) { o.Client = client }
}

// Fetcher reads policies from stash by locator.
type Fetcher struct {
	Options Options
	client  stashclient.StashClient
}

// New returns a fetcher. Without a client option the stash client is built
// from the URL and Token options, or from the environment when both are
// empty; the connection is made lazily, on the first fetch.
func New(funcs ...optFn) *Fetcher {
	opts := Options{}
	for _, fn := range funcs {
		fn(&opts)
	}
	return &Fetcher{Options: opts, client: opts.Client}
}

// Supports reports whether the location is a stash locator.
func (f *Fetcher) Supports(location string) bool {
	return strings.HasPrefix(location, prefix)
}

// Get fetches the stored document a locator names, verbatim: bare JSON, a
// DSSE envelope or a sigstore bundle, as it was pushed.
func (f *Fetcher) Get(ctx context.Context, location string) ([]byte, error) {
	docs, err := f.GetGroup(ctx, []string{location})
	if err != nil {
		return nil, err
	}
	return docs[0], nil
}

// GetGroup fetches the documents the locators name, in parallel, in the
// order given.
func (f *Fetcher) GetGroup(ctx context.Context, locations []string) ([][]byte, error) {
	refs := make([]stashclient.PolicyRef, 0, len(locations))
	for _, location := range locations {
		l, err := Parse(location)
		if err != nil {
			return nil, err
		}
		if l.LineageID == "" {
			return nil, fmt.Errorf("%s locator %q names no lineage to fetch", Scheme, location)
		}
		refs = append(refs, l.Ref())
	}
	client, err := f.stash()
	if err != nil {
		return nil, err
	}
	docs, err := client.GetPolicies(ctx, refs)
	if err != nil {
		return nil, fmt.Errorf("reading policies from stash: %w", err)
	}
	out := make([][]byte, len(docs))
	for i, doc := range docs {
		if len(doc.Raw) == 0 {
			return nil, fmt.Errorf("stash answered no document for %q", locations[i]) //nolint:gosec // docs has one entry per location
		}
		out[i] = doc.Raw
	}
	return out, nil
}

// stash returns the client, building it on first use.
func (f *Fetcher) stash() (stashclient.StashClient, error) {
	if f.client != nil {
		return f.client, nil
	}
	var client *stashclient.GRPCClient
	var err error
	if f.Options.URL == "" && f.Options.Token == "" {
		client, err = stashclient.NewGRPCClientFromEnv()
	} else {
		client, err = stashclient.NewGRPCClientFromConfig(&stashconfig.Config{BaseURL: f.Options.URL, Token: f.Options.Token})
	}
	if err != nil {
		return nil, fmt.Errorf("building the stash client: %w", err)
	}
	if client == nil {
		return nil, errors.New("building the stash client: no client")
	}
	client.Parallelism = f.Options.Parallelism
	f.client = client
	return client, nil
}
