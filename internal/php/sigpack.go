package php

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// SignaturePackSchema is the schema identifier a signature pack must declare.
const SignaturePackSchema = "qphpscanner-signature-pack/1"

// Built-in pack identity. The built-ins are the default pack, recorded in scan
// provenance alongside any loaded packs so a diff can tell a signature-set
// change from a real site change.
const (
	BuiltinPackID      = "builtin"
	BuiltinPackVersion = "1"
)

// Pack bounds. Everything stays bounded: a pack cannot be huge, hold an
// unreasonable number of matchers, or carry a pathological body pattern. (Go's
// regexp is RE2, so matching is already linear-time with no backtracking; these
// caps bound compilation and input size on top of that.)
const (
	maxPackBytes      = 1 << 20 // 1 MiB of pack JSON
	maxPackSignatures = 1024    // total header+cookie+body matchers per pack
	maxPatternLen     = 512     // characters in a body regex source
)

// PackRef identifies a loaded signature pack for scan provenance (recorded in
// Meta.SignaturePacks).
type PackRef struct {
	ID      string `json:"id" xml:"id,attr"`
	Version string `json:"version" xml:"version,attr"`
	Sigs    int    `json:"signatures,omitempty" xml:"signatures,attr,omitempty"`
}

// SignatureSet is the active detection signature set: the built-in matchers,
// with any runtime signature packs merged on top. A nil *SignatureSet means
// "built-ins only"; use DefaultSignatureSet to obtain an explicit one.
type SignatureSet struct {
	headers []headerSig
	cookies []cookieSig
	body    []bodySig
	packs   []PackRef
}

// DefaultSignatureSet returns the built-in signature set as the default pack.
// The returned set may be extended with Merge without mutating the built-ins.
func DefaultSignatureSet() *SignatureSet {
	return &SignatureSet{
		headers: headerSigs,
		cookies: cookieSigs,
		body:    bodySigs,
		packs: []PackRef{{
			ID:      BuiltinPackID,
			Version: BuiltinPackVersion,
			Sigs:    len(headerSigs) + len(cookieSigs) + len(bodySigs),
		}},
	}
}

// Refs returns the active pack provenance (built-in first, then loaded packs).
func (s *SignatureSet) Refs() []PackRef {
	if s == nil {
		return DefaultSignatureSet().packs
	}
	return append([]PackRef(nil), s.packs...)
}

// Merge folds a loaded pack's matchers onto the set and records its provenance.
// It copies the underlying slices, so the built-in catalogues are never mutated.
func (s *SignatureSet) Merge(p *SignaturePack) {
	if p == nil {
		return
	}
	s.headers = append(append([]headerSig(nil), s.headers...), p.headers...)
	s.cookies = append(append([]cookieSig(nil), s.cookies...), p.cookies...)
	s.body = append(append([]bodySig(nil), s.body...), p.body...)
	s.packs = append(s.packs, PackRef{ID: p.ID, Version: p.Version, Sigs: p.Count()})
}

// headerSigs/cookieSigs/bodySigs accessors fall back to the built-ins for a nil
// set, so Analyze can treat nil as "defaults".
func (s *SignatureSet) headerSigs() []headerSig {
	if s == nil {
		return headerSigs
	}
	return s.headers
}

func (s *SignatureSet) cookieSigs() []cookieSig {
	if s == nil {
		return cookieSigs
	}
	return s.cookies
}

func (s *SignatureSet) bodySigs() []bodySig {
	if s == nil {
		return bodySigs
	}
	return s.body
}

// SignaturePack is a parsed, validated and compiled signature pack ready to be
// merged into a SignatureSet.
type SignaturePack struct {
	ID      string
	Version string
	headers []headerSig
	cookies []cookieSig
	body    []bodySig
}

// Count reports how many matchers the pack contributes.
func (p *SignaturePack) Count() int {
	return len(p.headers) + len(p.cookies) + len(p.body)
}

// packFile is the on-disk JSON schema (hand-rolled, stdlib-only).
type packFile struct {
	Schema  string          `json:"schema"`
	ID      string          `json:"id"`
	Version string          `json:"version"`
	Headers []packHeaderSig `json:"headers,omitempty"`
	Cookies []packCookieSig `json:"cookies,omitempty"`
	Body    []packBodySig   `json:"body,omitempty"`
}

type packHeaderSig struct {
	Header    string `json:"header"`
	Contains  string `json:"contains,omitempty"`
	Framework string `json:"framework,omitempty"`
	Variant   string `json:"variant,omitempty"`
	PHP       bool   `json:"php,omitempty"`
	Weight    int    `json:"weight"`
	Detail    string `json:"detail,omitempty"`
}

type packCookieSig struct {
	Name      string `json:"name"`
	Match     string `json:"match,omitempty"` // "exact" (default) or "prefix"
	Framework string `json:"framework,omitempty"`
	Weight    int    `json:"weight"`
	Detail    string `json:"detail,omitempty"`
}

type packBodySig struct {
	ID        string `json:"id"`
	Pattern   string `json:"pattern"`
	Framework string `json:"framework,omitempty"`
	PHP       bool   `json:"php,omitempty"`
	Weight    int    `json:"weight"`
	Detail    string `json:"detail,omitempty"`
}

// ParseSignaturePack decodes, validates and compiles a signature pack. It
// rejects an unknown schema, a missing id/version, an over-large pack, too many
// matchers, and an invalid or over-long body pattern — each with a clear error.
func ParseSignaturePack(data []byte) (*SignaturePack, error) {
	if len(data) > maxPackBytes {
		return nil, fmt.Errorf("signature pack too large (%d bytes, max %d)", len(data), maxPackBytes)
	}
	var pf packFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return nil, fmt.Errorf("parse signature pack: %w", err)
	}
	if pf.Schema != SignaturePackSchema {
		return nil, fmt.Errorf("unsupported signature pack schema %q (want %q)", pf.Schema, SignaturePackSchema)
	}
	if strings.TrimSpace(pf.ID) == "" || strings.TrimSpace(pf.Version) == "" {
		return nil, fmt.Errorf("signature pack must declare a non-empty id and version")
	}
	total := len(pf.Headers) + len(pf.Cookies) + len(pf.Body)
	if total == 0 {
		return nil, fmt.Errorf("signature pack %q is empty (no header/cookie/body matchers)", pf.ID)
	}
	if total > maxPackSignatures {
		return nil, fmt.Errorf("signature pack %q has too many matchers (%d, max %d)", pf.ID, total, maxPackSignatures)
	}

	p := &SignaturePack{ID: strings.TrimSpace(pf.ID), Version: strings.TrimSpace(pf.Version)}
	for i, h := range pf.Headers {
		if strings.TrimSpace(h.Header) == "" {
			return nil, fmt.Errorf("signature pack %q: headers[%d] missing a header name", p.ID, i)
		}
		if err := checkWeight(h.Weight); err != nil {
			return nil, fmt.Errorf("signature pack %q: headers[%d] (%s): %w", p.ID, i, h.Header, err)
		}
		p.headers = append(p.headers, headerSig{
			header: h.Header, contains: h.Contains, framework: h.Framework,
			phpImplied: h.PHP, variant: h.Variant, weight: h.Weight, detail: h.Detail,
		})
	}
	for i, c := range pf.Cookies {
		if strings.TrimSpace(c.Name) == "" {
			return nil, fmt.Errorf("signature pack %q: cookies[%d] missing a cookie name", p.ID, i)
		}
		kind, err := cookieKind(c.Match)
		if err != nil {
			return nil, fmt.Errorf("signature pack %q: cookies[%d] (%s): %w", p.ID, i, c.Name, err)
		}
		if err := checkWeight(c.Weight); err != nil {
			return nil, fmt.Errorf("signature pack %q: cookies[%d] (%s): %w", p.ID, i, c.Name, err)
		}
		p.cookies = append(p.cookies, cookieSig{
			name: c.Name, kind: kind, framework: c.Framework, weight: c.Weight, detail: c.Detail,
		})
	}
	for i, b := range pf.Body {
		if strings.TrimSpace(b.ID) == "" {
			return nil, fmt.Errorf("signature pack %q: body[%d] missing an id", p.ID, i)
		}
		re, err := compilePackPattern(b.Pattern)
		if err != nil {
			return nil, fmt.Errorf("signature pack %q: body[%d] (%s): %w", p.ID, i, b.ID, err)
		}
		if err := checkWeight(b.Weight); err != nil {
			return nil, fmt.Errorf("signature pack %q: body[%d] (%s): %w", p.ID, i, b.ID, err)
		}
		p.body = append(p.body, bodySig{
			id: b.ID, re: re, framework: b.Framework, phpImplied: b.PHP, weight: b.Weight, detail: b.Detail,
		})
	}
	return p, nil
}

func checkWeight(w int) error {
	if w < 0 || w > 100 {
		return fmt.Errorf("weight %d out of range (0–100)", w)
	}
	return nil
}

func cookieKind(match string) (matchKind, error) {
	switch strings.ToLower(strings.TrimSpace(match)) {
	case "", "exact":
		return matchExact, nil
	case "prefix":
		return matchPrefix, nil
	default:
		return matchExact, fmt.Errorf("unknown cookie match %q (want exact or prefix)", match)
	}
}

// compilePackPattern compiles a body pattern safely: it bounds the source
// length and rejects anything that does not compile, with a clear error.
func compilePackPattern(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, fmt.Errorf("empty body pattern")
	}
	if len(pattern) > maxPatternLen {
		return nil, fmt.Errorf("body pattern too long (%d chars, max %d)", len(pattern), maxPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid body pattern: %w", err)
	}
	return re, nil
}

// LoadSignaturePack reads a signature pack from a local file path or an
// http(s) URL and parses it. Reads are bounded to maxPackBytes.
func LoadSignaturePack(ctx context.Context, src string, client *http.Client) (*SignaturePack, error) {
	data, err := loadBounded(ctx, src, client, maxPackBytes)
	if err != nil {
		return nil, err
	}
	return ParseSignaturePack(data)
}

// loadBounded reads at most max+1 bytes from a file or URL and errors if the
// source exceeds max.
func loadBounded(ctx context.Context, src string, client *http.Client, max int64) ([]byte, error) {
	var r io.ReadCloser
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch signature pack: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("fetch signature pack: HTTP %d", resp.StatusCode)
		}
		r = resp.Body
	} else {
		fh, err := os.Open(src)
		if err != nil {
			return nil, fmt.Errorf("read signature pack: %w", err)
		}
		r = fh
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("signature pack too large (max %d bytes)", max)
	}
	return data, nil
}
