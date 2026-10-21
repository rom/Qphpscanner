package php

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SignaturePackSchema is the identifier an external signature pack must declare
// (an empty schema is accepted for brevity, but a non-empty one must match).
const SignaturePackSchema = "qphpscanner-signature-pack/1"

// Bounds that keep a pack inert-on-error: a malformed, oversized or
// unparseable pack is rejected outright rather than silently truncated or
// allowed to inflate detection. Go's regexp engine is RE2 (linear time, no
// catastrophic backtracking), so the length cap is about program size and
// memory, not a ReDoS guard.
const (
	maxPackEntries = 500     // per matcher category (headers / cookies / bodies)
	maxRegexLen    = 512     // bytes of a body-matcher regular expression
	maxPackBytes   = 8 << 20 // 8 MiB fetched/read ceiling
)

// PackHeaderSig is a response-header matcher contributed by a signature pack.
type PackHeaderSig struct {
	Header    string `json:"header"`
	Contains  string `json:"contains,omitempty"` // case-insensitive substring; "" = present at all
	Framework string `json:"framework,omitempty"`
	PHP       bool   `json:"php,omitempty"`     // a match is (also) evidence of PHP
	Variant   string `json:"variant,omitempty"` // runtime variant (PHP, HHVM, ...)
	Weight    int    `json:"weight"`
	Detail    string `json:"detail,omitempty"`
}

// PackCookieSig is a cookie-name matcher contributed by a signature pack.
type PackCookieSig struct {
	Name      string `json:"name"`
	Match     string `json:"match,omitempty"` // "exact" (default) or "prefix"
	Framework string `json:"framework,omitempty"`
	Weight    int    `json:"weight"`
	Detail    string `json:"detail,omitempty"`
}

// PackBodySig is a response-body regular-expression matcher contributed by a
// signature pack.
type PackBodySig struct {
	ID        string `json:"id"`
	Regex     string `json:"regex"`
	Framework string `json:"framework,omitempty"`
	PHP       bool   `json:"php,omitempty"`
	Weight    int    `json:"weight"`
	Detail    string `json:"detail,omitempty"`
}

// SignaturePack is the JSON shape of an external, versioned detection-signature
// pack. Its header, cookie and body matchers are consumed by the detection
// pipeline exactly like the built-in catalogues once registered.
type SignaturePack struct {
	Schema  string          `json:"schema,omitempty"`
	ID      string          `json:"id"`
	Version string          `json:"version,omitempty"`
	Headers []PackHeaderSig `json:"headers,omitempty"`
	Cookies []PackCookieSig `json:"cookies,omitempty"`
	Bodies  []PackBodySig   `json:"bodies,omitempty"`
}

var (
	packMu      sync.Mutex
	activePacks []string // "id" or "id@version" of each registered pack, in order
)

// SignaturePacks returns the identifiers of the signature packs registered so
// far ("id", or "id@version" when a version is declared), in registration
// order. Used to stamp scan provenance.
func SignaturePacks() []string {
	packMu.Lock()
	defer packMu.Unlock()
	if len(activePacks) == 0 {
		return nil
	}
	out := make([]string, len(activePacks))
	copy(out, activePacks)
	return out
}

// clampWeight bounds a pack-supplied weight so no single pack entry can swamp
// the evidence score.
func clampWeight(w int) int {
	switch {
	case w < 0:
		return 0
	case w > 100:
		return 100
	default:
		return w
	}
}

// build validates the pack and returns the internal matcher forms. It is the
// single source of validation truth, used both by ParseSignaturePack (to
// reject a bad pack) and RegisterSignaturePack (to merge a good one).
func (p *SignaturePack) build() (hdr []headerSig, cke []cookieSig, bdy []bodySig, err error) {
	if strings.TrimSpace(p.ID) == "" {
		return nil, nil, nil, &packError{msg: `missing "id"`}
	}
	if len(p.Headers) > maxPackEntries || len(p.Cookies) > maxPackEntries || len(p.Bodies) > maxPackEntries {
		return nil, nil, nil, &packError{msg: "too many entries (max " + strconv.Itoa(maxPackEntries) + " per category)"}
	}
	for _, h := range p.Headers {
		if strings.TrimSpace(h.Header) == "" {
			return nil, nil, nil, &packError{msg: `header matcher with empty "header"`}
		}
		hdr = append(hdr, headerSig{
			header:     h.Header,
			contains:   h.Contains,
			framework:  h.Framework,
			phpImplied: h.PHP,
			variant:    h.Variant,
			weight:     clampWeight(h.Weight),
			detail:     h.Detail,
		})
	}
	for _, c := range p.Cookies {
		if strings.TrimSpace(c.Name) == "" {
			return nil, nil, nil, &packError{msg: `cookie matcher with empty "name"`}
		}
		var kind matchKind
		switch strings.ToLower(strings.TrimSpace(c.Match)) {
		case "", "exact":
			kind = matchExact
		case "prefix":
			kind = matchPrefix
		default:
			return nil, nil, nil, &packError{msg: `cookie "match" must be "exact" or "prefix", got ` + strconv.Quote(c.Match)}
		}
		cke = append(cke, cookieSig{
			name:      c.Name,
			kind:      kind,
			framework: c.Framework,
			weight:    clampWeight(c.Weight),
			detail:    c.Detail,
		})
	}
	for _, b := range p.Bodies {
		if strings.TrimSpace(b.ID) == "" {
			return nil, nil, nil, &packError{msg: `body matcher with empty "id"`}
		}
		if b.Regex == "" {
			return nil, nil, nil, &packError{msg: "body matcher " + strconv.Quote(b.ID) + ` with empty "regex"`}
		}
		if len(b.Regex) > maxRegexLen {
			return nil, nil, nil, &packError{msg: "body matcher " + strconv.Quote(b.ID) + " regex exceeds " + strconv.Itoa(maxRegexLen) + " bytes"}
		}
		re, cerr := regexp.Compile(b.Regex)
		if cerr != nil {
			return nil, nil, nil, &packError{msg: "body matcher " + strconv.Quote(b.ID) + " regex: " + cerr.Error()}
		}
		bdy = append(bdy, bodySig{
			id:         b.ID,
			re:         re,
			framework:  b.Framework,
			phpImplied: b.PHP,
			weight:     clampWeight(b.Weight),
			detail:     b.Detail,
		})
	}
	return hdr, cke, bdy, nil
}

// ParseSignaturePack decodes a signature pack and validates it fully (schema,
// id, bounds, cookie match kinds and body regular expressions). A pack that
// fails any check is rejected with an error.
func ParseSignaturePack(data []byte) (*SignaturePack, error) {
	var p SignaturePack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Schema != "" && p.Schema != SignaturePackSchema {
		return nil, &schemaError{got: p.Schema, want: SignaturePackSchema}
	}
	if _, _, _, err := p.build(); err != nil {
		return nil, err
	}
	return &p, nil
}

// RegisterSignaturePack validates a pack and merges its matchers into the
// active detection catalogues. Like RegisterFavicons it must be called before a
// scan starts; it is not safe to call concurrently with an in-flight Analyze.
// The pack's "id@version" is recorded for scan provenance.
func RegisterSignaturePack(p *SignaturePack) error {
	hdr, cke, bdy, err := p.build()
	if err != nil {
		return err
	}
	headerSigs = append(headerSigs, hdr...)
	cookieSigs = append(cookieSigs, cke...)
	bodySigs = append(bodySigs, bdy...)
	packMu.Lock()
	activePacks = append(activePacks, packLabel(p))
	packMu.Unlock()
	return nil
}

func packLabel(p *SignaturePack) string {
	if strings.TrimSpace(p.Version) != "" {
		return p.ID + "@" + p.Version
	}
	return p.ID
}

// LoadSignaturePack reads a signature pack from a local file or http(s) URL and
// registers it. It returns the number of matchers (headers+cookies+bodies)
// added.
func LoadSignaturePack(ctx context.Context, src string, client *http.Client) (int, error) {
	var data []byte
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if rerr != nil {
			return 0, rerr
		}
		resp, derr := client.Do(req)
		if derr != nil {
			return 0, derr
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, &packError{msg: "fetch: HTTP " + strconv.Itoa(resp.StatusCode)}
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, maxPackBytes))
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return 0, err
	}
	p, err := ParseSignaturePack(data)
	if err != nil {
		return 0, err
	}
	if err := RegisterSignaturePack(p); err != nil {
		return 0, err
	}
	return len(p.Headers) + len(p.Cookies) + len(p.Bodies), nil
}

type packError struct{ msg string }

func (e *packError) Error() string { return "invalid signature pack: " + e.msg }
