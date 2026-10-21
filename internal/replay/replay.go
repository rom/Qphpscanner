// Package replay records the sanitized HTTP exchanges of a scan to a corpus and
// replays a corpus through the detection pipeline with no network. The corpus
// is a regression harness: new signatures (and detection changes generally) can
// be validated against real captured responses — static copies, generic login
// pages, WAF challenges and soft-404s — entirely offline.
//
// Recording is aggressively sanitised: Set-Cookie values and secret-shaped body
// values are redacted, keeping only what detection needs (cookie names, header
// substrings, body markers). Everything is bounded: the body kept per exchange
// and the number of exchanges are both capped.
package replay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
)

// CorpusSchema is the schema identifier a corpus declares.
const CorpusSchema = "qphpscanner-corpus/1"

// Bounds: the corpus stays small and predictable.
const (
	maxCorpusBodyBytes = 64 << 10 // bytes of body kept per exchange
	maxCorpusExchanges = 1024     // exchanges kept per corpus
	maxCorpusBytes     = 96 << 20 // bytes accepted when loading a corpus file
	redacted           = "[REDACTED]"
)

// Exchange is one sanitized request/response captured for replay.
type Exchange struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Status  int                 `json:"status,omitempty"`
	Proto   string              `json:"proto,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"` // response headers (Set-Cookie values dropped)
	Body    string              `json:"body,omitempty"`    // sanitized, bounded
	Err     string              `json:"error,omitempty"`
}

// Corpus is a recorded set of sanitized exchanges.
type Corpus struct {
	Schema    string     `json:"schema"`
	Recorded  string     `json:"recorded,omitempty"`
	Truncated bool       `json:"truncated,omitempty"`
	Exchanges []Exchange `json:"exchanges"`
}

// Recorder implements probe.Recorder, collecting sanitized exchanges in memory
// (bounded) for a scan. It is safe for concurrent use.
type Recorder struct {
	mu        sync.Mutex
	exchanges []Exchange
	truncated bool
}

// NewRecorder returns an empty corpus recorder.
func NewRecorder() *Recorder { return &Recorder{} }

// Record sanitises and stores one exchange, up to the per-corpus cap.
func (r *Recorder) Record(ex probe.Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.exchanges) >= maxCorpusExchanges {
		r.truncated = true
		return
	}
	r.exchanges = append(r.exchanges, sanitize(ex))
}

// Corpus returns a snapshot of what has been recorded so far.
func (r *Recorder) Corpus() *Corpus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &Corpus{
		Schema:    CorpusSchema,
		Recorded:  time.Now().UTC().Format(time.RFC3339),
		Truncated: r.truncated,
		Exchanges: append([]Exchange(nil), r.exchanges...),
	}
}

// WriteFile writes the corpus as indented JSON to path.
func (r *Recorder) WriteFile(path string) error {
	data, err := json.MarshalIndent(r.Corpus(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// --- Sanitisation ---------------------------------------------------------

var (
	// Secret-shaped assignments in env-style bodies: keep the key and "=", drop
	// the value. Matches KEY names that contain a secret-ish word.
	reEnvSecret = regexp.MustCompile(`(?im)^([ \t]*[A-Za-z0-9_]*(?:KEY|SECRET|PASSWORD|PASSWD|PASS|PWD|TOKEN|DSN|CREDENTIAL|PRIVATE)[A-Za-z0-9_]*[ \t]*=)[ \t]*\S.*$`)
	// Secret-shaped JSON string values: keep the key, drop the value.
	reJSONSecret = regexp.MustCompile(`(?i)("[a-z0-9_]*(?:key|secret|password|passwd|pass|pwd|token|dsn|credential|private)[a-z0-9_]*"[ \t]*:[ \t]*")[^"]*(")`)
)

// sanitize converts a live exchange into a corpus record, dropping secrets while
// keeping what detection relies on.
func sanitize(ex probe.Exchange) Exchange {
	out := Exchange{
		Method: ex.Method,
		URL:    ex.URL,
		Status: ex.Status,
		Proto:  ex.Proto,
		Err:    ex.Err,
	}
	if len(ex.RespHeaders) > 0 {
		out.Headers = sanitizeHeaders(ex.RespHeaders)
	}
	if len(ex.RespBody) > 0 {
		body := ex.RespBody
		if len(body) > maxCorpusBodyBytes {
			body = body[:maxCorpusBodyBytes]
		}
		out.Body = sanitizeBody(string(body))
	}
	return out
}

// sanitizeHeaders copies response headers, dropping Set-Cookie values (keeping
// the cookie name and attributes) and any secret-bearing header entirely.
func sanitizeHeaders(h http.Header) map[string][]string {
	out := map[string][]string{}
	for k, vs := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "Proxy-Authorization", "Www-Authenticate", "Proxy-Authenticate":
			// Credential / challenge headers: keep only the scheme token.
			out[k] = scheme(vs)
			continue
		case "Set-Cookie":
			cv := make([]string, 0, len(vs))
			for _, v := range vs {
				cv = append(cv, sanitizeSetCookie(v))
			}
			out[k] = cv
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func scheme(vs []string) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if i := strings.IndexByte(v, ' '); i > 0 {
			out = append(out, v[:i]+" "+redacted)
		} else {
			out = append(out, redacted)
		}
	}
	return out
}

// sanitizeSetCookie drops a cookie's value but keeps its name and attributes,
// so cookie-name detection and header-substring matches still work.
func sanitizeSetCookie(v string) string {
	rest := ""
	first := v
	if semi := strings.IndexByte(v, ';'); semi >= 0 {
		first, rest = v[:semi], v[semi:]
	}
	eq := strings.IndexByte(first, '=')
	if eq < 0 {
		return v // no value present
	}
	return first[:eq] + "=" + rest
}

// sanitizeBody redacts secret-shaped values in env- and JSON-style bodies while
// preserving the surrounding keys and markers detection looks for.
func sanitizeBody(body string) string {
	body = reEnvSecret.ReplaceAllString(body, "${1}"+redacted)
	body = reJSONSecret.ReplaceAllString(body, "${1}"+redacted+"${2}")
	return body
}

// --- Loading --------------------------------------------------------------

// Parse decodes and validates a corpus from JSON.
func Parse(data []byte) (*Corpus, error) {
	if len(data) > maxCorpusBytes {
		return nil, fmt.Errorf("corpus too large (%d bytes, max %d)", len(data), maxCorpusBytes)
	}
	var c Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse corpus: %w", err)
	}
	if c.Schema != CorpusSchema {
		return nil, fmt.Errorf("unsupported corpus schema %q (want %q)", c.Schema, CorpusSchema)
	}
	return &c, nil
}

// Load reads and parses a corpus from a local file.
func Load(path string) (*Corpus, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	if info.Size() > maxCorpusBytes {
		return nil, fmt.Errorf("corpus too large (%d bytes, max %d)", info.Size(), maxCorpusBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	return Parse(data)
}

// --- Replay ---------------------------------------------------------------

// Options configures a replay through the detection pipeline.
type Options struct {
	// Signatures is the active detection signature set (nil = built-ins). Pass a
	// set with a loaded pack to validate new signatures against the corpus.
	Signatures *php.SignatureSet
	// Catalog supplies vulnerability/EOL data (nil = built-in default).
	Catalog *php.Catalog
}

// Result is the detection outcome for one origin in the corpus.
type Result struct {
	Origin    string
	TargetURL string
	Status    int
	Detection *php.Detection
}

// Replay groups the corpus exchanges by origin, reconstructs each origin's
// detection Input from the captured responses and runs the detection pipeline
// with no network. Origins are returned in a stable (sorted) order.
func Replay(c *Corpus, opts Options) []Result {
	if c == nil {
		return nil
	}
	type origin struct {
		url     string
		byURL   map[string]*probe.Response
		ordered []string
	}
	origins := map[string]*origin{}
	var order []string
	for _, e := range c.Exchanges {
		o := originOf(e.URL)
		if o == "" {
			continue
		}
		grp, ok := origins[o]
		if !ok {
			grp = &origin{url: o, byURL: map[string]*probe.Response{}}
			origins[o] = grp
			order = append(order, o)
		}
		// Only GET responses feed the detection pipeline (an OPTIONS probe has no
		// body to analyse). The first response seen for a URL wins.
		if !strings.EqualFold(e.Method, http.MethodGet) {
			continue
		}
		if _, dup := grp.byURL[e.URL]; dup {
			continue
		}
		grp.byURL[e.URL] = toResponse(e)
		grp.ordered = append(grp.ordered, e.URL)
	}

	sortStrings(order)
	var out []Result
	for _, o := range order {
		grp := origins[o]
		in := buildInput(o, grp.byURL, opts)
		if in.Root == nil {
			continue
		}
		res := Result{Origin: o, TargetURL: in.TargetURL, Detection: php.Analyze(in)}
		res.Status = in.Root.Status
		out = append(out, res)
	}
	return out
}

// buildInput reconstructs a php.Input for one origin, assigning the special
// probe URLs to their Input fields and everything else to the deep-probe Extra
// map — mirroring how the scanner assembles detection input.
func buildInput(origin string, byURL map[string]*probe.Response, opts Options) php.Input {
	in := php.Input{
		Deep:       true,
		Catalog:    opts.Catalog,
		Signatures: opts.Signatures,
		Extra:      map[string]*probe.Response{},
	}
	rootURL := origin + "/"
	control := origin + php.ControlProbePath
	credits := origin + "/" + php.EasterEggCredits
	logo := origin + "/" + php.EasterEggLogo
	favicon := origin + php.FaviconPath
	pathInfo := origin + php.PathInfoProbe

	for u, resp := range byURL {
		switch u {
		case rootURL:
			in.Root = resp
			in.TargetURL = u
		case control:
			in.Control = resp
			in.Extra[u] = resp
		case credits:
			in.EasterCredits = resp
		case logo:
			in.EasterLogo = resp
		case favicon:
			in.Favicon = resp
		case pathInfo:
			in.PathInfo = resp
		default:
			in.Extra[u] = resp
		}
	}
	if in.TargetURL == "" {
		in.TargetURL = rootURL
	}
	return in
}

// toResponse rebuilds a probe.Response (including parsed cookies) from a
// sanitized corpus record.
func toResponse(e Exchange) *probe.Response {
	h := http.Header{}
	for k, vs := range e.Headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	r := &probe.Response{
		RequestURL: e.URL,
		FinalURL:   e.URL,
		Status:     e.Status,
		Proto:      e.Proto,
		Header:     h,
		Body:       []byte(e.Body),
		Err:        e.Err,
	}
	r.Cookies = (&http.Response{Header: h}).Cookies()
	return r
}

// originOf returns scheme://host[:port] for a URL, or "" when it cannot be
// parsed.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// sortStrings sorts in place (small helper to avoid importing sort for one use).
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
