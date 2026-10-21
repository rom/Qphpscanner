// Package corpus records a sanitised fixture of the HTTP responses a scan
// collected for PHP detection, and loads them back, so a scan can be replayed
// through the detection pipeline offline (a regression harness that needs no
// live targets). It is a leaf package: it depends only on internal/probe and
// holds no detection logic of its own.
package corpus

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rom/qphpscanner/internal/probe"
)

// Schema is the identifier a corpus document declares.
const Schema = "qphpscanner-replay-corpus/1"

// redacted replaces a secret value that is dropped during sanitisation.
const redacted = "REDACTED"

// Cookie is a response cookie reduced to the fields detection cares about: the
// name is a strong signal (PHPSESSID, laravel_session, …); the value is a
// secret and is redacted on capture.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// Response is a serialisable, sanitised form of probe.Response. The body is a
// byte slice (base64 in JSON) so binary payloads — notably the favicon, whose
// mmh3 hash is part of fingerprinting — round-trip exactly.
type Response struct {
	RequestURL string              `json:"request_url,omitempty"`
	FinalURL   string              `json:"final_url,omitempty"`
	Status     int                 `json:"status,omitempty"`
	Proto      string              `json:"proto,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Cookies    []Cookie            `json:"cookies,omitempty"`
	Body       []byte              `json:"body,omitempty"`
	TLS        *probe.TLSInfo      `json:"tls,omitempty"`
	Hops       int                 `json:"hops,omitempty"`
	Err        string              `json:"error,omitempty"`
}

// Service is one scanned endpoint's captured detection inputs — the exact
// responses that were fed to php.Analyze, keyed as that Input holds them.
type Service struct {
	Target        string               `json:"target"`
	Deep          bool                 `json:"deep,omitempty"`
	Root          *Response            `json:"root,omitempty"`
	Extra         map[string]*Response `json:"extra,omitempty"`
	EasterCredits *Response            `json:"easter_credits,omitempty"`
	EasterLogo    *Response            `json:"easter_logo,omitempty"`
	Favicon       *Response            `json:"favicon,omitempty"`
	PathInfo      *Response            `json:"path_info,omitempty"`
	Control       *Response            `json:"control,omitempty"`
}

// Corpus is a saved set of per-service detection inputs plus provenance.
type Corpus struct {
	Schema   string    `json:"schema"`
	Tool     string    `json:"tool,omitempty"`
	Version  string    `json:"version,omitempty"`
	Created  time.Time `json:"created,omitempty"`
	Services []Service `json:"services"`
}

// Recorder collects per-service snapshots during a scan. It is safe for
// concurrent use: scan workers call Add from multiple goroutines. Snapshots are
// sanitised as they are added, so secrets never enter even the in-memory
// corpus.
type Recorder struct {
	mu       sync.Mutex
	services []Service
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder { return &Recorder{} }

// Add sanitises and stores one service snapshot.
func (r *Recorder) Add(s Service) {
	s.sanitize()
	r.mu.Lock()
	r.services = append(r.services, s)
	r.mu.Unlock()
}

// Corpus returns the recorded services as a Corpus, with the given tool
// provenance stamped in.
func (r *Recorder) Corpus(tool, version string) *Corpus {
	r.mu.Lock()
	defer r.mu.Unlock()
	svcs := make([]Service, len(r.services))
	copy(svcs, r.services)
	return &Corpus{
		Schema:   Schema,
		Tool:     tool,
		Version:  version,
		Created:  time.Now(),
		Services: svcs,
	}
}

// FromResponse converts a probe.Response into its serialisable form, copying
// slices so later mutation (e.g. sanitisation) cannot reach the original.
func FromResponse(r *probe.Response) *Response {
	if r == nil {
		return nil
	}
	out := &Response{
		RequestURL: r.RequestURL,
		FinalURL:   r.FinalURL,
		Status:     r.Status,
		Proto:      r.Proto,
		TLS:        r.TLS,
		Hops:       r.Hops,
		Err:        r.Err,
	}
	if len(r.Body) > 0 {
		out.Body = append([]byte(nil), r.Body...)
	}
	if len(r.Header) > 0 {
		out.Headers = make(map[string][]string, len(r.Header))
		for k, v := range r.Header {
			out.Headers[k] = append([]string(nil), v...)
		}
	}
	for _, c := range r.Cookies {
		if c == nil {
			continue
		}
		out.Cookies = append(out.Cookies, Cookie{Name: c.Name, Value: c.Value})
	}
	return out
}

// ToResponse rebuilds a probe.Response for replay through the detection
// pipeline.
func (r *Response) ToResponse() *probe.Response {
	if r == nil {
		return nil
	}
	out := &probe.Response{
		RequestURL: r.RequestURL,
		FinalURL:   r.FinalURL,
		Status:     r.Status,
		Proto:      r.Proto,
		TLS:        r.TLS,
		Hops:       r.Hops,
		Err:        r.Err,
	}
	if len(r.Body) > 0 {
		out.Body = append([]byte(nil), r.Body...)
	}
	if len(r.Headers) > 0 {
		out.Header = make(http.Header, len(r.Headers))
		for k, v := range r.Headers {
			out.Header[k] = append([]string(nil), v...)
		}
	}
	for _, c := range r.Cookies {
		out.Cookies = append(out.Cookies, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	return out
}

// sensitiveHeaders have their values redacted entirely on capture.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"x-auth-token":        true,
}

func (s *Service) sanitize() {
	sanitizeResponse(s.Root)
	sanitizeResponse(s.EasterCredits)
	sanitizeResponse(s.EasterLogo)
	sanitizeResponse(s.Favicon)
	sanitizeResponse(s.PathInfo)
	sanitizeResponse(s.Control)
	for _, r := range s.Extra {
		sanitizeResponse(r)
	}
}

// sanitizeResponse redacts secret-bearing header and cookie values in place,
// keeping the names and non-secret attributes that detection relies on. Bodies
// are left verbatim: they are the fingerprinting material, so a corpus should
// still be reviewed before it is shared.
func sanitizeResponse(r *Response) {
	if r == nil {
		return
	}
	for k, vals := range r.Headers {
		lk := strings.ToLower(k)
		switch {
		case sensitiveHeaders[lk]:
			for i := range vals {
				vals[i] = redacted
			}
		case lk == "set-cookie":
			for i := range vals {
				vals[i] = redactSetCookie(vals[i])
			}
		}
	}
	for i := range r.Cookies {
		if r.Cookies[i].Value != "" {
			r.Cookies[i].Value = redacted
		}
	}
}

// redactSetCookie blanks a Set-Cookie value while keeping the cookie name and
// its attributes: "SID=secret; Path=/; HttpOnly" → "SID=REDACTED; Path=/; HttpOnly".
func redactSetCookie(v string) string {
	nv, rest := v, ""
	if semi := strings.IndexByte(v, ';'); semi >= 0 {
		nv, rest = v[:semi], v[semi:]
	}
	if eq := strings.IndexByte(nv, '='); eq >= 0 {
		return nv[:eq+1] + redacted + rest
	}
	return v
}

// Write encodes a corpus as indented JSON.
func Write(w io.Writer, c *Corpus) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

// Load decodes a corpus and validates its schema (an empty schema is accepted
// for brevity; a non-empty one must match).
func Load(data []byte) (*Corpus, error) {
	var c Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Schema != "" && c.Schema != Schema {
		return nil, &schemaError{got: c.Schema}
	}
	return &c, nil
}

type schemaError struct{ got string }

func (e *schemaError) Error() string {
	return "unsupported replay corpus schema " + e.got + " (want " + Schema + ")"
}
