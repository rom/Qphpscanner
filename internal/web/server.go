// Package web provides the browser-based GUI: a small single-page frontend
// plus a JSON API that drives the same scanner the CLI uses.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rom/qphpscanner/internal/portspec"
	"github.com/rom/qphpscanner/internal/report"
	"github.com/rom/qphpscanner/internal/scanner"
)

//go:embed assets
var assets embed.FS

// historyItem is one retained scan result.
type historyItem struct {
	ID     string
	At     time.Time
	Result *scanner.ScanResult
}

// Server hosts the GUI and API. Recent scan results are retained in memory so
// report downloads and the history view do not require re-scanning.
type Server struct {
	addr       string
	maxTargets int
	histMax    int

	authUser string
	authPass string

	mu      sync.Mutex
	seq     int
	history []historyItem // newest first
}

// NewServer creates a Server bound to addr (e.g. "127.0.0.1:8088").
func NewServer(addr string) *Server {
	return &Server{addr: addr, maxTargets: 4096, histMax: 25}
}

// SetAuth enables HTTP Basic authentication for the whole server.
func (s *Server) SetAuth(user, pass string) {
	s.authUser, s.authPass = user, pass
}

// Handler returns the HTTP handler (useful for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	sub, _ := fs.Sub(assets, "assets")
	fileServer := http.FileServer(http.FS(sub))

	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("GET /api/download", s.handleDownload)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("GET /api/diff", s.handleDiff)
	mux.HandleFunc("POST /api/diff-upload", s.handleDiffUpload)
	mux.HandleFunc("GET /api/overview", s.handleOverview)
	// Any other /api/ request (wrong method, unknown path) gets a clean JSON
	// error instead of falling through to the file server, whose 404/405 for a
	// POST is opaque to the GUI.
	mux.HandleFunc("/api/", s.handleAPIFallback)
	mux.Handle("/", fileServer)
	// CORS/OPTIONS handling wraps auth so a browser preflight (which carries no
	// credentials) is answered before the auth check, letting the GUI work when
	// it is served through a reverse proxy or preview on a different origin.
	return s.corsMiddleware(s.authMiddleware(mux))
}

// corsMiddleware answers CORS preflight (OPTIONS) requests for the API and adds
// permissive CORS headers so the GUI works cross-origin (e.g. behind a preview
// proxy). It only touches /api/ paths; static assets are untouched.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if origin := r.Header.Get("Origin"); origin != "" {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleAPIFallback returns a clear JSON error for an API request that matched
// no specific route: a 405 (with Allow) when the path is known but the method
// is wrong, otherwise a 404.
func (s *Server) handleAPIFallback(w http.ResponseWriter, r *http.Request) {
	known := map[string]string{
		"/api/scan":     http.MethodPost,
		"/api/download": http.MethodGet,
		"/api/history":  http.MethodGet,
	}
	if want, ok := known[r.URL.Path]; ok {
		w.Header().Set("Allow", want+", OPTIONS")
		writeJSON(w, http.StatusMethodNotAllowed, streamMsg{Type: "error",
			Error: fmt.Sprintf("method %s not allowed on %s (use %s)", r.Method, r.URL.Path, want)})
		return
	}
	writeJSON(w, http.StatusNotFound, streamMsg{Type: "error",
		Error: "unknown API endpoint " + r.URL.Path})
}

// authMiddleware enforces Basic auth when credentials are configured.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authUser != "" || s.authPass != "" {
			u, p, ok := r.BasicAuth()
			if !ok || subtleEqual(u, s.authUser) == false || subtleEqual(p, s.authPass) == false {
				w.Header().Set("WWW-Authenticate", `Basic realm="qphpscanner"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) store(res *scanner.ScanResult) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := fmt.Sprintf("scan-%d", s.seq)
	s.history = append([]historyItem{{ID: id, At: time.Now(), Result: res}}, s.history...)
	if len(s.history) > s.histMax {
		s.history = s.history[:s.histMax]
	}
	return id
}

func (s *Server) lookup(id string) *scanner.ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		if len(s.history) > 0 {
			return s.history[0].Result
		}
		return nil
	}
	for _, h := range s.history {
		if h.ID == id {
			return h.Result
		}
	}
	return nil
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

type scanRequest struct {
	Targets         []string `json:"targets"`
	TargetsText     string   `json:"targets_text"`
	Ports           string   `json:"ports"`
	Mode            string   `json:"mode"`
	TLS             string   `json:"tls"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	Concurrency     int      `json:"concurrency"`
	Follow          bool     `json:"follow_redirects"`
	Insecure        bool     `json:"insecure"`
	SecurityTxt     bool     `json:"security_txt"`
	IncludeClosed   bool     `json:"include_closed"`
	NoDNSEnum       bool     `json:"no_dns_enum"`
	ResolveDNS      bool     `json:"resolve_dns"`
	Banners         bool     `json:"banners"`
	HostConcurrency int      `json:"host_concurrency"`
	Allow           []string `json:"allow"`
	Block           []string `json:"block"`
}

// streamMsg is one line of the NDJSON response stream.
type streamMsg struct {
	Type    string                 `json:"type"` // "progress" | "service" | "result" | "error"
	Event   *scanner.ProgressEvent `json:"event,omitempty"`
	Service *scanner.ServiceResult `json:"service,omitempty"`
	Result  *scanner.ScanResult    `json:"result,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// buildOptions turns a request into scanner options, or returns a user error.
func (s *Server) buildOptions(req scanRequest) (scanner.Options, []string, error) {
	targets := append([]string{}, req.Targets...)
	targets = append(targets, splitTargets(req.TargetsText)...)
	targets = cleanTargets(targets)
	if len(targets) == 0 {
		return scanner.Options{}, nil, fmt.Errorf("no targets supplied")
	}
	opts := scanner.Options{
		Mode:            normMode(req.Mode),
		TLSMode:         normTLS(req.TLS),
		Follow:          req.Follow,
		Insecure:        req.Insecure,
		SecurityTxt:     req.SecurityTxt,
		IncludeClosed:   req.IncludeClosed,
		Concurrency:     req.Concurrency,
		DisableDNSEnum:  req.NoDNSEnum,
		ResolveDNS:      req.ResolveDNS,
		GrabBanners:     req.Banners,
		HostConcurrency: req.HostConcurrency,
		Allowlist:       cleanTargets(req.Allow),
		Blocklist:       cleanTargets(req.Block),
		MaxHostsPerSpec: s.maxTargets,
	}
	if req.Ports != "" {
		ports, err := parsePortsField(req.Ports)
		if err != nil {
			return scanner.Options{}, nil, err
		}
		opts.Ports = ports
	}
	if req.TimeoutSeconds > 0 {
		opts.Timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	return opts, targets, nil
}

// handleScan runs a scan and streams NDJSON: a line per progress event
// followed by a final {"type":"result", ...} line (or {"type":"error"}).
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, streamMsg{Type: "error", Error: "invalid request: " + err.Error()})
		return
	}
	opts, targets, err := s.buildOptions(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, streamMsg{Type: "error", Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var writeMu sync.Mutex
	send := func(m streamMsg) {
		writeMu.Lock()
		_ = enc.Encode(m)
		if flusher != nil {
			flusher.Flush()
		}
		writeMu.Unlock()
	}

	opts.OnProgress = func(ev scanner.ProgressEvent) {
		e := ev
		send(streamMsg{Type: "progress", Event: &e})
	}
	// Stream every completed service so the GUI can render partial results that
	// survive a cancellation or timeout (nothing is wiped on error).
	opts.OnService = func(res scanner.ServiceResult) {
		r := res
		send(streamMsg{Type: "service", Service: &r})
	}

	// No artificial scan deadline: a long scan runs until it finishes or the
	// client disconnects/cancels (which cancels r.Context()). Individual
	// requests are still bounded by the per-probe timeout, and the Cancel
	// button aborts the stream. This avoids killing a legitimate long scan
	// with "context deadline exceeded".
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	result, err := scanner.Scan(ctx, targets, opts)
	if err != nil {
		send(streamMsg{Type: "error", Error: err.Error()})
		return
	}

	s.store(result)

	send(streamMsg{Type: "result", Result: result})
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	res := s.lookup(r.URL.Query().Get("scan"))
	if res == nil {
		http.Error(w, "no such scan (run one first)", http.StatusBadRequest)
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	var (
		ctype string
		ext   string
		isOut bool
	)
	switch format {
	case "json":
		ctype, ext, isOut = "application/json", "json", true
	case "xml":
		ctype, ext, isOut = "application/xml", "xml", true
	case "csv":
		ctype, ext, isOut = "text/csv; charset=utf-8", "csv", true
	case "sarif":
		ctype, ext, isOut = "application/sarif+json", "sarif", true
	case "text", "txt":
		ctype, ext, isOut = "text/plain; charset=utf-8", "txt", true
	case "rtf":
		ctype, ext = "application/rtf", "rtf"
	case "pdf":
		ctype, ext = "application/pdf", "pdf"
	case "html":
		ctype, ext = "text/html; charset=utf-8", "html"
	default:
		http.Error(w, "unknown format (want json, xml, csv, sarif, text, rtf, pdf or html)", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", downloadName(res, r.URL.Query().Get("scan"), ext, isOut)))

	var err error
	if isOut {
		err = report.WriteOutput(w, res, format)
	} else {
		err = report.WriteReport(w, res, format)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// downloadName builds a unique, timestamped filename for a downloaded scan:
// qphpscan-<YYYYMMDD-HHMMSS>[-<scan id>][-report].<ext>. The timestamp is the
// scan's finish time so every saved file is distinct and traceable to its run.
func downloadName(res *scanner.ScanResult, scanID, ext string, isOutput bool) string {
	ts := res.Meta.FinishedAt
	if ts.IsZero() {
		ts = res.Meta.StartedAt
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	name := "qphpscan-" + ts.Format("20060102-150405")
	if id := sanitiseID(scanID); id != "" {
		name += "-" + id
	}
	if !isOutput {
		name += "-report"
	}
	return name + "." + ext
}

// sanitiseID keeps a scan id safe for a filename (it comes from the query).
func sanitiseID(id string) string {
	id = strings.TrimSpace(id)
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= 40 {
			break
		}
	}
	return b.String()
}

// handleDiff compares two retained scans (by id; "" or "latest" = newest) and
// returns the structured difference.
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	ida := r.URL.Query().Get("a")
	idb := r.URL.Query().Get("b")
	a := s.lookup(latestID(ida))
	b := s.lookup(latestID(idb))
	if a == nil || b == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "both scans must exist (run or select two scans first)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"a":    scanMeta(a),
		"b":    scanMeta(b),
		"diff": report.Diff(a, b),
	})
}

// handleDiffUpload diffs an uploaded saved scan (JSON or XML) against a
// retained scan ("b" query param; "" or "latest" = newest). The uploaded file
// is the baseline (A).
func (s *Server) handleDiffUpload(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "read upload: " + err.Error()})
		return
	}
	a, err := report.LoadScanAny(data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	b := s.lookup(latestID(r.URL.Query().Get("b")))
	if b == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "no scan to compare against — run a scan first"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"a":    scanMeta(a),
		"b":    scanMeta(b),
		"diff": report.Diff(a, b),
	})
}

func latestID(id string) string {
	if id == "latest" {
		return ""
	}
	return id
}

func scanMeta(res *scanner.ScanResult) map[string]interface{} {
	return map[string]interface{}{
		"mode":        res.Meta.Mode,
		"finished_at": res.Meta.FinishedAt.Format(time.RFC3339),
		"hosts":       res.Summary.HostsScanned,
	}
}

// handleOverview returns aggregated statistics and clickable tag groups across
// all retained scans.
func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.computeOverview())
}

// handleHistory lists retained scans (newest first) with light summaries.
func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	items := make([]map[string]interface{}, 0, len(s.history))
	for _, h := range s.history {
		hosts := make([]string, 0, len(h.Result.Targets))
		for _, t := range h.Result.Targets {
			hosts = append(hosts, t.Host)
		}
		items = append(items, map[string]interface{}{
			"id": h.ID, "at": h.At.Format(time.RFC3339),
			"summary": h.Result.Summary, "hosts": hosts, "mode": h.Result.Meta.Mode,
		})
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{"scans": items})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func splitTargets(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
	return fields
}

func cleanTargets(in []string) []string {
	var out []string
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func normMode(m string) string {
	if strings.ToLower(m) == scanner.ModeDeep {
		return scanner.ModeDeep
	}
	return scanner.ModeDetect
}

func parsePortsField(s string) ([]int, error) {
	return portspec.Parse(s)
}

func normTLS(t string) string {
	switch strings.ToLower(t) {
	case scanner.TLSOn:
		return scanner.TLSOn
	case scanner.TLSOff:
		return scanner.TLSOff
	default:
		return scanner.TLSAuto
	}
}
