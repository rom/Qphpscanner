package scanner

import (
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/qphpscanner/internal/pcap"
	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/webserver"
)

// auditSink is the optional audit trail: a libpcap capture of every exchange
// and/or a human-readable session log explaining each detection decision. It
// implements probe.Recorder so the Fetcher feeds it every request/response.
//
// It is nil when neither --pcap nor --log is requested, so callers must guard
// their use with a nil check; its exported methods are also safe to call on a
// nil receiver.
type auditSink struct {
	pcapFile *os.File
	logFile  *os.File

	pw      *pcap.Writer
	log     *sessionLog
	portSeq uint32 // atomic ephemeral client-port allocator
}

// newAuditSink opens the requested audit outputs. It returns (nil, nil) when
// neither is configured, so no recorder is attached to the Fetcher.
func newAuditSink(opts Options, specs []string, start time.Time) (*auditSink, error) {
	if opts.PCAPPath == "" && opts.LogPath == "" {
		return nil, nil
	}
	a := &auditSink{}
	if opts.PCAPPath != "" {
		fh, err := os.Create(opts.PCAPPath)
		if err != nil {
			return nil, fmt.Errorf("open pcap file: %w", err)
		}
		w, err := pcap.NewWriter(fh)
		if err != nil {
			_ = fh.Close()
			return nil, fmt.Errorf("write pcap header: %w", err)
		}
		a.pcapFile = fh
		a.pw = w
	}
	if opts.LogPath != "" {
		fh, err := os.Create(opts.LogPath)
		if err != nil {
			a.close()
			return nil, fmt.Errorf("open log file: %w", err)
		}
		a.logFile = fh
		a.log = &sessionLog{w: fh}
		a.log.header(opts, specs, start)
	}
	return a, nil
}

// Record receives one HTTP exchange from the Fetcher and fans it out to the
// enabled audit outputs. It is safe for concurrent use.
func (a *auditSink) Record(ex probe.Exchange) {
	if a == nil {
		return
	}
	if a.pw != nil {
		a.writeFlow(ex)
	}
	if a.log != nil {
		a.log.exchange(ex)
	}
}

// logService records the detection decision for one completed service.
func (a *auditSink) logService(res ServiceResult) {
	if a == nil || a.log == nil {
		return
	}
	a.log.service(res)
}

// logResumed notes a service whose result was restored from a checkpoint (and
// therefore produced no live exchanges this run).
func (a *auditSink) logResumed(res ServiceResult) {
	if a == nil || a.log == nil {
		return
	}
	a.log.resumed(res)
}

func (a *auditSink) writeFlow(ex probe.Exchange) {
	flow := pcap.HTTPFlow{
		Time:       ex.Time,
		ClientIP:   [4]byte{10, 0, 0, 1},
		ServerIP:   serverIP(ex.Host),
		ClientPort: a.nextPort(),
		ServerPort: clampPort(ex.Port),
		Request:    requestBytes(ex),
		Response:   responseBytes(ex),
	}
	// Best-effort: a write failure must not abort the scan.
	_ = a.pw.WriteHTTPFlow(flow)
}

// nextPort hands out a fresh ephemeral client port per flow so that concurrent
// conversations stay distinct in the capture.
func (a *auditSink) nextPort() uint16 {
	n := atomic.AddUint32(&a.portSeq, 1)
	return uint16(49152 + (n % 16000))
}

func (a *auditSink) close() error {
	if a == nil {
		return nil
	}
	var first error
	if a.pcapFile != nil {
		if err := a.pcapFile.Close(); err != nil && first == nil {
			first = err
		}
	}
	if a.logFile != nil {
		a.log.footer()
		if err := a.logFile.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// serverIP uses the real address when the host is an IPv4 literal; otherwise it
// synthesises a stable 10.x.y.z address so the capture stays valid (raw-IPv4
// link type) and each host maps consistently.
func serverIP(host string) [4]byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return [4]byte{v4[0], v4[1], v4[2], v4[3]}
		}
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	v := h.Sum32()
	last := byte(v)
	if last == 0 || last == 255 {
		last = 1
	}
	return [4]byte{10, byte(v >> 16), byte(v >> 8), last}
}

func clampPort(p int) uint16 {
	if p <= 0 || p > 65535 {
		return 80
	}
	return uint16(p)
}

// requestBytes reconstructs the wire form of the request line and headers.
func requestBytes(ex probe.Exchange) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", ex.Method, requestTarget(ex.URL))
	if ex.ReqHost != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", ex.ReqHost)
	}
	writeHeaders(&b, ex.ReqHeaders, map[string]bool{"Host": true})
	b.WriteString("\r\n")
	return []byte(b.String())
}

// responseBytes reconstructs the status line, headers and body. It returns nil
// when the exchange never produced a response (a connection-level error).
func responseBytes(ex probe.Exchange) []byte {
	if ex.Status == 0 {
		return nil
	}
	var b strings.Builder
	proto := ex.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	reason := http.StatusText(ex.Status)
	fmt.Fprintf(&b, "%s %d %s\r\n", proto, ex.Status, reason)
	writeHeaders(&b, ex.RespHeaders, nil)
	b.WriteString("\r\n")
	out := append([]byte(b.String()), ex.RespBody...)
	return out
}

// writeHeaders emits headers in sorted order for a deterministic capture,
// skipping any names in omit.
func writeHeaders(b *strings.Builder, h http.Header, omit map[string]bool) {
	if h == nil {
		return
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		if omit[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}

func requestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	t := u.EscapedPath()
	if t == "" {
		t = "/"
	}
	if u.RawQuery != "" {
		t += "?" + u.RawQuery
	}
	return t
}

// sessionLog writes the human-readable detection journal.
type sessionLog struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *sessionLog) header(opts Options, specs []string, start time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "qphpscanner session log\n")
	fmt.Fprintf(l.w, "started: %s\n", start.Format(time.RFC3339))
	fmt.Fprintf(l.w, "mode:    %s\n", opts.Mode)
	fmt.Fprintf(l.w, "targets: %s\n", strings.Join(specs, ", "))
	fmt.Fprintf(l.w, "ports:   %s\n", intsCSV(opts.Ports))
	fmt.Fprintf(l.w, "note:    all probing is passive; evidence is read-only fingerprinting.\n")
	fmt.Fprintf(l.w, "%s\n\n", strings.Repeat("=", 72))
}

func (l *sessionLog) footer() {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s\nsession finished: %s\n", strings.Repeat("=", 72), time.Now().Format(time.RFC3339))
}

// exchange logs one request/response as it happens.
func (l *sessionLog) exchange(ex probe.Exchange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	scheme := "http"
	if ex.TLS {
		scheme = "https/TLS"
	}
	ts := ex.Time.Format("15:04:05.000")
	fmt.Fprintf(l.w, "[%s] %s:%d  %s %s  (%s)\n", ts, ex.Host, ex.Port, ex.Method, ex.URL, scheme)
	if ex.Err != "" {
		fmt.Fprintf(l.w, "    -> transport error: %s\n", ex.Err)
		return
	}
	fmt.Fprintf(l.w, "    -> %d %s", ex.Status, http.StatusText(ex.Status))
	if n := len(ex.RespBody); n > 0 {
		fmt.Fprintf(l.w, "  (%d body byte(s))", n)
	}
	l.w.Write([]byte("\n"))
	for _, h := range auditResponseHeaders {
		if v := ex.RespHeaders.Get(h); v != "" {
			fmt.Fprintf(l.w, "       %s: %s\n", h, v)
		}
	}
}

var auditResponseHeaders = []string{"Server", "X-Powered-By", "X-Generator", "Via", "X-Cache", "Set-Cookie"}

// service logs the reasoning behind one service's verdict.
func (l *sessionLog) service(res ServiceResult) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprintf(l.w, "\n%s\nDECISION  %s:%d  %s\n%s\n", strings.Repeat("-", 72), res.Host, res.Port, res.URL, strings.Repeat("-", 72))
	if !res.PortOpen {
		fmt.Fprintf(l.w, "  port closed/filtered")
		if res.Error != "" {
			fmt.Fprintf(l.w, " (%s)", res.Error)
		}
		l.w.Write([]byte("\n"))
		return
	}
	if res.HTTP == nil {
		fmt.Fprintf(l.w, "  open port, no HTTP response")
		if res.Banner != "" {
			fmt.Fprintf(l.w, "; banner: %s", res.Banner)
		}
		if res.Error != "" {
			fmt.Fprintf(l.w, " (%s)", res.Error)
		}
		l.w.Write([]byte("\n"))
		return
	}

	if res.Server != nil && res.Server.Product != "" {
		v := res.Server.Product
		if res.Server.Version != "" {
			v += " " + res.Server.Version
		}
		fmt.Fprintf(l.w, "  web server: %s\n", v)
	}
	if res.Proxy != nil && res.Proxy.Present {
		fmt.Fprintf(l.w, "  reverse proxy: YES — origin reply is concealed%s\n", proxyDetail(res.Proxy))
	}

	det := res.PHP
	if det == nil {
		fmt.Fprintf(l.w, "  PHP verdict: not analysed\n")
		return
	}
	fmt.Fprintf(l.w, "  PHP verdict: %s (confidence %d/100)\n", strings.ToUpper(string(det.Verdict)), det.Confidence)
	if det.Version != "" {
		src := det.VersionSource
		if src != "" {
			src = " — learned via " + src
		}
		fmt.Fprintf(l.w, "  version: %s%s\n", det.Version, src)
	}
	if det.EOLDetail != "" {
		if det.EndOfLife {
			fmt.Fprintf(l.w, "  lifecycle: END OF LIFE — %s\n", det.EOLDetail)
		} else {
			fmt.Fprintf(l.w, "  lifecycle: %s\n", det.EOLDetail)
		}
	}

	if len(det.Evidence) == 0 {
		fmt.Fprintf(l.w, "  reasoning: no positive PHP evidence was observed.\n")
	} else {
		fmt.Fprintf(l.w, "  reasoning — %d evidence item(s), highest-weighted first:\n", len(det.Evidence))
		for _, ev := range det.Evidence {
			logEvidence(l.w, ev)
		}
	}

	if n := len(det.Vulnerabilities); n > 0 {
		fmt.Fprintf(l.w, "  version-correlated vulnerability leads: %d (informational; correlated from the detected version only)\n", n)
	}
}

func (l *sessionLog) resumed(res ServiceResult) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "\n[resumed from checkpoint] %s:%d  %s — no live probes this run\n", res.Host, res.Port, res.URL)
}

func logEvidence(w io.Writer, ev php.Evidence) {
	fmt.Fprintf(w, "    • [%s w%d] %s — %s\n", ev.Confidence, ev.Weight, ev.Signal, ev.Detail)
	where := ev.Where
	if where == "" {
		where = ev.Source
	}
	fmt.Fprintf(w, "        where: %s\n", where)
	if ev.How != "" {
		fmt.Fprintf(w, "        how:   %s\n", ev.How)
	}
	if ev.Probe != "" {
		fmt.Fprintf(w, "        probe: %s\n", ev.Probe)
	}
	if ev.Status > 0 {
		fmt.Fprintf(w, "        http status: %d\n", ev.Status)
	}
	if ev.Pattern != "" {
		fmt.Fprintf(w, "        matcher: %s\n", collapseSpace(ev.Pattern))
	}
	if ev.Line > 0 {
		fmt.Fprintf(w, "        body line: %d\n", ev.Line)
	}
	if ev.Snippet != "" {
		fmt.Fprintf(w, "        match: %s\n", collapseSpace(ev.Snippet))
	}
}

func proxyDetail(p *webserver.ProxyInfo) string {
	var parts []string
	if len(p.CDN) > 0 {
		parts = append(parts, "CDN "+strings.Join(p.CDN, "/"))
	}
	if len(p.WAF) > 0 {
		parts = append(parts, "WAF "+strings.Join(p.WAF, "/"))
	}
	if len(p.LoadBalancers) > 0 {
		parts = append(parts, "LB "+strings.Join(p.LoadBalancers, "/"))
	}
	if len(p.Caches) > 0 {
		parts = append(parts, "cache "+strings.Join(p.Caches, "/"))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func intsCSV(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ",")
}
