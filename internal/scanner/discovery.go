package scanner

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
)

// maxRetryAfter caps how long a server's Retry-After we take notice of: a huge
// value must not be recorded verbatim. Adaptive discovery does not sleep; it
// simply stops issuing optional probes when asked to back off, so this is only
// the clamp applied to the recorded back-off hint.
const maxRetryAfter = 30 * time.Second

// discovery drives adaptive, budgeted deep-mode probing for one service.
//
// It counts every fetch against an optional per-service request budget and,
// once the budget is spent, stops issuing *optional* probes (essential ones —
// the OPTIONS request and the soft-404 control — still run). It also honours a
// server Retry-After: a 429/503 short-circuits the remaining optional probes
// for that service rather than retrying blindly. Whether the optional schedule
// was cut short is recorded so the diff's coverage states can reflect it.
//
// Adaptive discovery only ever reduces or reorders requests; it never adds an
// intrusive one. A discovery is used by a single scanService goroutine and is
// not safe for concurrent use.
type discovery struct {
	fetcher *probe.Fetcher
	ctx     context.Context

	limit     int    // configured budget (0 = unlimited)
	remaining int    // fetches left before optional probes stop
	issued    int    // probes actually issued (every fetch is counted)
	skipOpt   bool   // once set, no further optional probes are issued
	limited   string // "" | "budget" | "retry-after"
	retryWait time.Duration
}

// newDiscovery builds a discovery with the given per-service budget (0 =
// unlimited).
func newDiscovery(ctx context.Context, f *probe.Fetcher, budget int) *discovery {
	return &discovery{fetcher: f, ctx: ctx, limit: budget, remaining: budget}
}

// get issues an essential probe (always fetched, always counted).
func (d *discovery) get(url string) *probe.Response {
	return d.countedFetch(http.MethodGet, url)
}

// request issues an essential probe with a custom method.
func (d *discovery) request(method, url string) *probe.Response {
	return d.countedFetch(method, url)
}

// optional issues an optional probe, or returns nil when the per-service budget
// is spent or a back-off has been requested. A nil result means "not fetched"
// and callers must treat it as such.
func (d *discovery) optional(url string) *probe.Response {
	if d.skipOpt {
		return nil
	}
	if d.limit > 0 && d.remaining <= 0 {
		d.markLimited("budget")
		return nil
	}
	return d.countedFetch(http.MethodGet, url)
}

func (d *discovery) countedFetch(method, url string) *probe.Response {
	resp := d.fetcher.Request(d.ctx, method, url)
	d.issued++
	if d.limit > 0 {
		d.remaining--
	}
	d.inspectBackoff(resp)
	return resp
}

// inspectBackoff notices a 429/503 reply and short-circuits further optional
// probes, recording a Retry-After hint (clamped) when present.
func (d *discovery) inspectBackoff(resp *probe.Response) {
	if resp == nil || resp.Err != "" {
		return
	}
	if resp.Status != http.StatusTooManyRequests && resp.Status != http.StatusServiceUnavailable {
		return
	}
	d.markLimited("retry-after")
	if wait, ok := parseRetryAfter(resp.HeaderGet("Retry-After"), time.Now()); ok {
		if wait > maxRetryAfter {
			wait = maxRetryAfter
		}
		if wait > d.retryWait {
			d.retryWait = wait
		}
	}
}

func (d *discovery) markLimited(reason string) {
	d.skipOpt = true
	if d.limited == "" {
		d.limited = reason
	}
}

// result summarises the discovery for the ServiceResult, or nil when there is
// nothing noteworthy to record (no budget configured and no limiting occurred).
func (d *discovery) result() *Discovery {
	if d.limited == "" && d.limit == 0 {
		return nil
	}
	return &Discovery{
		ProbesIssued: d.issued,
		Budget:       d.limit,
		Limited:      d.limited,
		RetryAfterMS: d.retryWait.Milliseconds(),
	}
}

// parseRetryAfter parses an HTTP Retry-After header, which is either a number
// of seconds or an HTTP date. It returns a non-negative duration from now and
// whether a value was present and valid.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			secs = 0
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// detectedApps collapses a phase-1 detection's frameworks and addons into a
// lowercased set used to gate conditional (app-specific) phase-2 probes.
func detectedApps(d *php.Detection) map[string]bool {
	set := map[string]bool{}
	if d == nil {
		return set
	}
	for _, f := range d.Frameworks {
		set[strings.ToLower(f)] = true
	}
	for _, a := range d.Addons {
		set[strings.ToLower(a)] = true
	}
	return set
}
