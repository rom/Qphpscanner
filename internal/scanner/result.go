// Package scanner orchestrates target expansion, port checks, HTTP probing and
// PHP analysis, producing a structured ScanResult that the report package
// renders into the various output formats.
package scanner

import (
	"encoding/xml"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/securitytxt"
	"github.com/rom/qphpscanner/internal/webserver"
)

// ScanResult is the complete output of a scan run.
type ScanResult struct {
	XMLName xml.Name       `json:"-" xml:"scan"`
	Meta    Meta           `json:"meta" xml:"meta"`
	Targets []TargetResult `json:"targets" xml:"targets>target"`
	Summary Summary        `json:"summary" xml:"summary"`
}

// Meta records how and when the scan was run. The provenance fields (TLSMode
// through CatalogCMS) capture the result-affecting settings and catalogue sizes
// so a diff can tell a real website change from a scanner/config change. They
// are omitempty and absent from scans produced before they existed.
type Meta struct {
	Tool       string    `json:"tool" xml:"tool"`
	Version    string    `json:"version" xml:"version"`
	Mode       string    `json:"mode" xml:"mode"`
	StartedAt  time.Time `json:"started_at" xml:"started_at"`
	FinishedAt time.Time `json:"finished_at" xml:"finished_at"`
	DurationMS int64     `json:"duration_ms" xml:"duration_ms"`
	Ports      []int     `json:"ports" xml:"ports>port"`

	TLSMode    string `json:"tls_mode,omitempty" xml:"tls_mode,omitempty"`
	TimeoutMS  int64  `json:"timeout_ms,omitempty" xml:"timeout_ms,omitempty"`
	Follow     bool   `json:"follow,omitempty" xml:"follow,omitempty"`
	Insecure   bool   `json:"insecure,omitempty" xml:"insecure,omitempty"`
	Auth       bool   `json:"auth,omitempty" xml:"auth,omitempty"`
	Pinned     bool   `json:"pinned,omitempty" xml:"pinned,omitempty"`
	AllowBlock bool   `json:"allow_block,omitempty" xml:"allow_block,omitempty"`
	CatalogPHP int    `json:"catalog_php,omitempty" xml:"catalog_php,omitempty"`
	CatalogCMS int    `json:"catalog_cms,omitempty" xml:"catalog_cms,omitempty"`
	// RequestBudget is the per-service deep-mode probe budget in effect
	// (0 = unlimited); a change between scans can explain coverage differences.
	RequestBudget int `json:"request_budget,omitempty" xml:"request_budget,omitempty"`
	// SignaturePacks records the active detection signature packs (built-in plus
	// any loaded at runtime) with their versions, so a diff can tell a
	// signature-set change from a site change. Absent when only the built-in
	// signatures are in use.
	SignaturePacks []php.PackRef `json:"signature_packs,omitempty" xml:"signature_packs>pack,omitempty"`
}

// Summary holds roll-up counts for quick triage.
type Summary struct {
	HostsScanned    int `json:"hosts_scanned" xml:"hosts_scanned"`
	ServicesProbed  int `json:"services_probed" xml:"services_probed"`
	OpenPorts       int `json:"open_ports" xml:"open_ports"`
	HTTPServices    int `json:"http_services" xml:"http_services"`
	PHPConfirmed    int `json:"php_confirmed" xml:"php_confirmed"`
	PHPLikely       int `json:"php_likely" xml:"php_likely"`
	PHPPossible     int `json:"php_possible" xml:"php_possible"`
	Vulnerabilities int `json:"vulnerabilities" xml:"vulnerabilities"`
	SecurityTxt     int `json:"security_txt" xml:"security_txt"`
	BehindProxy     int `json:"behind_proxy" xml:"behind_proxy"`
	WAFProtected    int `json:"waf_protected" xml:"waf_protected"`
}

// TargetResult groups all services discovered on one host.
type TargetResult struct {
	Host      string          `json:"host" xml:"host,attr"`
	Inputs    []string        `json:"inputs,omitempty" xml:"inputs>input,omitempty"`
	Addresses []string        `json:"addresses,omitempty" xml:"addresses>address,omitempty"`
	PTR       []string        `json:"ptr,omitempty" xml:"ptr>name,omitempty"`
	Services  []ServiceResult `json:"services" xml:"services>service"`
}

// ServiceResult is the assessment of one host:port endpoint.
type ServiceResult struct {
	Host        string                   `json:"host" xml:"host,attr"`
	Port        int                      `json:"port" xml:"port,attr"`
	TLS         bool                     `json:"tls" xml:"tls,attr"`
	Scheme      string                   `json:"scheme" xml:"scheme,attr"`
	URL         string                   `json:"url" xml:"url"`
	PortOpen    bool                     `json:"port_open" xml:"port_open"`
	Error       string                   `json:"error,omitempty" xml:"error,omitempty"`
	Banner      string                   `json:"banner,omitempty" xml:"banner,omitempty"`
	HTTP        *HTTPInfo                `json:"http,omitempty" xml:"http,omitempty"`
	Server      *webserver.ServerInfo    `json:"server,omitempty" xml:"server,omitempty"`
	Proxy       *webserver.ProxyInfo     `json:"proxy,omitempty" xml:"proxy,omitempty"`
	PHP         *php.Detection           `json:"php,omitempty" xml:"php,omitempty"`
	SecurityTxt *securitytxt.SecurityTxt `json:"security_txt,omitempty" xml:"security_txt,omitempty"`
	// Discovery summarises adaptive deep-mode probing for this service: how many
	// probes were issued, the per-service request budget (0 = unlimited) and
	// whether the optional-probe schedule was cut short (budget exhausted or a
	// server Retry-After back-off). Nil in detect mode and when no budget was set
	// and nothing was limited, so older scans and plain deep scans are unchanged.
	Discovery  *Discovery `json:"discovery,omitempty" xml:"discovery,omitempty"`
	DurationMS int64      `json:"duration_ms" xml:"duration_ms"`
	// CheckedAt is when this endpoint was probed (the moment the scan of this
	// service began). Zero for results restored from an older checkpoint.
	CheckedAt time.Time `json:"checked_at,omitempty" xml:"checked_at,omitempty"`
}

// Discovery records how deep-mode adaptive probing was bounded for one service.
type Discovery struct {
	// ProbesIssued is the number of deep-mode probe requests actually issued
	// (every fetch is counted).
	ProbesIssued int `json:"probes_issued" xml:"probes_issued"`
	// Budget is the configured per-service request budget (0 = unlimited).
	Budget int `json:"budget,omitempty" xml:"budget,omitempty"`
	// Limited is why the optional-probe schedule stopped early: "budget" (the
	// per-service cap was reached) or "retry-after" (the host returned 429/503
	// and we backed off). Empty when discovery ran to completion.
	Limited string `json:"limited,omitempty" xml:"limited,omitempty"`
	// RetryAfterMS is the Retry-After back-off the host asked for (clamped),
	// when one was seen.
	RetryAfterMS int64 `json:"retry_after_ms,omitempty" xml:"retry_after_ms,omitempty"`
}

// HTTPInfo is a serialisable summary of the primary HTTP response.
type HTTPInfo struct {
	URL         string            `json:"url" xml:"url"`
	FinalURL    string            `json:"final_url,omitempty" xml:"final_url,omitempty"`
	Status      int               `json:"status" xml:"status"`
	Proto       string            `json:"proto,omitempty" xml:"proto,omitempty"`
	Server      string            `json:"server,omitempty" xml:"server,omitempty"`
	PoweredBy   string            `json:"powered_by,omitempty" xml:"powered_by,omitempty"`
	Title       string            `json:"title,omitempty" xml:"title,omitempty"`
	ContentType string            `json:"content_type,omitempty" xml:"content_type,omitempty"`
	Redirects   int               `json:"redirects,omitempty" xml:"redirects,omitempty"`
	TLS         *probe.TLSInfo    `json:"tls,omitempty" xml:"tls,omitempty"`
	Headers     map[string]string `json:"headers,omitempty" xml:"-"`
	// HTTP2 is true when the primary response used HTTP/2; ALPN is the TLS
	// protocol negotiated; H2C is true when the server advertised cleartext
	// HTTP/2 upgrade support.
	HTTP2 bool   `json:"http2,omitempty" xml:"http2,omitempty"`
	ALPN  string `json:"alpn,omitempty" xml:"alpn,omitempty"`
	H2C   bool   `json:"h2c,omitempty" xml:"h2c,omitempty"`
}
