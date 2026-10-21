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

// Meta records how and when the scan was run.
type Meta struct {
	Tool       string    `json:"tool" xml:"tool"`
	Version    string    `json:"version" xml:"version"`
	Mode       string    `json:"mode" xml:"mode"`
	StartedAt  time.Time `json:"started_at" xml:"started_at"`
	FinishedAt time.Time `json:"finished_at" xml:"finished_at"`
	DurationMS int64     `json:"duration_ms" xml:"duration_ms"`
	Ports      []int     `json:"ports" xml:"ports>port"`
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
	DurationMS  int64                    `json:"duration_ms" xml:"duration_ms"`
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
