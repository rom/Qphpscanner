// Package config loads the optional YAML configuration file and exposes it as
// a typed Config. Pointer-typed booleans let the caller distinguish "unset"
// (so a CLI flag can win) from an explicit false.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config mirrors the YAML schema. See config.example.yaml for documentation.
type Config struct {
	Targets         []string
	Ports           string
	Mode            string
	TLS             string
	Timeout         string
	Concurrency     int
	FollowRedirects *bool
	Insecure        *bool
	SecurityTxt     *bool
	IncludeClosed   *bool
	MaxHostsPerSpec int
	UserAgent       string
	MaxBodyBytes    int64
	Output          OutputConfig
	Report          ReportConfig
	Web             WebConfig

	// Politeness.
	Rate               float64
	PerHostConcurrency int
	HostConcurrency    int
	Jitter             string
	Retries            int

	// Enrichment.
	ResolveDNS *bool
	Banners    *bool

	// HTTP request shaping.
	Headers []string // "Name: value" entries
	Cookie  string
	Bearer  string
	Basic   string // user:pass
	Vhost   string
	Proxy   string
	Resolve []string // "host:port:addr" rules (curl --resolve style)
	SNI     string   // TLS SNI override

	// Data / resume / targets.
	VulnFeeds        []string
	ComposerFiles    []string
	FaviconCatalogs  []string
	Allow            []string
	Block            []string
	FailOn           string
	Resume           string
	VerifySubdomains *bool
	NoDNSEnum        *bool
	TargetsFile      string

	// Audit trail.
	PCAP string
	Log  string
}

// OutputConfig selects the machine-readable scan output.
type OutputConfig struct {
	Format string
	File   string
}

// ReportConfig selects the human-readable report.
type ReportConfig struct {
	Format string
	File   string
}

// WebConfig configures the embedded web UI.
type WebConfig struct {
	Enabled *bool
	Listen  string
	Auth    string // user:pass for HTTP Basic auth
}

// Load reads and parses a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	m, err := Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	c := &Config{}
	c.Targets = getStringSlice(m, "targets")
	c.Ports = getString(m, "ports")
	c.Mode = getString(m, "mode")
	c.TLS = getString(m, "tls")
	c.Timeout = getString(m, "timeout")
	c.UserAgent = getString(m, "user_agent")

	if v, ok, err := getInt(m, "concurrency"); err != nil {
		return nil, err
	} else if ok {
		c.Concurrency = v
	}
	if v, ok, err := getInt(m, "max_hosts_per_spec"); err != nil {
		return nil, err
	} else if ok {
		c.MaxHostsPerSpec = v
	}
	if v, ok, err := getInt64(m, "max_body_bytes"); err != nil {
		return nil, err
	} else if ok {
		c.MaxBodyBytes = v
	}

	c.Jitter = getString(m, "jitter")
	c.Cookie = getString(m, "cookie")
	c.Bearer = getString(m, "bearer")
	c.Basic = getString(m, "basic")
	c.Vhost = getString(m, "vhost")
	c.Proxy = getString(m, "proxy")
	c.Resolve = getStringSlice(m, "resolve")
	c.SNI = getString(m, "sni")
	c.FailOn = getString(m, "fail_on")
	c.Resume = getString(m, "resume")
	c.TargetsFile = getString(m, "targets_file")
	c.PCAP = getString(m, "pcap")
	c.Log = getString(m, "log")
	c.Headers = getHeaders(m, "headers")
	c.VulnFeeds = getStringSlice(m, "vuln_feeds")
	c.ComposerFiles = getStringSlice(m, "composer_files")
	c.FaviconCatalogs = getStringSlice(m, "favicon_catalogs")
	c.Allow = getStringSlice(m, "allow")
	c.Block = getStringSlice(m, "block")

	if v, ok, err := getInt(m, "per_host_concurrency"); err != nil {
		return nil, err
	} else if ok {
		c.PerHostConcurrency = v
	}
	if v, ok, err := getInt(m, "host_concurrency"); err != nil {
		return nil, err
	} else if ok {
		c.HostConcurrency = v
	}
	if v, ok, err := getInt(m, "retries"); err != nil {
		return nil, err
	} else if ok {
		c.Retries = v
	}
	if v, ok, err := getFloat(m, "rate"); err != nil {
		return nil, err
	} else if ok {
		c.Rate = v
	}

	var perr error
	c.FollowRedirects, perr = getBoolPtr(m, "follow_redirects", perr)
	c.Insecure, perr = getBoolPtr(m, "insecure", perr)
	c.SecurityTxt, perr = getBoolPtr(m, "security_txt", perr)
	c.IncludeClosed, perr = getBoolPtr(m, "include_closed", perr)
	c.ResolveDNS, perr = getBoolPtr(m, "resolve_dns", perr)
	c.Banners, perr = getBoolPtr(m, "banners", perr)
	c.VerifySubdomains, perr = getBoolPtr(m, "verify_subdomains", perr)
	c.NoDNSEnum, perr = getBoolPtr(m, "no_dns_enum", perr)
	if perr != nil {
		return nil, perr
	}

	if out := getMap(m, "output"); out != nil {
		c.Output.Format = getString(out, "format")
		c.Output.File = getString(out, "file")
	}
	if rep := getMap(m, "report"); rep != nil {
		c.Report.Format = getString(rep, "format")
		c.Report.File = getString(rep, "file")
	}
	if web := getMap(m, "web"); web != nil {
		c.Web.Listen = getString(web, "listen")
		c.Web.Auth = getString(web, "auth")
		c.Web.Enabled, perr = getBoolPtr(web, "enabled", nil)
		if perr != nil {
			return nil, perr
		}
	}

	return c, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringSlice(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		// Allow a comma-separated single-line form too.
		var out []string
		for _, s := range strings.Split(t, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key]; ok {
		if mm, ok := v.(map[string]interface{}); ok {
			return mm
		}
	}
	return nil
}

func getInt(m map[string]interface{}, key string) (int, bool, error) {
	s := getString(m, key)
	if s == "" {
		return 0, false, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false, fmt.Errorf("config key %q: %q is not an integer", key, s)
	}
	return n, true, nil
}

func getInt64(m map[string]interface{}, key string) (int64, bool, error) {
	s := getString(m, key)
	if s == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("config key %q: %q is not an integer", key, s)
	}
	return n, true, nil
}

func getFloat(m map[string]interface{}, key string) (float64, bool, error) {
	s := getString(m, key)
	if s == "" {
		return 0, false, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false, fmt.Errorf("config key %q: %q is not a number", key, s)
	}
	return f, true, nil
}

// getHeaders accepts either a list of "Name: value" strings or a map of
// {Name: value} and normalises both to "Name: value" entries.
func getHeaders(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []interface{}:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case map[string]interface{}:
		var out []string
		for k, val := range t {
			if s, ok := val.(string); ok {
				out = append(out, k+": "+s)
			}
		}
		return out
	}
	return nil
}

func getBoolPtr(m map[string]interface{}, key string, prev error) (*bool, error) {
	if prev != nil {
		return nil, prev
	}
	s := getString(m, key)
	if s == "" {
		return nil, nil
	}
	switch strings.ToLower(s) {
	case "true", "yes", "on", "1":
		b := true
		return &b, nil
	case "false", "no", "off", "0":
		b := false
		return &b, nil
	default:
		return nil, fmt.Errorf("config key %q: %q is not a boolean", key, s)
	}
}
