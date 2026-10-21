package php

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FaviconEntry maps a Shodan-style favicon hash (mmh3 of the MIME-base64 of the
// icon bytes) to the product it identifies.
type FaviconEntry struct {
	// Hash is the signed-decimal mmh3 favicon hash (as faviconHash returns).
	Hash string `json:"hash"`
	// Product is the human name shown in evidence.
	Product string `json:"product"`
	// Framework, when set, is attributed to the Frameworks list.
	Framework string `json:"framework,omitempty"`
	// PHP indicates a match is (also) evidence the stack is PHP.
	PHP bool `json:"php,omitempty"`
	// Note is an optional clarification.
	Note string `json:"note,omitempty"`
}

// FaviconCatalog is the JSON shape of an external favicon catalogue.
type FaviconCatalog struct {
	Schema   string         `json:"schema,omitempty"`
	Favicons []FaviconEntry `json:"favicons"`
}

// FaviconCatalogSchema is the identifier an external catalogue should declare.
const FaviconCatalogSchema = "qphpscanner-favicon-catalog/1"

// builtinFavicons seeds the catalogue with hashes of well-known PHP-application
// favicons drawn from public icon-hash corpora. An unknown or stale hash is
// simply inert: real favicons never collide with it, so a wrong entry can only
// fail to match — never misattribute — which keeps the seed safe to extend.
var builtinFavicons = []FaviconEntry{
	{Hash: "-1961736892", Product: "phpMyAdmin", Framework: "phpMyAdmin", PHP: true},
	{Hash: "1279322348", Product: "phpMyAdmin", Framework: "phpMyAdmin", PHP: true},
	{Hash: "1485257654", Product: "Adminer", Framework: "Adminer", PHP: true},
	{Hash: "743365239", Product: "WordPress", Framework: "WordPress", PHP: true},
	{Hash: "-1105063887", Product: "Joomla", Framework: "Joomla", PHP: true},
	{Hash: "-1588080585", Product: "Drupal", Framework: "Drupal", PHP: true},
	{Hash: "1064742722", Product: "phpBB", Framework: "phpBB", PHP: true},
	{Hash: "1485495435", Product: "Magento", Framework: "Magento", PHP: true},
	{Hash: "81586312", Product: "Roundcube", Framework: "Roundcube", PHP: true},
	{Hash: "-333791179", Product: "Nextcloud", Framework: "Nextcloud/ownCloud", PHP: true},
	{Hash: "13421739", Product: "Zabbix", Framework: "Zabbix", PHP: true},
	{Hash: "-1255347784", Product: "GLPI", Framework: "GLPI", PHP: true},
	{Hash: "1109941334", Product: "Matomo", Framework: "Matomo", PHP: true},
	{Hash: "-1010568750", Product: "Cacti", Framework: "Cacti", PHP: true},
	{Hash: "-235701012", Product: "osTicket", Framework: "osTicket", PHP: true},
	{Hash: "2142627359", Product: "MediaWiki", Framework: "MediaWiki", PHP: true},
}

var (
	faviconMu    sync.RWMutex
	faviconIndex = buildFaviconIndex(builtinFavicons)
)

func buildFaviconIndex(entries []FaviconEntry) map[string]FaviconEntry {
	m := make(map[string]FaviconEntry, len(entries))
	for _, e := range entries {
		if e.Hash == "" {
			continue
		}
		m[e.Hash] = e
	}
	return m
}

// faviconLookup returns the catalogue entry for a favicon hash, if known.
func faviconLookup(hash string) (FaviconEntry, bool) {
	if hash == "" {
		return FaviconEntry{}, false
	}
	faviconMu.RLock()
	defer faviconMu.RUnlock()
	e, ok := faviconIndex[hash]
	return e, ok
}

// RegisterFavicons merges extra entries into the active catalogue. It must be
// called before a scan starts (it is not safe to call concurrently with an
// in-flight Analyze). Later entries override earlier ones for the same hash.
func RegisterFavicons(entries []FaviconEntry) {
	faviconMu.Lock()
	defer faviconMu.Unlock()
	for _, e := range entries {
		if e.Hash == "" {
			continue
		}
		faviconIndex[e.Hash] = e
	}
}

// FaviconCatalogCount reports how many favicon entries are active.
func FaviconCatalogCount() int {
	faviconMu.RLock()
	defer faviconMu.RUnlock()
	return len(faviconIndex)
}

// ParseFaviconCatalog decodes a favicon catalogue and validates its schema.
func ParseFaviconCatalog(data []byte) (*FaviconCatalog, error) {
	var c FaviconCatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Schema != "" && c.Schema != FaviconCatalogSchema {
		return nil, &schemaError{got: c.Schema, want: FaviconCatalogSchema}
	}
	return &c, nil
}

type schemaError struct{ got, want string }

func (e *schemaError) Error() string {
	return "unsupported favicon catalogue schema " + strconv.Quote(e.got) + " (want " + strconv.Quote(e.want) + ")"
}

// LoadFaviconCatalog reads a favicon catalogue from a local file or http(s) URL
// and registers its entries. It returns the number of entries added.
func LoadFaviconCatalog(ctx context.Context, src string, client *http.Client) (int, error) {
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
			return 0, &httpStatusError{code: resp.StatusCode}
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return 0, err
	}
	cat, err := ParseFaviconCatalog(data)
	if err != nil {
		return 0, err
	}
	RegisterFavicons(cat.Favicons)
	return len(cat.Favicons), nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string {
	return "fetch favicon catalogue: HTTP " + strconv.Itoa(e.code)
}
