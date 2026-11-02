package eurodns

import "encoding/json"

// Zone mirrors the DnsZonePage schema. URL and mail forwards are kept as raw
// JSON so that a zone read then written back is preserved byte for byte.
type Zone struct {
	Name          string                     `json:"name,omitempty"`
	DomainConnect *bool                      `json:"domainConnect,omitempty"`
	Records       []Record                   `json:"records"`
	URLForwards   []json.RawMessage          `json:"urlForwards"`
	MailForwards  []json.RawMessage          `json:"mailForwards"`
	Report        *ValidationReport          `json:"report,omitempty"`
	Extra         map[string]json.RawMessage `json:"-"`

	// ETag is set by GetZone when the server returns one (eurodns-gate does,
	// EuroDNS does not). It is never serialized.
	ETag string `json:"-"`
}

// Record mirrors the DnsRecord schema. Unknown fields are kept in Extra and
// written back unchanged (custom JSON marshalling).
type Record struct {
	ID       *int64                     `json:"id,omitempty"`
	Type     string                     `json:"type"`
	Host     string                     `json:"host"`
	TTL      int                        `json:"ttl"`
	RData    string                     `json:"rdata"`
	Updated  *bool                      `json:"updated,omitempty"`
	Locked   *bool                      `json:"locked,omitempty"`
	IsDynDNS *bool                      `json:"isDynDns,omitempty"`
	Proxy    string                     `json:"proxy,omitempty"`
	Extra    map[string]json.RawMessage `json:"-"`
}

// ValidationReport mirrors ZoneValidationReport; error details are kept raw.
type ValidationReport struct {
	IsValid           *bool             `json:"isValid,omitempty"`
	RecordErrors      []json.RawMessage `json:"recordErrors,omitempty"`
	URLForwardErrors  []json.RawMessage `json:"urlForwardErrors,omitempty"`
	MailForwardErrors []json.RawMessage `json:"mailForwardErrors,omitempty"`
	ZoneErrors        []json.RawMessage `json:"zoneErrors,omitempty"`
}

// Snapshot mirrors DnsZoneSnapshotItem.
type Snapshot struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"createdAt"`
	ZoneName  string `json:"zoneName"`
}

// AllowedTTLs is the fixed list of TTL values accepted by EuroDNS.
var AllowedTTLs = []int{600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400, 172800, 432000, 604800}

// GateInfo is returned by an eurodns-gate on GET /.well-known/eurodns-gate.
type GateInfo struct {
	Version  string   `json:"version"`
	Features []string `json:"features"` // e.g. "if-match", "ownership", "adopt"
}

// Gate feature names.
const (
	FeatureIfMatch   = "if-match"
	FeatureOwnership = "ownership"
	FeatureAdopt     = "adopt"
)

// GateInfoPath is the extension endpoint served by eurodns-gate only.
const GateInfoPath = "/.well-known/eurodns-gate"

// AdoptRequest is the body of POST /.well-known/eurodns-gate/zones/{domain}/adopt.
type AdoptRequest struct {
	RRsets []AdoptRRset `json:"rrsets"`
	Owner  string       `json:"owner,omitempty"` // owner team; defaults to the caller's team
}

// AdoptRRset identifies one RRset to adopt.
type AdoptRRset struct {
	Host string `json:"host"`
	Type string `json:"type"`
}
