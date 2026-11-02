// Package rrset groups EuroDNS records into RRsets (host + type), the unit
// of ownership in eurodns-gate and of management in the Terraform provider.
package rrset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

// Apex is the normalized host of the zone apex.
const Apex = "@"

// Key identifies an RRset. Host is normalized (see NormalizeHost).
type Key struct {
	Host string
	Type string
}

func (k Key) String() string { return k.Host + "/" + k.Type }

// Less orders keys by host then type.
func (k Key) Less(o Key) bool {
	if k.Host != o.Host {
		return k.Host < o.Host
	}
	return k.Type < o.Type
}

// Set is an RRset: all records sharing a Key. Values are sorted rdata.
type Set struct {
	Key     Key
	TTL     int
	Values  []string
	Records []eurodns.Record // original records, in zone order
}

// KeyOf returns the normalized key of a record.
func KeyOf(zone string, r eurodns.Record) Key {
	return Key{Host: NormalizeHost(r.Host, zone), Type: strings.ToUpper(strings.TrimSpace(r.Type))}
}

// NormalizeHost lowercases, strips a trailing dot and the zone suffix, and
// maps "" and "@" to "@" (apex).
func NormalizeHost(host, zone string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	z := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if z != "" {
		if h == z {
			return Apex
		}
		h = strings.TrimSuffix(h, "."+z)
	}
	if h == "" || h == Apex {
		return Apex
	}
	return h
}

// Group groups records by Key. Pseudo types URL and MAIL are included.
func Group(zone string, recs []eurodns.Record) map[Key]Set {
	out := map[Key]Set{}
	for _, r := range recs {
		k := KeyOf(zone, r)
		s, ok := out[k]
		if !ok {
			s = Set{Key: k, TTL: r.TTL}
		}
		s.Values = append(s.Values, r.RData)
		s.Records = append(s.Records, r)
		out[k] = s
	}
	for k, s := range out {
		sort.Strings(s.Values)
		out[k] = s
	}
	return out
}

// SortedKeys returns the keys of a grouping, ordered by host then type.
func SortedKeys(m map[Key]Set) []Key {
	keys := make([]Key, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
	return keys
}

// ContentHash is a stable hash of TTL + sorted values (hex sha256).
func ContentHash(s Set) string {
	vals := append([]string(nil), s.Values...)
	sort.Strings(vals)
	h := sha256.New()
	fmt.Fprintf(h, "ttl=%d\n", s.TTL)
	for _, v := range vals {
		fmt.Fprintf(h, "%d:%s\n", len(v), v)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MatchHost reports whether a normalized host matches a glob pattern where
// "*" matches exactly one label and "**" any number of labels (>= 1).
// Inside a label, "*" also matches any run of characters ("_*" matches
// "_acme-challenge"). "@" matches only the apex.
func MatchHost(pattern, host string) bool {
	p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if p == "" {
		p = Apex
	}
	if h == "" {
		h = Apex
	}
	if p == Apex || h == Apex {
		return p == h
	}
	return matchLabels(strings.Split(p, "."), strings.Split(h, "."))
}

func matchLabels(p, h []string) bool {
	if len(p) == 0 {
		return len(h) == 0
	}
	if p[0] == "**" {
		for i := 1; i <= len(h); i++ {
			if matchLabels(p[1:], h[i:]) {
				return true
			}
		}
		return false
	}
	if len(h) == 0 || !matchLabel(p[0], h[0]) {
		return false
	}
	return matchLabels(p[1:], h[1:])
}

// matchLabel is a glob match where "*" matches any run of characters.
func matchLabel(p, s string) bool {
	if !strings.Contains(p, "*") {
		return p == s
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last) && len(s) >= len(last)
}

var fqdnTypes = map[string]bool{"CNAME": true, "MX": true, "NS": true, "SRV": true, "PTR": true, "APEX": true}

// NeedsFQDN reports whether the type's rdata ends with a domain name that
// EuroDNS expects fully qualified (ending dot); without it EuroDNS appends
// the zone name.
func NeedsFQDN(typ string) bool { return fqdnTypes[strings.ToUpper(strings.TrimSpace(typ))] }

// TargetOf returns the domain name carried by rdata for types where
// NeedsFQDN is true (last field for MX and SRV, whole rdata otherwise), and
// "" for other types.
func TargetOf(typ, rdata string) string {
	t := strings.ToUpper(strings.TrimSpace(typ))
	if !fqdnTypes[t] {
		return ""
	}
	fields := strings.Fields(rdata)
	if len(fields) == 0 {
		return ""
	}
	if t == "MX" || t == "SRV" {
		return fields[len(fields)-1]
	}
	return strings.TrimSpace(rdata)
}

// ServerManaged reports whether a record is managed by EuroDNS and must be
// left untouched: any SOA, and any record flagged locked (apex SOA and NS).
func ServerManaged(r eurodns.Record) bool {
	return strings.EqualFold(strings.TrimSpace(r.Type), "SOA") || (r.Locked != nil && *r.Locked)
}
