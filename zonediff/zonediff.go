// Package zonediff computes the RRset-level delta between two zone states.
package zonediff

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

// Op is the kind of change on an RRset.
type Op string

const (
	OpCreate Op = "create"
	OpUpdate Op = "update"
	OpDelete Op = "delete"
)

// Change is one RRset-level change. Old is nil on create, New nil on delete.
type Change struct {
	Op  Op
	Key rrset.Key
	Old *rrset.Set
	New *rrset.Set
}

// Delta is the full difference between two zones.
type Delta struct {
	Changes         []Change // sorted by Key
	ForwardsChanged bool     // URL or mail forwards differ (raw JSON compare)
	OtherChanged    bool     // domainConnect or unknown top-level fields differ
}

// Empty reports whether the delta carries no change at all.
func (d Delta) Empty() bool {
	return len(d.Changes) == 0 && !d.ForwardsChanged && !d.OtherChanged
}

// Diff compares current (server) and desired zones. Two RRsets differ when
// their TTL, values or per-record attributes (proxy, isDynDns, unknown
// fields) differ; ids and read-only flags are ignored.
//
// Server-managed records are ignored on both sides: every SOA (its serial is
// bumped by EuroDNS on each write), records locked in the current zone, and
// desired records flagged locked or identical to a locked current record.
func Diff(zone string, current, desired *eurodns.Zone) Delta {
	if current == nil {
		current = &eurodns.Zone{}
	}
	if desired == nil {
		desired = &eurodns.Zone{}
	}
	curRecs, managed := splitManaged(zone, current.Records)
	var desRecs []eurodns.Record
	for _, r := range desired.Records {
		if rrset.ServerManaged(r) || managed[managedKey(zone, r)] {
			continue
		}
		desRecs = append(desRecs, r)
	}
	cur := rrset.Group(zone, curRecs)
	des := rrset.Group(zone, desRecs)

	var d Delta
	keys := map[rrset.Key]bool{}
	for k := range cur {
		keys[k] = true
	}
	for k := range des {
		keys[k] = true
	}
	for k := range keys {
		c, inCur := cur[k]
		n, inDes := des[k]
		switch {
		case inCur && !inDes:
			c := c
			d.Changes = append(d.Changes, Change{Op: OpDelete, Key: k, Old: &c})
		case !inCur && inDes:
			n := n
			d.Changes = append(d.Changes, Change{Op: OpCreate, Key: k, New: &n})
		case !sameSet(c, n):
			c, n := c, n
			d.Changes = append(d.Changes, Change{Op: OpUpdate, Key: k, Old: &c, New: &n})
		}
	}
	sort.Slice(d.Changes, func(i, j int) bool { return d.Changes[i].Key.Less(d.Changes[j].Key) })

	d.ForwardsChanged = !sameRawList(current.URLForwards, desired.URLForwards) ||
		!sameRawList(current.MailForwards, desired.MailForwards)
	if desired.DomainConnect != nil && (current.DomainConnect == nil || *current.DomainConnect != *desired.DomainConnect) {
		d.OtherChanged = true
	}
	for k, v := range desired.Extra {
		if !sameRaw(current.Extra[k], v) {
			d.OtherChanged = true
		}
	}
	return d
}

// splitManaged returns the records that are not server-managed, and the
// identities (key + rdata) of the server-managed ones.
func splitManaged(zone string, recs []eurodns.Record) ([]eurodns.Record, map[string]bool) {
	var out []eurodns.Record
	managed := map[string]bool{}
	for _, r := range recs {
		if rrset.ServerManaged(r) {
			managed[managedKey(zone, r)] = true
			continue
		}
		out = append(out, r)
	}
	return out, managed
}

func managedKey(zone string, r eurodns.Record) string {
	return rrset.KeyOf(zone, r).String() + "\x00" + strings.TrimSpace(r.RData)
}

func sameSet(a, b rrset.Set) bool {
	if a.TTL != b.TTL || len(a.Records) != len(b.Records) {
		return false
	}
	return strings.Join(signatures(a), "\x00") == strings.Join(signatures(b), "\x00")
}

// signatures returns the sorted comparable form of an RRset's records.
func signatures(s rrset.Set) []string {
	out := make([]string, 0, len(s.Records))
	for _, r := range s.Records {
		sig := struct {
			TTL   int                        `json:"ttl"`
			RData string                     `json:"rdata"`
			Dyn   bool                       `json:"dyn"`
			Proxy string                     `json:"proxy"`
			Extra map[string]json.RawMessage `json:"extra,omitempty"`
		}{TTL: r.TTL, RData: r.RData, Dyn: r.IsDynDNS != nil && *r.IsDynDNS, Proxy: r.Proxy}
		if len(r.Extra) > 0 {
			sig.Extra = map[string]json.RawMessage{}
			for k, v := range r.Extra {
				sig.Extra[k] = canonical(v)
			}
		}
		b, _ := json.Marshal(sig)
		out = append(out, string(b))
	}
	sort.Strings(out)
	return out
}

func canonical(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("null")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

func sameRaw(a, b json.RawMessage) bool {
	return bytes.Equal(canonical(a), canonical(b))
}

func sameRawList(a, b []json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameRaw(a[i], b[i]) {
			return false
		}
	}
	return true
}

// Apply returns current with the given changes applied, every other record
// kept byte-identical and in place. Used to rebase a scoped write.
// Server-managed records (SOA, locked) are always taken from current
// unchanged, whatever the changes say.
//
// An update replaces the RRset's records at the position of its first
// record, reusing original ids for unchanged values. A create appends at the
// end without ids. A change whose Key no longer exists is treated as a create
// (update) or ignored (delete). New sets without Records are synthesized from
// Key, TTL and Values.
func Apply(zone string, current *eurodns.Zone, changes []Change) *eurodns.Zone {
	out := &eurodns.Zone{}
	if current != nil {
		*out = *current
	}
	byKey := map[rrset.Key]Change{}
	for _, c := range changes {
		byKey[c.Key] = c
	}

	var recs []eurodns.Record
	done := map[rrset.Key]bool{}
	var old []eurodns.Record
	if current != nil {
		old = current.Records
	}
	oldByKey := map[rrset.Key][]eurodns.Record{}
	for _, r := range old {
		if rrset.ServerManaged(r) {
			continue
		}
		k := rrset.KeyOf(zone, r)
		oldByKey[k] = append(oldByKey[k], r)
	}
	for _, r := range old {
		if rrset.ServerManaged(r) {
			recs = append(recs, r)
			continue
		}
		k := rrset.KeyOf(zone, r)
		c, changed := byKey[k]
		if !changed {
			recs = append(recs, r)
			continue
		}
		if done[k] {
			continue
		}
		done[k] = true
		if c.Op == OpDelete || c.New == nil {
			continue
		}
		recs = append(recs, newRecords(c.Key, c.New, oldByKey[k])...)
	}
	for _, c := range changes {
		if done[c.Key] || c.Op == OpDelete || c.New == nil {
			continue
		}
		done[c.Key] = true
		recs = append(recs, newRecords(c.Key, c.New, nil)...)
	}
	if recs == nil {
		recs = []eurodns.Record{}
	}
	out.Records = recs
	out.Report = nil
	return out
}

func newRecords(k rrset.Key, s *rrset.Set, old []eurodns.Record) []eurodns.Record {
	var src []eurodns.Record
	if len(s.Records) > 0 {
		for _, r := range s.Records {
			if rrset.ServerManaged(r) {
				continue
			}
			r.ID, r.Updated, r.Locked = nil, nil, nil
			if s.TTL > 0 {
				r.TTL = s.TTL
			}
			src = append(src, r)
		}
	} else if !strings.EqualFold(k.Type, "SOA") {
		for _, v := range s.Values {
			src = append(src, eurodns.Record{Type: k.Type, Host: k.Host, TTL: s.TTL, RData: v})
		}
	}
	used := make([]bool, len(old))
	for i := range src {
		for j, o := range old {
			if !used[j] && o.ID != nil && o.RData == src[i].RData {
				used[j] = true
				id := *o.ID
				src[i].ID = &id
				break
			}
		}
	}
	return src
}
