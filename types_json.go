package eurodns

import (
	"encoding/json"
)

var zoneKnown = map[string]bool{
	"name": true, "domainConnect": true, "records": true,
	"urlForwards": true, "mailForwards": true, "report": true,
}

var recordKnown = map[string]bool{
	"id": true, "type": true, "host": true, "ttl": true, "rdata": true,
	"updated": true, "locked": true, "isDynDns": true, "proxy": true,
}

type zoneAlias Zone
type recordAlias Record

// MarshalJSON writes known fields, then unknown fields kept in Extra.
// Nil records and forwards are written as empty arrays.
func (z Zone) MarshalJSON() ([]byte, error) {
	a := zoneAlias(z)
	if a.Records == nil {
		a.Records = []Record{}
	}
	if a.URLForwards == nil {
		a.URLForwards = []json.RawMessage{}
	}
	if a.MailForwards == nil {
		a.MailForwards = []json.RawMessage{}
	}
	return mergeExtra(a, z.Extra, zoneKnown)
}

// UnmarshalJSON reads known fields and keeps unknown ones in Extra.
func (z *Zone) UnmarshalJSON(b []byte) error {
	var a zoneAlias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	extra, err := splitExtra(b, zoneKnown)
	if err != nil {
		return err
	}
	a.Extra = extra
	a.ETag = z.ETag
	*z = Zone(a)
	return nil
}

// MarshalJSON writes known fields, then unknown fields kept in Extra.
func (r Record) MarshalJSON() ([]byte, error) {
	return mergeExtra(recordAlias(r), r.Extra, recordKnown)
}

// UnmarshalJSON reads known fields and keeps unknown ones in Extra.
func (r *Record) UnmarshalJSON(b []byte) error {
	var a recordAlias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	extra, err := splitExtra(b, recordKnown)
	if err != nil {
		return err
	}
	a.Extra = extra
	*r = Record(a)
	return nil
}

func mergeExtra(v any, extra map[string]json.RawMessage, known map[string]bool) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(extra) == 0 {
		return b, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, raw := range extra {
		if known[k] {
			continue
		}
		m[k] = raw
	}
	return json.Marshal(m)
}

func splitExtra(b []byte, known map[string]bool) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	var extra map[string]json.RawMessage
	for k, raw := range m {
		if known[k] {
			continue
		}
		if extra == nil {
			extra = map[string]json.RawMessage{}
		}
		extra[k] = raw
	}
	return extra, nil
}
