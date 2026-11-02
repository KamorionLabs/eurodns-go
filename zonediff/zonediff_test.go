package zonediff

import (
	"encoding/json"
	"testing"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

func id(n int64) *int64 { return &n }

func base() *eurodns.Zone {
	return &eurodns.Zone{Name: "example.com", Records: []eurodns.Record{
		{ID: id(1), Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"},
		{ID: id(2), Type: "MX", Host: "@", TTL: 3600, RData: "10 mx.example.net."},
		{ID: id(3), Type: "A", Host: "www", TTL: 600, RData: "192.0.2.2"},
		{ID: id(4), Type: "TXT", Host: "old", TTL: 600, RData: `"x"`},
	}, URLForwards: []json.RawMessage{json.RawMessage(`{"host":"go", "url":"https://example.net"}`)}}
}

func TestDiff(t *testing.T) {
	cur := base()
	des := base()
	des.Records[0].RData = "192.0.2.9"                                                                                   // www/A update
	des.Records = append(des.Records[:3], eurodns.Record{Type: "CNAME", Host: "app", TTL: 600, RData: "x.example.net."}) // drop old/TXT, add app/CNAME
	des.Records[1].ID = nil                                                                                              // id change alone is not a change
	des.URLForwards = []json.RawMessage{json.RawMessage(`{"url":"https://example.net","host":"go"}`)}

	d := Diff("example.com", cur, des)
	if len(d.Changes) != 3 || d.ForwardsChanged || d.OtherChanged {
		t.Fatalf("unexpected delta: %+v", d)
	}
	want := []struct {
		op  Op
		key rrset.Key
	}{{OpCreate, rrset.Key{Host: "app", Type: "CNAME"}}, {OpDelete, rrset.Key{Host: "old", Type: "TXT"}}, {OpUpdate, rrset.Key{Host: "www", Type: "A"}}}
	for i, w := range want {
		if d.Changes[i].Op != w.op || d.Changes[i].Key != w.key {
			t.Errorf("change %d = %s %v, want %s %v", i, d.Changes[i].Op, d.Changes[i].Key, w.op, w.key)
		}
	}

	des.URLForwards = nil
	f := true
	des.DomainConnect = &f
	d = Diff("example.com", cur, des)
	if !d.ForwardsChanged || !d.OtherChanged {
		t.Fatalf("forwards/other change not detected: %+v", d)
	}
}

func TestDiffAttributesAndEmpty(t *testing.T) {
	cur := base()
	des := base()
	if !Diff("example.com", cur, des).Empty() {
		t.Fatal("identical zones must give an empty delta")
	}
	des.Records[0].Proxy = "ON"
	if d := Diff("example.com", cur, des); len(d.Changes) != 1 || d.Changes[0].Op != OpUpdate {
		t.Fatalf("proxy change not detected: %+v", d)
	}
}

func TestApply(t *testing.T) {
	cur := base()
	upd := rrset.Set{Key: rrset.Key{Host: "www", Type: "A"}, TTL: 900, Values: []string{"192.0.2.2", "192.0.2.3"}}
	crt := rrset.Set{Key: rrset.Key{Host: "_acme-challenge", Type: "TXT"}, TTL: 600, Values: []string{`"tok"`}}
	out := Apply("example.com", cur, []Change{
		{Op: OpUpdate, Key: upd.Key, New: &upd},
		{Op: OpDelete, Key: rrset.Key{Host: "@", Type: "MX"}},
		{Op: OpCreate, Key: crt.Key, New: &crt},
	})
	got := out.Records
	if len(got) != 4 {
		t.Fatalf("want 4 records, got %+v", got)
	}
	// www/A replaced in place of its first record, id reused for the kept value.
	if got[0].RData != "192.0.2.2" || got[0].ID == nil || *got[0].ID != 3 || got[0].TTL != 900 {
		t.Fatalf("bad first record: %+v", got[0])
	}
	if got[1].RData != "192.0.2.3" || got[1].ID != nil {
		t.Fatalf("bad second record: %+v", got[1])
	}
	if got[2].Host != "old" || *got[2].ID != 4 {
		t.Fatalf("untouched record moved or changed: %+v", got[2])
	}
	if got[3].Host != "_acme-challenge" || got[3].ID != nil {
		t.Fatalf("create not appended: %+v", got[3])
	}
	if string(out.URLForwards[0]) != string(cur.URLForwards[0]) {
		t.Fatal("forwards must be kept byte-identical")
	}
	if len(cur.Records) != 4 || cur.Records[1].Type != "MX" {
		t.Fatal("Apply must not mutate its input")
	}
	// Apply(Diff) reproduces the desired RRsets.
	des := base()
	des.Records[2].RData = "192.0.2.7"
	again := Apply("example.com", cur, Diff("example.com", cur, des).Changes)
	if !Diff("example.com", again, des).Empty() {
		t.Fatal("Apply(Diff) must converge")
	}
}

func managedZone() *eurodns.Zone {
	t := true
	z := base()
	z.Records = append([]eurodns.Record{
		{ID: id(90), Type: "SOA", Host: "", TTL: 86400, RData: "ns1.example.net. hostmaster.example.net. 2026110205 86400 7200 604800 600", Locked: &t},
		{ID: id(91), Type: "NS", Host: "", TTL: 86400, RData: "ns1.example.net.", Locked: &t},
	}, z.Records...)
	return z
}

func TestDiffIgnoresServerManagedRecords(t *testing.T) {
	cur := managedZone()
	des := managedZone()
	des.Records[0].RData = "ns1.example.net. hostmaster.example.net. 2026110201 86400 7200 604800 600"
	des.Records[0].Locked = nil
	if d := Diff("example.com", cur, des); !d.Empty() {
		t.Fatalf("stale SOA must give an empty delta: %+v", d)
	}
	des.Records = des.Records[2:] // client dropped SOA and NS
	if d := Diff("example.com", cur, des); !d.Empty() {
		t.Fatalf("dropping managed records must give an empty delta: %+v", d)
	}
}

func TestApplyKeepsServerManagedRecords(t *testing.T) {
	cur := managedZone()
	soa := rrset.Set{Key: rrset.Key{Host: "@", Type: "SOA"}, TTL: 600, Values: []string{"evil"}}
	ns := rrset.Set{Key: rrset.Key{Host: "@", Type: "NS"}, TTL: 600, Values: []string{"ns.attacker.example."}}
	out := Apply("example.com", cur, []Change{
		{Op: OpUpdate, Key: soa.Key, New: &soa},
		{Op: OpDelete, Key: rrset.Key{Host: "@", Type: "NS"}},
	})
	if out.Records[0].RData != cur.Records[0].RData || out.Records[1].RData != "ns1.example.net." {
		t.Fatalf("managed records changed: %+v", out.Records[:2])
	}
	for _, r := range out.Records {
		if r.RData == "evil" {
			t.Fatal("SOA must never be synthesized")
		}
	}
	out = Apply("example.com", cur, []Change{{Op: OpCreate, Key: ns.Key, New: &ns}})
	if n := len(out.Records); n != len(cur.Records)+1 || out.Records[1].RData != "ns1.example.net." {
		t.Fatalf("locked NS must stay, extra NS appended: %+v", out.Records)
	}
}
