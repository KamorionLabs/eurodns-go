package rrset

import (
	"testing"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[[2]string]string{
		{"", "example.com"}:                 "@",
		{"@", "example.com"}:                "@",
		{"example.com.", "example.com"}:     "@",
		{"WWW", "example.com"}:              "www",
		{"www.example.com.", "Example.COM"}: "www",
		{"a.b", "example.com"}:              "a.b",
		{"a.b.", ""}:                        "a.b",
	}
	for in, want := range cases {
		if got := NormalizeHost(in[0], in[1]); got != want {
			t.Errorf("NormalizeHost(%q,%q)=%q want %q", in[0], in[1], got, want)
		}
	}
}

func TestMatchHost(t *testing.T) {
	cases := []struct {
		p, h string
		ok   bool
	}{
		{"@", "@", true},
		{"@", "www", false},
		{"*", "@", false},
		{"**", "@", false},
		{"*", "www", true},
		{"*", "a.b", false},
		{"**", "a.b.c", true},
		{"*.staging", "app.staging", true},
		{"*.staging", "a.app.staging", false},
		{"**.staging", "a.app.staging", true},
		{"**.staging", "staging", false},
		{"_*.staging", "_acme-challenge.staging", true},
		{"_*.staging", "acme.staging", false},
		{"_acme-challenge.**", "_acme-challenge.www", true},
		{"_acme-challenge", "_acme-challenge", true},
		{"Www", "www", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	}
	for _, c := range cases {
		if got := MatchHost(c.p, c.h); got != c.ok {
			t.Errorf("MatchHost(%q,%q)=%v want %v", c.p, c.h, got, c.ok)
		}
	}
}

func TestGroupAndHash(t *testing.T) {
	recs := []eurodns.Record{
		{Type: "a", Host: "www", TTL: 600, RData: "192.0.2.2"},
		{Type: "MX", Host: "", TTL: 3600, RData: "10 mx"},
		{Type: "A", Host: "WWW.example.com.", TTL: 600, RData: "192.0.2.1"},
	}
	g := Group("example.com", recs)
	s := g[Key{Host: "www", Type: "A"}]
	if len(g) != 2 || len(s.Records) != 2 || s.Values[0] != "192.0.2.1" || s.Records[0].RData != "192.0.2.2" {
		t.Fatalf("bad grouping: %+v", g)
	}
	if _, ok := g[Key{Host: "@", Type: "MX"}]; !ok {
		t.Fatal("apex MX missing")
	}
	h1 := ContentHash(s)
	s2 := Set{TTL: 600, Values: []string{"192.0.2.2", "192.0.2.1"}}
	if ContentHash(s2) != h1 {
		t.Fatal("hash must not depend on value order or records")
	}
	s2.TTL = 900
	if ContentHash(s2) == h1 {
		t.Fatal("hash must depend on TTL")
	}
	if ContentHash(Set{Values: []string{"ab", "c"}}) == ContentHash(Set{Values: []string{"a", "bc"}}) {
		t.Fatal("hash must be unambiguous")
	}
	keys := SortedKeys(g)
	if keys[0].Host != "@" {
		t.Fatalf("keys not sorted: %v", keys)
	}
}

func TestFQDNHelpers(t *testing.T) {
	for typ, want := range map[string]bool{"CNAME": true, "mx": true, "NS": true, "SRV": true, "PTR": true, "APEX": true, "DS": false, "TXT": false, "A": false} {
		if NeedsFQDN(typ) != want {
			t.Errorf("NeedsFQDN(%s) != %v", typ, want)
		}
	}
	cases := [][3]string{
		{"MX", "10 mail.example.net.", "mail.example.net."},
		{"SRV", "10 5 5060 sip.example.com", "sip.example.com"},
		{"CNAME", " target.example.net ", "target.example.net"},
		{"TXT", "v=spf1 -all", ""},
		{"MX", "", ""},
	}
	for _, c := range cases {
		if got := TargetOf(c[0], c[1]); got != c[2] {
			t.Errorf("TargetOf(%s,%q)=%q want %q", c[0], c[1], got, c[2])
		}
	}
	tr := true
	if !ServerManaged(eurodns.Record{Type: "soa"}) || !ServerManaged(eurodns.Record{Type: "NS", Locked: &tr}) || ServerManaged(eurodns.Record{Type: "NS"}) {
		t.Fatal("ServerManaged")
	}
}
