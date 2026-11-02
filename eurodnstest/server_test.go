package eurodnstest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

func TestReassignIDsAndRateLimit(t *testing.T) {
	s := NewServer(Options{ReassignIDsOnSave: true, RateLimit: 2, RateWindow: time.Hour})
	defer s.Close()
	s.Seed(&eurodns.Zone{Name: "example.com", Records: []eurodns.Record{{Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"}}})
	z := s.Zone("example.com")
	before := *z.Records[len(z.Records)-1].ID

	req, _ := http.NewRequest(http.MethodPut, s.URL+"/dns-zones/example.com",
		bytes.NewReader([]byte(`{"records":[{"id":1,"type":"A","host":"www","ttl":600,"rdata":"192.0.2.1"}]}`)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("save: %v %v", resp, err)
	}
	z = s.Zone("example.com")
	if after := *z.Records[len(z.Records)-1].ID; after == before || after == 1 {
		t.Fatalf("ids not reassigned: %d -> %d", before, after)
	}
	resp, _ = http.Get(s.URL + "/dns-zones/example.com")
	resp.Body.Close()
	resp, _ = http.Get(s.URL + "/dns-zones/example.com")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || s.Rejected() != 1 || s.Requests() != 3 {
		t.Fatalf("rate limit: status %d rejected %d requests %d", resp.StatusCode, s.Rejected(), s.Requests())
	}
}

func TestGateEndpointIsNotFoundAndCNAMEConflict(t *testing.T) {
	s := NewServer(Options{})
	defer s.Close()
	s.Seed(&eurodns.Zone{Name: "example.com", Records: []eurodns.Record{{Type: "A", Host: "app", TTL: 600, RData: "192.0.2.1"}}})
	resp, _ := http.Get(s.URL + eurodns.GateInfoPath)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("well-known: %d", resp.StatusCode)
	}
	resp, _ = http.Post(s.URL+"/dns-zones/example.com/dns-records", "application/json",
		bytes.NewReader([]byte(`[{"type":"CNAME","host":"app","ttl":600,"rdata":"x.example.net."}]`)))
	if resp.StatusCode != http.StatusBadRequest || len(s.Zone("example.com").Records) != 6 {
		t.Fatalf("CNAME conflict accepted: %d", resp.StatusCode)
	}
}

func TestManagedRecordsSerialSnapshotsAndIDs(t *testing.T) {
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	s := NewServer(Options{Now: func() time.Time { return now }})
	defer s.Close()
	s.Seed(&eurodns.Zone{Name: "example.com", Records: []eurodns.Record{{Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"}}})
	z := s.Zone("example.com")
	if len(z.Records) != 6 || z.Records[0].Type != "SOA" || z.Records[0].Locked == nil || !*z.Records[0].Locked {
		t.Fatalf("seed must add locked SOA and NS: %+v", z.Records)
	}
	if s.Serial("example.com") != 2026110201 {
		t.Fatalf("serial: %d", s.Serial("example.com"))
	}
	wwwID := *z.Records[5].ID
	put := func(body string) int {
		req, _ := http.NewRequest(http.MethodPut, s.URL+"/dns-zones/example.com", bytes.NewReader([]byte(body)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// The client drops SOA/NS and modifies www: managed records survive, id kept.
	for i := 0; i < 7; i++ {
		body := fmt.Sprintf(`{"records":[{"id":%d,"type":"A","host":"www","ttl":600,"rdata":"192.0.2.%d"},
			{"type":"MX","host":"","ttl":3600,"rdata":"10 mail"},{"type":"TXT","host":"t","ttl":600,"rdata":"\"quoted\""}]}`, wwwID, i+2)
		if code := put(body); code != http.StatusNoContent {
			t.Fatalf("put %d: %d", i, code)
		}
	}
	z = s.Zone("example.com")
	if len(z.Records) != 8 || z.Records[0].Type != "SOA" || z.Records[1].Type != "NS" {
		t.Fatalf("managed records lost: %+v", z.Records)
	}
	byType := map[string]eurodns.Record{}
	for _, r := range z.Records {
		byType[r.Type] = r
	}
	if *byType["A"].ID != wwwID || byType["A"].RData != "192.0.2.8" {
		t.Fatalf("modified record must keep its id: %+v", byType["A"])
	}
	if byType["MX"].RData != "10 mail.example.com." || byType["TXT"].RData != `"quoted"` {
		t.Fatalf("qualify/TXT: %q %q", byType["MX"].RData, byType["TXT"].RData)
	}
	if s.Serial("example.com") != 2026110208 {
		t.Fatalf("serial must be bumped on every write: %d", s.Serial("example.com"))
	}
	resp, _ := http.Get(s.URL + "/dns-zones/example.com/snapshots")
	var snaps []eurodns.Snapshot
	_ = json.NewDecoder(resp.Body).Decode(&snaps)
	resp.Body.Close()
	if len(snaps) != MaxSnapshots {
		t.Fatalf("snapshots: %d", len(snaps))
	}
	req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/dns-zones/example.com/dns-records/%d", s.URL, *z.Records[0].ID), nil)
	resp, _ = http.DefaultClient.Do(req)
	var e struct {
		Errors []struct{ Code string } `json:"errors"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || len(e.Errors) != 1 || e.Errors[0].Code != "FORBIDDEN_ACTION" {
		t.Fatalf("deleting the SOA must be forbidden: %d %+v", resp.StatusCode, e)
	}
}
