package eurodns

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestZoneJSONRoundTripKeepsUnknownFields(t *testing.T) {
	in := `{"name":"example.com","domainConnect":false,"futureZoneField":{"a":1},
	"records":[{"id":12,"type":"A","host":"www","ttl":600,"rdata":"192.0.2.1","proxy":"OFF","futureRecordField":[1,2]}],
	"urlForwards":[{"id":3,"host":"go","url":"https://example.net","forwardType":"PERMANENT","futureFwd":true}],
	"mailForwards":[{"source":"*","destination":"ops@example.net"}]}`
	var z Zone
	if err := json.Unmarshal([]byte(in), &z); err != nil {
		t.Fatal(err)
	}
	if string(z.Extra["futureZoneField"]) != `{"a":1}` {
		t.Fatalf("zone extra lost: %v", z.Extra)
	}
	if string(z.Records[0].Extra["futureRecordField"]) != `[1,2]` {
		t.Fatalf("record extra lost: %v", z.Records[0].Extra)
	}
	out, err := json.Marshal(z)
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	_ = json.Unmarshal([]byte(in), &a)
	_ = json.Unmarshal(out, &b)
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatalf("round trip differs:\n in=%s\nout=%s", aj, bj)
	}
	if !strings.Contains(string(out), `"futureFwd":true`) {
		t.Fatalf("forward not preserved raw: %s", out)
	}
}

func TestZoneJSONNilSlicesAsEmptyArrays(t *testing.T) {
	out, err := json.Marshal(Zone{Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{`"records":[]`, `"urlForwards":[]`, `"mailForwards":[]`} {
		if !strings.Contains(string(out), f) {
			t.Errorf("missing %s in %s", f, out)
		}
	}
	if strings.Contains(string(out), "ETag") || strings.Contains(string(out), "Extra") {
		t.Errorf("internal fields serialized: %s", out)
	}
}

func TestExtraDoesNotOverrideKnownFields(t *testing.T) {
	r := Record{Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1",
		Extra: map[string]json.RawMessage{"rdata": json.RawMessage(`"evil"`), "x": json.RawMessage(`1`)}}
	out, _ := json.Marshal(r)
	if strings.Contains(string(out), "evil") || !strings.Contains(string(out), `"x":1`) {
		t.Fatalf("unexpected: %s", out)
	}
}

func TestReportProblemsFromRealFormat(t *testing.T) {
	in := `{"isValid":false,"recordErrors":[{"messages":["\"601\" is not a valid TTL"],"record":{"id":1,"type":"A","host":"www","ttl":601,"rdata":"192.0.2.1"},"severity":"ERROR"}],
	"urlForwardErrors":[],"mailForwardErrors":[],
	"zoneErrors":[{"message":"An ending dot or a corresponding record in the zone is required","records":[{"type":"CNAME","host":"app","ttl":600,"rdata":"x"},{"type":"MX","host":"","ttl":600,"rdata":"10 y"}],"urlForwards":[],"mailForwards":[],"severity":"WARNING"}]}`
	var r ValidationReport
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	p := r.Problems()
	if len(p) != 3 || p[0].Severity != SeverityError || p[0].Host != "www" || p[1].Type != "CNAME" || p[2].Severity != SeverityWarning {
		t.Fatalf("problems: %+v", p)
	}
	if r.Valid() || len(r.Errors()) != 1 {
		t.Fatal("report with an ERROR must be invalid")
	}
	out, _ := json.Marshal(r)
	if !strings.Contains(string(out), `"severity":"WARNING"`) || !strings.Contains(string(out), `"rdata":"10 y"`) {
		t.Fatalf("raw entries not preserved: %s", out)
	}
	var nilReport *ValidationReport
	if !nilReport.Valid() || nilReport.Problems() != nil {
		t.Fatal("nil report is valid")
	}
}
