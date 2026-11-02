package eurodns_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

func seeded(t *testing.T, opts eurodnstest.Options) *eurodnstest.Server {
	t.Helper()
	srv := eurodnstest.NewServer(opts)
	t.Cleanup(srv.Close)
	srv.Seed(&eurodns.Zone{Name: "example.com", Records: []eurodns.Record{
		{Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"},
		{Type: "MX", Host: "@", TTL: 3600, RData: "10 mail.example.net."},
	}})
	return srv
}

// userRecords drops server-managed records (SOA, locked apex NS).
func userRecords(z *eurodns.Zone) []eurodns.Record {
	var out []eurodns.Record
	for _, r := range z.Records {
		if !rrset.ServerManaged(r) {
			out = append(out, r)
		}
	}
	return out
}

func indexOf(z *eurodns.Zone, host, typ string) int {
	for i, r := range z.Records {
		if r.Host == host && r.Type == typ {
			return i
		}
	}
	return -1
}

func fastClient(t *testing.T, base string, extra ...eurodns.Option) *eurodns.Client {
	t.Helper()
	opts := append([]eurodns.Option{
		eurodns.WithBaseURL(base),
		eurodns.WithAuth(eurodns.APIKeyAuth{AppID: "app", APIKey: "key"}),
		eurodns.WithRateLimit(time.Millisecond, 100),
		eurodns.WithRetryBackoff(5*time.Millisecond, 20*time.Millisecond),
	}, extra...)
	c, err := eurodns.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestZoneLifecycle(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{AppID: "app", APIKey: "key"})
	c := fastClient(t, srv.URL)
	ctx := context.Background()

	z, err := c.GetZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(userRecords(z)) != 2 || len(z.Records) != 7 || z.Records[0].ID == nil {
		t.Fatalf("unexpected zone: %+v", z)
	}
	if z.ETag != "" {
		t.Fatalf("plain EuroDNS returns no ETag, got %q", z.ETag)
	}

	z2, err := c.AddRecords(ctx, "example.com", []eurodns.Record{{Type: "TXT", Host: "_acme-challenge", TTL: 600, RData: `"token"`}})
	if err != nil {
		t.Fatal(err)
	}
	if len(userRecords(z2)) != 3 {
		t.Fatalf("want 3 records, got %d", len(userRecords(z2)))
	}
	id := *z2.Records[indexOf(z2, "_acme-challenge", "TXT")].ID
	if _, err := c.DeleteRecord(ctx, "example.com", id); err != nil {
		t.Fatal(err)
	}
	if got := len(userRecords(srv.Zone("example.com"))); got != 2 {
		t.Fatalf("want 2 records after delete, got %d", got)
	}

	www := indexOf(z, "www", "A")
	wwwID := *z.Records[www].ID
	serial := srv.Serial("example.com")
	z.Records[www].RData = "192.0.2.2"
	z.Records = append(z.Records, eurodns.Record{Type: "CNAME", Host: "app", TTL: 600, RData: "www"})
	if err := c.SaveZone(ctx, "example.com", z); err != nil {
		t.Fatal(err)
	}
	after := srv.Zone("example.com")
	if r := after.Records[indexOf(after, "www", "A")]; r.RData != "192.0.2.2" || *r.ID != wwwID {
		t.Fatalf("save not applied or id not kept: %+v", r)
	}
	if r := after.Records[indexOf(after, "app", "CNAME")]; r.RData != "www.example.com." || r.ID == nil {
		t.Fatalf("CNAME target not qualified or no id: %+v", r)
	}
	if srv.Serial("example.com") <= serial {
		t.Fatal("SOA serial not bumped")
	}
	snaps, err := c.ListSnapshots(ctx, "example.com")
	if err != nil || len(snaps) != 3 {
		t.Fatalf("snapshots: %v %v", snaps, err)
	}
}

func TestCheckZoneReportsInvalidTTL(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{})
	c := fastClient(t, srv.URL)
	z, _ := c.GetZone(context.Background(), "example.com")
	z.Records[indexOf(z, "www", "A")].TTL = 601
	out, err := c.CheckZone(context.Background(), "example.com", z)
	if err != nil {
		t.Fatal(err)
	}
	if out.Report.Valid() || len(out.Report.RecordErrors) != 1 {
		t.Fatalf("expected invalid report, got %+v", out.Report)
	}
	if p := out.Report.Errors(); len(p) != 1 || p[0].Message != `"601" is not a valid TTL` || p[0].Host != "www" {
		t.Fatalf("problems: %+v", p)
	}
	err = c.SaveZone(context.Background(), "example.com", z)
	var ae *eurodns.APIError
	if !errors.As(err, &ae) || ae.StatusCode != 400 || ae.Code == "" {
		t.Fatalf("expected 400 with code, got %v", err)
	}
}

func TestCheckZoneWarnsOnMissingEndingDot(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{})
	c := fastClient(t, srv.URL)
	z, _ := c.GetZone(context.Background(), "example.com")
	z.Records = append(z.Records, eurodns.Record{Type: "CNAME", Host: "app", TTL: 600, RData: "target.example.net"})
	out, err := c.CheckZone(context.Background(), "example.com", z)
	if err != nil {
		t.Fatal(err)
	}
	p := out.Report.Problems()
	if !out.Report.Valid() || len(p) != 1 || p[0].Severity != eurodns.SeverityWarning || p[0].Host != "app" {
		t.Fatalf("expected one warning, got %+v", p)
	}
	if err := c.SaveZone(context.Background(), "example.com", z); err != nil {
		t.Fatalf("warnings must not block the save: %v", err)
	}
}

func TestBadCredentials(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{AppID: "app", APIKey: "other"})
	c := fastClient(t, srv.URL)
	_, err := c.GetZone(context.Background(), "example.com")
	var ae *eurodns.APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusUnauthorized || ae.Code != "INVALID_API_KEY" {
		t.Fatalf("want 401 INVALID_API_KEY, got %v", err)
	}
	if !eurodns.IsNotFound(fastGet(t, srv.URL, "missing.example")) {
		t.Fatal("IsNotFound should match")
	}
}

func fastGet(t *testing.T, base, domain string) error {
	c, _ := eurodns.New(eurodns.WithBaseURL(base), eurodns.WithAuth(eurodns.APIKeyAuth{AppID: "app", APIKey: "other"}))
	_, err := c.GetZone(context.Background(), domain)
	return err
}

func TestEuroDNSErrorFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":[{"status":"403","code":"FORBIDDEN_ACTION","title":"You are not allowed to do this","meta":null}]}`))
	}))
	defer srv.Close()
	_, err := fastClient(t, srv.URL).GetZone(context.Background(), "example.com")
	var ae *eurodns.APIError
	if !errors.As(err, &ae) || !eurodns.IsForbidden(err) || ae.Code != "FORBIDDEN_ACTION" ||
		ae.Message != "You are not allowed to do this" || len(ae.Errors) != 1 {
		t.Fatalf("error not parsed: %#v", err)
	}
	if !strings.Contains(err.Error(), "FORBIDDEN_ACTION") {
		t.Fatalf("message: %v", err)
	}
}

func TestGateInfo(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{})
	if _, err := fastClient(t, srv.URL).GateInfo(context.Background()); !errors.Is(err, eurodns.ErrNotGate) {
		t.Fatalf("plain EuroDNS: want ErrNotGate, got %v", err)
	}
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != eurodns.GateInfoPath {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"version":"0.1.0","features":["if-match","ownership"]}`))
	}))
	defer gate.Close()
	gi, err := fastClient(t, gate.URL).GateInfo(context.Background())
	if err != nil || !gi.HasFeature(eurodns.FeatureOwnership) || gi.HasFeature(eurodns.FeatureAdopt) {
		t.Fatalf("gate info: %+v %v", gi, err)
	}
}

func TestGateHeadersAndErrors(t *testing.T) {
	var gotAuth, gotIfMatch, gotKey atomic.Value
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotKey.Store(r.Header.Get("X-API-KEY"))
		gotIfMatch.Store(r.Header.Get("If-Match"))
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", `"v7"`)
			w.Write([]byte(`{"name":"example.com","records":[]}`))
		case http.MethodPut:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			w.Write([]byte(`{"reason":"precondition","message":"zone changed"}`))
		case http.MethodPost:
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"reason":"foreign_rrset","message":"www/A is not managed"}`))
		}
	}))
	defer gate.Close()
	c, _ := eurodns.New(eurodns.WithBaseURL(gate.URL), eurodns.WithAuth(eurodns.BearerAuth{Source: eurodns.StaticToken("jwt")}),
		eurodns.WithRateLimit(time.Millisecond, 10))
	ctx := context.Background()
	z, err := c.GetZone(ctx, "example.com")
	if err != nil || z.ETag != `"v7"` {
		t.Fatalf("etag: %+v %v", z, err)
	}
	if gotAuth.Load() != "Bearer jwt" || gotKey.Load() != "" {
		t.Fatalf("bad auth headers: %v %v", gotAuth.Load(), gotKey.Load())
	}
	err = c.SaveZone(ctx, "example.com", z, eurodns.WithIfMatch(z.ETag))
	if !eurodns.IsPreconditionFailed(err) || gotIfMatch.Load() != `"v7"` {
		t.Fatalf("want 412 with If-Match, got %v / %v", err, gotIfMatch.Load())
	}
	_, err = c.AddRecords(ctx, "example.com", nil)
	var ae *eurodns.APIError
	if !errors.As(err, &ae) || ae.Reason != "foreign_rrset" || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("reason not parsed: %v", err)
	}
	if err := c.Adopt(ctx, "example.com", eurodns.AdoptRequest{}); err == nil {
		t.Fatal("adopt should surface the 409")
	}
}

func TestRetryOn429ThenSuccess(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"name":"example.com","records":[]}`))
	}))
	defer srv.Close()
	c := fastClient(t, srv.URL)
	if _, err := c.AddRecords(context.Background(), "example.com", []eurodns.Record{{Type: "A", Host: "x", TTL: 600, RData: "192.0.2.9"}}); err != nil {
		t.Fatalf("POST should be retried on 429: %v", err)
	}
	if n.Load() != 3 {
		t.Fatalf("want 3 attempts, got %d", n.Load())
	}
}

func TestNoRetryOf5xxForWrites(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := fastClient(t, srv.URL)
	_ = c.SaveZone(context.Background(), "example.com", &eurodns.Zone{})
	if n.Load() != 1 {
		t.Fatalf("PUT must not be retried on 5xx, got %d attempts", n.Load())
	}
	n.Store(0)
	_, _ = c.GetZone(context.Background(), "example.com")
	if n.Load() != 5 {
		t.Fatalf("GET should be retried 4 times, got %d attempts", n.Load())
	}
}

func TestTransportRespectsRateLimit(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{RateLimit: 3, RateWindow: 300 * time.Millisecond})
	c, _ := eurodns.New(eurodns.WithBaseURL(srv.URL), eurodns.WithRateLimit(110*time.Millisecond, 1),
		eurodns.WithRetryBackoff(time.Millisecond, time.Millisecond), eurodns.WithMaxRetries(0))
	for i := 0; i < 8; i++ {
		if _, err := c.GetZone(context.Background(), "example.com"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if srv.Rejected() != 0 {
		t.Fatalf("limiter let %d requests be rejected", srv.Rejected())
	}
}

func TestSharedTransportAndContextCancel(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{})
	c1 := fastClient(t, srv.URL)
	c2, _ := eurodns.New(eurodns.WithBaseURL(srv.URL), eurodns.WithTransport(c1.Transport()))
	if c2.Transport() != c1.Transport() {
		t.Fatal("transport not shared")
	}
	if _, err := c2.GetZone(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	slow, _ := eurodns.New(eurodns.WithBaseURL(srv.URL), eurodns.WithRateLimit(time.Hour, 1))
	_, _ = slow.GetZone(context.Background(), "example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := slow.GetZone(ctx, "example.com"); err == nil {
		t.Fatal("expected context error while waiting for the limiter")
	}
}

func TestTransportBehindReverseProxy(t *testing.T) {
	srv := seeded(t, eurodnstest.Options{AppID: "app", APIKey: "key"})
	up, _ := url.Parse(srv.URL)
	rp := httputil.NewSingleHostReverseProxy(up)
	rp.Transport = eurodns.NewTransport(eurodns.WithAuth(eurodns.APIKeyAuth{AppID: "app", APIKey: "key"}),
		eurodns.WithRateLimit(time.Millisecond, 10))
	front := httptest.NewServer(rp)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/dns-zones/example.com/dns-records",
		strings.NewReader(`[{"type":"TXT","host":"t","ttl":600,"rdata":"\"x\""}]`))
	req.Header.Set("Authorization", "Bearer client-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || len(userRecords(srv.Zone("example.com"))) != 3 {
		t.Fatalf("proxied write failed: %d", resp.StatusCode)
	}
}
