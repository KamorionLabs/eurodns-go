// Package eurodnstest provides an in-memory fake of the EuroDNS DNS zone API
// for tests (records, ids, forwards, check, snapshots, rate limiting).
package eurodnstest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

// Options configures the fake.
type Options struct {
	AppID, APIKey string        // required headers; empty disables the check
	RateLimit     int           // max requests per RateWindow; 0 disables
	RateWindow    time.Duration // default 10s
	// ReassignIDsOnSave renumbers every record on PUT. EuroDNS keeps ids
	// (default false); kept to test clients that must not rely on ids.
	ReassignIDsOnSave bool
	// Now overrides the clock used for SOA serials and snapshots.
	Now func() time.Time
}

// MaxSnapshots is the number of snapshots EuroDNS keeps per zone.
const MaxSnapshots = 5

// Apex nameservers and SOA created by Seed when the zone has none.
var (
	DefaultNameservers = []string{"ns1.example.net.", "ns2.example.net.", "ns3.example.net.", "ns4.example.net."}
	soaTemplate        = "ns1.example.net. hostmaster.example.net. %d 86400 7200 604800 600"
)

// Server is a running fake.
type Server struct {
	*httptest.Server

	opts Options

	mu        sync.Mutex
	zones     map[string]*eurodns.Zone
	snapshots map[string][]snapshot
	nextID    int64
	nextSnap  int64
	requests  int
	rejected  int
	window    []time.Time
}

type snapshot struct {
	meta eurodns.Snapshot
	zone *eurodns.Zone
}

// NewServer starts a fake. Callers must Close it.
func NewServer(opts Options) *Server {
	if opts.RateWindow <= 0 {
		opts.RateWindow = 10 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Server{
		opts:      opts,
		zones:     map[string]*eurodns.Zone{},
		snapshots: map[string][]snapshot{},
		nextID:    1000,
		nextSnap:  1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dns-zones/{domain}", s.getZone)
	mux.HandleFunc("PUT /dns-zones/{domain}", s.saveZone)
	mux.HandleFunc("POST /dns-zones/{domain}/check", s.checkZone)
	mux.HandleFunc("POST /dns-zones/{domain}/dns-records", s.addRecords)
	mux.HandleFunc("DELETE /dns-zones/{domain}/dns-records/{id}", s.deleteRecord)
	mux.HandleFunc("GET /dns-zones/{domain}/snapshots", s.listSnapshots)
	mux.HandleFunc("GET /dns-zones/{domain}/snapshots/{id}", s.getSnapshot)
	s.Server = httptest.NewServer(s.middleware(mux))
	return s
}

// Seed creates or replaces a zone. Records without id get one. Like
// EuroDNS, the zone gets a locked apex SOA and locked apex NS records when it
// has none; seeded SOA and apex NS records are marked locked.
func (s *Server) Seed(z *eurodns.Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := clone(z)
	t := true
	var hasSOA, hasNS bool
	for i := range c.Records {
		r := &c.Records[i]
		apex := rrset.NormalizeHost(r.Host, c.Name) == rrset.Apex
		switch strings.ToUpper(r.Type) {
		case "SOA":
			hasSOA, r.Locked = true, &t
		case "NS":
			if apex {
				hasNS, r.Locked = true, &t
			}
		}
		if r.ID == nil {
			r.ID = s.newID()
		}
	}
	var managed []eurodns.Record
	if !hasSOA {
		managed = append(managed, eurodns.Record{ID: s.newID(), Type: "SOA", Host: "", TTL: 86400,
			RData: fmt.Sprintf(soaTemplate, s.serialFor(0)), Locked: &t})
	}
	if !hasNS {
		for _, ns := range DefaultNameservers {
			managed = append(managed, eurodns.Record{ID: s.newID(), Type: "NS", Host: "", TTL: 86400, RData: ns, Locked: &t})
		}
	}
	c.Records = append(managed, c.Records...)
	c.Report = nil
	s.zones[strings.ToLower(c.Name)] = c
}

// Zone returns a copy of the stored zone, nil if absent.
func (s *Server) Zone(domain string) *eurodns.Zone {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zones[strings.ToLower(domain)]
	if !ok {
		return nil
	}
	return clone(z)
}

// Requests returns the number of requests served (for rate tests).
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// Rejected returns the number of requests refused with 429.
func (s *Server) Rejected() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejected
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests++
		if s.opts.RateLimit > 0 {
			now := time.Now()
			cut := now.Add(-s.opts.RateWindow)
			i := 0
			for i < len(s.window) && s.window[i].Before(cut) {
				i++
			}
			s.window = append(s.window[i:], now)
			if len(s.window) > s.opts.RateLimit {
				s.rejected++
				s.mu.Unlock()
				writeErr(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many requests")
				return
			}
		}
		s.mu.Unlock()
		if s.opts.AppID != "" || s.opts.APIKey != "" {
			appID, key := r.Header.Get("X-APP-ID"), r.Header.Get("X-API-KEY")
			if appID == "" || key == "" {
				writeErr(w, http.StatusUnauthorized, "API_KEY_REQUIRED", "An API key is required")
				return
			}
			if appID != s.opts.AppID || key != s.opts.APIKey {
				writeErr(w, http.StatusUnauthorized, "INVALID_API_KEY", "Invalid API key")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getZone(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, z)
}

func (s *Server) saveZone(w http.ResponseWriter, r *http.Request) {
	var in eurodns.Zone
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(w, r)
	if !ok {
		return
	}
	recs := s.merge(z, in.Records)
	if rep := validate(z.Name, recs); !rep.Valid() {
		writeErr(w, http.StatusBadRequest, "INVALID_DNS_ZONE", firstError(rep))
		return
	}
	known := map[int64]bool{}
	for _, rec := range z.Records {
		if rec.ID != nil {
			known[*rec.ID] = true
		}
	}
	seen := map[int64]bool{}
	for i := range recs {
		rec := &recs[i]
		if rrset.ServerManaged(*rec) {
			continue
		}
		if s.opts.ReassignIDsOnSave || rec.ID == nil || !known[*rec.ID] || seen[*rec.ID] {
			rec.ID = s.newID()
		}
		seen[*rec.ID] = true
		rec.Updated = nil
	}
	next := clone(&in)
	next.Name = z.Name
	next.Report = nil
	next.Records = recs
	if next.DomainConnect == nil {
		next.DomainConnect = z.DomainConnect
	}
	s.store(next)
	w.WriteHeader(http.StatusNoContent)
}

// merge returns the zone's server-managed records followed by the client
// records, dropping client SOA/locked records and qualifying targets.
func (s *Server) merge(z *eurodns.Zone, client []eurodns.Record) []eurodns.Record {
	var out []eurodns.Record
	for _, rec := range z.Records {
		if rrset.ServerManaged(rec) {
			out = append(out, rec)
		}
	}
	for _, rec := range client {
		if rrset.ServerManaged(rec) {
			continue
		}
		rec.Locked = nil
		rec.RData = qualify(z.Name, rec.Type, rec.RData)
		out = append(out, rec)
	}
	return out
}

func (s *Server) checkZone(w http.ResponseWriter, r *http.Request) {
	var in eurodns.Zone
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(w, r)
	if !ok {
		return
	}
	in.Name = z.Name
	in.Report = validate(z.Name, in.Records)
	t := true
	for i := range in.Records {
		rec := &in.Records[i]
		if q := qualify(z.Name, rec.Type, rec.RData); q != rec.RData {
			rec.RData, rec.Updated = q, &t
		}
	}
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) addRecords(w http.ResponseWriter, r *http.Request) {
	var in []eurodns.Record
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(w, r)
	if !ok {
		return
	}
	next := clone(z)
	for _, rec := range in {
		if strings.EqualFold(rec.Type, "SOA") {
			writeErr(w, http.StatusForbidden, "FORBIDDEN_ACTION", "You are not allowed to do this")
			return
		}
		rec.ID = s.newID()
		rec.Updated, rec.Locked = nil, nil
		rec.RData = qualify(z.Name, rec.Type, rec.RData)
		next.Records = append(next.Records, rec)
	}
	if rep := validate(z.Name, next.Records); !rep.Valid() {
		writeErr(w, http.StatusBadRequest, "INVALID_DNS_ZONE", firstError(rep))
		return
	}
	s.store(next)
	writeJSON(w, http.StatusOK, next)
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_PARAMETER", "Invalid record id")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(w, r)
	if !ok {
		return
	}
	next := clone(z)
	idx := slices.IndexFunc(next.Records, func(rec eurodns.Record) bool { return rec.ID != nil && *rec.ID == id })
	if idx < 0 {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Record not found")
		return
	}
	if rrset.ServerManaged(next.Records[idx]) {
		writeErr(w, http.StatusForbidden, "FORBIDDEN_ACTION", "You are not allowed to do this")
		return
	}
	next.Records = slices.Delete(next.Records, idx, idx+1)
	s.store(next)
	writeJSON(w, http.StatusOK, next)
}

func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(w, r)
	if !ok {
		return
	}
	out := []eurodns.Snapshot{}
	for _, sn := range s.snapshots[strings.ToLower(z.Name)] {
		out = append(out, sn.meta)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getSnapshot(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(w, r)
	if !ok {
		return
	}
	for _, sn := range s.snapshots[strings.ToLower(z.Name)] {
		if sn.meta.ID == id {
			writeJSON(w, http.StatusOK, sn.zone)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "NOT_FOUND", "Snapshot not found")
}

// zone returns the stored zone for the request; caller holds the lock.
func (s *Server) zone(w http.ResponseWriter, r *http.Request) (*eurodns.Zone, bool) {
	z, ok := s.zones[strings.ToLower(r.PathValue("domain"))]
	if !ok {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "DNS zone not found")
		return nil, false
	}
	return z, true
}

// store saves a zone, bumps its SOA serial and records a snapshot; caller
// holds the lock.
func (s *Server) store(z *eurodns.Zone) {
	for i := range z.Records {
		if strings.EqualFold(z.Records[i].Type, "SOA") {
			z.Records[i].RData = s.bumpSerial(z.Records[i].RData)
		}
	}
	key := strings.ToLower(z.Name)
	s.zones[key] = z
	sn := snapshot{
		meta: eurodns.Snapshot{ID: s.nextSnap, CreatedAt: s.opts.Now().UTC().Format(time.RFC3339), ZoneName: z.Name},
		zone: clone(z),
	}
	s.nextSnap++
	list := append(s.snapshots[key], sn)
	if len(list) > MaxSnapshots {
		list = list[len(list)-MaxSnapshots:]
	}
	s.snapshots[key] = list
}

// serialFor returns the next YYYYMMDDnn serial after prev.
func (s *Server) serialFor(prev int64) int64 {
	t := s.opts.Now().UTC()
	today := int64(t.Year()*10000+int(t.Month())*100+t.Day()) * 100
	if prev < today+1 {
		return today + 1
	}
	return prev + 1
}

func (s *Server) bumpSerial(rdata string) string {
	f := strings.Fields(rdata)
	if len(f) < 3 {
		return rdata
	}
	prev, _ := strconv.ParseInt(f[2], 10, 64)
	f[2] = strconv.FormatInt(s.serialFor(prev), 10)
	return strings.Join(f, " ")
}

// Serial returns the current SOA serial of a zone, 0 if none.
func (s *Server) Serial(domain string) int64 {
	z := s.Zone(domain)
	if z == nil {
		return 0
	}
	for _, r := range z.Records {
		if strings.EqualFold(r.Type, "SOA") {
			if f := strings.Fields(r.RData); len(f) >= 3 {
				n, _ := strconv.ParseInt(f[2], 10, 64)
				return n
			}
		}
	}
	return 0
}

// qualify appends the zone name to a target without ending dot, as EuroDNS
// does for CNAME, MX, NS, SRV, PTR and APEX.
func qualify(zone, typ, rdata string) string {
	target := rrset.TargetOf(typ, rdata)
	if target == "" || strings.HasSuffix(target, ".") {
		return rdata
	}
	full := target + "." + strings.TrimSuffix(zone, ".") + "."
	return strings.TrimSuffix(rdata, target) + full
}

func (s *Server) newID() *int64 {
	s.nextID++
	id := s.nextID
	return &id
}

var validTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "PTR": true, "SOA": true,
	"SRV": true, "TXT": true, "SPF": true, "CAA": true, "APEX": true, "TLSA": true, "MAIL": true,
	"URL": true, "SVCB": true, "HTTPS": true, "DS": true,
}

// validate returns the check report: ERROR record errors (type, TTL, empty
// rdata, CNAME conflict) and WARNING zone errors for targets without ending
// dot that do not match a host of the zone.
func validate(zone string, recs []eurodns.Record) *eurodns.ValidationReport {
	var errs, zoneErrs []json.RawMessage
	add := func(r eurodns.Record, msg string) {
		b, _ := json.Marshal(eurodns.RecordError{Messages: []string{msg}, Record: &r, Severity: eurodns.SeverityError})
		errs = append(errs, b)
	}
	cname := map[string]int{}
	other := map[string]int{}
	hosts := map[string]bool{}
	for _, r := range recs {
		hosts[rrset.NormalizeHost(r.Host, zone)] = true
	}
	var dotless []eurodns.Record
	for _, r := range recs {
		if !validTypes[strings.ToUpper(r.Type)] {
			add(r, fmt.Sprintf("%q is not a valid record type", r.Type))
		}
		if !slices.Contains(eurodns.AllowedTTLs, r.TTL) {
			add(r, fmt.Sprintf("%q is not a valid TTL", strconv.Itoa(r.TTL)))
		}
		if strings.TrimSpace(r.RData) == "" {
			add(r, "rdata is required")
		}
		if t := rrset.TargetOf(r.Type, r.RData); t != "" && !strings.HasSuffix(t, ".") && !hosts[rrset.NormalizeHost(t, zone)] {
			dotless = append(dotless, r)
		}
		h := rrset.NormalizeHost(r.Host, zone)
		if strings.EqualFold(r.Type, "CNAME") {
			cname[h]++
		} else {
			other[h]++
		}
	}
	for _, r := range recs {
		h := rrset.NormalizeHost(r.Host, zone)
		if strings.EqualFold(r.Type, "CNAME") && (cname[h] > 1 || other[h] > 0) {
			add(r, "A CNAME record must be the only record for its host")
		}
	}
	if len(dotless) > 0 {
		b, _ := json.Marshal(eurodns.ZoneError{Message: "An ending dot or a corresponding record in the zone is required",
			Records: dotless, URLForwards: []json.RawMessage{}, MailForwards: []json.RawMessage{}, Severity: eurodns.SeverityWarning})
		zoneErrs = append(zoneErrs, b)
	}
	valid := len(errs) == 0
	empty := []json.RawMessage{}
	if errs == nil {
		errs = empty
	}
	if zoneErrs == nil {
		zoneErrs = empty
	}
	return &eurodns.ValidationReport{IsValid: &valid, RecordErrors: errs, URLForwardErrors: empty,
		MailForwardErrors: empty, ZoneErrors: zoneErrs}
}

func firstError(rep *eurodns.ValidationReport) string {
	if errs := rep.Errors(); len(errs) > 0 {
		return errs[0].Message
	}
	return "Invalid DNS zone"
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON: "+err.Error())
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, code int, errCode, title string) {
	writeJSON(w, code, map[string]any{"errors": []map[string]any{{
		"status": strconv.Itoa(code), "code": errCode, "title": title, "meta": nil,
	}}})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clone(z *eurodns.Zone) *eurodns.Zone {
	b, err := json.Marshal(z)
	if err != nil {
		panic(err)
	}
	var c eurodns.Zone
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return &c
}
