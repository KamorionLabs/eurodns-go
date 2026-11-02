package eurodns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the EuroDNS REST API endpoint.
const DefaultBaseURL = "https://rest-api.eurodns.com"

// Authenticator sets credentials on an outgoing request.
type Authenticator interface {
	Apply(ctx context.Context, req *http.Request) error
}

// APIKeyAuth authenticates directly against EuroDNS.
type APIKeyAuth struct {
	AppID  string
	APIKey string
}

// TokenSource returns a bearer token (OIDC JWT) for eurodns-gate.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// BearerAuth authenticates against eurodns-gate with a bearer token.
type BearerAuth struct {
	Source TokenSource
}

// Option configures a Client.
type Option func(*options)

type options struct {
	baseURL    string
	httpClient *http.Client
	transport  *Transport
	auth       Authenticator
	userAgent  string
	rateEvery  time.Duration
	rateBurst  int
	maxRetries int

	backoffBase time.Duration
	backoffMax  time.Duration
}

func WithBaseURL(u string) Option          { return func(o *options) { o.baseURL = u } }
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.httpClient = c } }
func WithAuth(a Authenticator) Option      { return func(o *options) { o.auth = a } }
func WithUserAgent(ua string) Option       { return func(o *options) { o.userAgent = ua } }
func WithMaxRetries(n int) Option          { return func(o *options) { o.maxRetries = n } }

// WithRateLimit sets the client-side limiter: one request every `every`,
// with the given burst. Default: one request per 1.1s, burst 5.
func WithRateLimit(every time.Duration, burst int) Option {
	return func(o *options) { o.rateEvery = every; o.rateBurst = burst }
}

// WithTransport shares an existing Transport (and therefore its rate limiter)
// between several clients or with a reverse proxy.
func WithTransport(t *Transport) Option { return func(o *options) { o.transport = t } }

// WriteOption configures a write call.
type WriteOption func(*writeOptions)

type writeOptions struct {
	ifMatch string
}

// WithIfMatch sends If-Match. EuroDNS ignores it; eurodns-gate returns 412
// when the zone changed since the given ETag.
func WithIfMatch(etag string) WriteOption { return func(w *writeOptions) { w.ifMatch = etag } }

// Client is a EuroDNS (or eurodns-gate) API client. Safe for concurrent use.
type Client struct {
	opts      options
	transport *Transport
	http      *http.Client
	baseURL   *url.URL
}

// New builds a Client.
func New(opts ...Option) (*Client, error) {
	o := applyOptions(opts)
	u, err := url.Parse(strings.TrimRight(o.baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("eurodns: invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("eurodns: base URL must be http(s): %q", o.baseURL)
	}
	t := o.transport
	if t == nil {
		t = newTransport(o)
	}
	hc := &http.Client{Transport: t, Timeout: 60 * time.Second}
	if o.httpClient != nil {
		hc.Timeout = o.httpClient.Timeout
		hc.CheckRedirect = o.httpClient.CheckRedirect
	}
	return &Client{opts: o, transport: t, http: hc, baseURL: u}, nil
}

// Transport returns the client's transport, to share it.
func (c *Client) Transport() *Transport { return c.transport }

func zonePath(domain string, rest ...string) string {
	p := "/dns-zones/" + url.PathEscape(domain)
	for _, r := range rest {
		p += "/" + r
	}
	return p
}

// GetZone returns the zone with its records and forwards. ETag is filled
// when the server returns one.
func (c *Client) GetZone(ctx context.Context, domain string) (*Zone, error) {
	var z Zone
	h, err := c.do(ctx, http.MethodGet, zonePath(domain), nil, nil, &z)
	if err != nil {
		return nil, err
	}
	z.ETag = h.Get("ETag")
	return &z, nil
}

// SaveZone replaces the whole zone (PUT /dns-zones/{domain}).
func (c *Client) SaveZone(ctx context.Context, domain string, z *Zone, opts ...WriteOption) error {
	_, err := c.do(ctx, http.MethodPut, zonePath(domain), z, writeHeaders(opts), nil)
	return err
}

// CheckZone validates a zone without saving it (POST /dns-zones/{domain}/check).
func (c *Client) CheckZone(ctx context.Context, domain string, z *Zone) (*Zone, error) {
	var out Zone
	if _, err := c.do(ctx, http.MethodPost, zonePath(domain, "check"), z, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddRecords adds records (POST /dns-zones/{domain}/dns-records).
func (c *Client) AddRecords(ctx context.Context, domain string, recs []Record, opts ...WriteOption) (*Zone, error) {
	if recs == nil {
		recs = []Record{}
	}
	var out Zone
	h, err := c.do(ctx, http.MethodPost, zonePath(domain, "dns-records"), recs, writeHeaders(opts), &out)
	if err != nil {
		return nil, err
	}
	out.ETag = h.Get("ETag")
	return &out, nil
}

// DeleteRecord deletes one record by id (DELETE /dns-zones/{domain}/dns-records/{id}).
func (c *Client) DeleteRecord(ctx context.Context, domain string, id int64, opts ...WriteOption) (*Zone, error) {
	var out Zone
	h, err := c.do(ctx, http.MethodDelete, zonePath(domain, "dns-records", strconv.FormatInt(id, 10)), nil, writeHeaders(opts), &out)
	if err != nil {
		return nil, err
	}
	out.ETag = h.Get("ETag")
	return &out, nil
}

// ListSnapshots lists zone snapshots.
func (c *Client) ListSnapshots(ctx context.Context, domain string) ([]Snapshot, error) {
	var out []Snapshot
	if _, err := c.do(ctx, http.MethodGet, zonePath(domain, "snapshots"), nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GateInfo queries GateInfoPath. Returns ErrNotGate on 404 (plain EuroDNS).
// 401, 403 and 405 are also treated as "not a gate": the gate serves this
// endpoint without authentication.
func (c *Client) GateInfo(ctx context.Context) (*GateInfo, error) {
	var gi GateInfo
	_, err := c.do(ctx, http.MethodGet, GateInfoPath, nil, nil, &gi)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			switch ae.StatusCode {
			case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUnauthorized, http.StatusForbidden:
				return nil, ErrNotGate
			}
		}
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, ErrNotGate
		}
		return nil, err
	}
	if gi.Version == "" {
		return nil, ErrNotGate
	}
	return &gi, nil
}

// HasFeature reports whether the gate advertises a feature.
func (g *GateInfo) HasFeature(name string) bool {
	if g == nil {
		return false
	}
	for _, f := range g.Features {
		if f == name {
			return true
		}
	}
	return false
}

// Adopt asks eurodns-gate to take ownership of existing foreign RRsets.
func (c *Client) Adopt(ctx context.Context, domain string, req AdoptRequest) error {
	if req.RRsets == nil {
		req.RRsets = []AdoptRRset{}
	}
	path := GateInfoPath + "/zones/" + url.PathEscape(domain) + "/adopt"
	_, err := c.do(ctx, http.MethodPost, path, req, nil, nil)
	return err
}

func writeHeaders(opts []WriteOption) http.Header {
	var w writeOptions
	for _, o := range opts {
		o(&w)
	}
	if w.ifMatch == "" {
		return nil
	}
	return http.Header{"If-Match": []string{w.ifMatch}}
}

func (c *Client) do(ctx context.Context, method, path string, in any, headers http.Header, out any) (http.Header, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	u.RawPath = strings.TrimRight(c.baseURL.EscapedPath(), "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Header, newAPIError(resp, b)
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.Header, fmt.Errorf("eurodns: decode %s %s: %w", method, path, err)
		}
	}
	return resp.Header, nil
}
