package eurodns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

const maxReplayBody = 16 << 20

// Transport is an http.RoundTripper that applies authentication, the shared
// rate limit (waits, never drops) and retries with backoff on 429/5xx and
// network errors for idempotent methods. A reverse proxy can use it directly.
type Transport struct {
	Base http.RoundTripper

	auth        Authenticator
	limiter     *rate.Limiter
	maxRetries  int
	backoffBase time.Duration
	backoffMax  time.Duration
	userAgent   string
}

// WithRetryBackoff sets the retry backoff (exponential with jitter, capped).
// Defaults to 10s / 2m: EuroDNS extends its ban on every violation during a
// ban, so retries must wait at least one rate window.
func WithRetryBackoff(base, max time.Duration) Option {
	return func(o *options) { o.backoffBase = base; o.backoffMax = max }
}

func defaultOptions() options {
	return options{
		baseURL:     DefaultBaseURL,
		userAgent:   "eurodns-go",
		rateEvery:   1100 * time.Millisecond,
		rateBurst:   5,
		maxRetries:  4,
		backoffBase: 10 * time.Second,
		backoffMax:  2 * time.Minute,
	}
}

func applyOptions(opts []Option) options {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// NewTransport builds a Transport from options (WithAuth, WithRateLimit,
// WithMaxRetries, WithRetryBackoff, WithUserAgent, WithHTTPClient's
// transport as base).
func NewTransport(opts ...Option) *Transport {
	return newTransport(applyOptions(opts))
}

func newTransport(o options) *Transport {
	base := http.DefaultTransport
	if o.httpClient != nil && o.httpClient.Transport != nil {
		base = o.httpClient.Transport
	}
	limit := rate.Inf
	if o.rateEvery > 0 {
		limit = rate.Every(o.rateEvery)
	}
	burst := o.rateBurst
	if burst < 1 {
		burst = 1
	}
	return &Transport{
		Base:        base,
		auth:        o.auth,
		limiter:     rate.NewLimiter(limit, burst),
		maxRetries:  o.maxRetries,
		backoffBase: o.backoffBase,
		backoffMax:  o.backoffMax,
		userAgent:   o.userAgent,
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if err := ensureReplayable(req); err != nil {
		return nil, err
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	for attempt := 0; ; attempt++ {
		r, err := t.prepare(ctx, req)
		if err != nil {
			return nil, err
		}
		if err := t.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		resp, err := base.RoundTrip(r)
		retry, wait := t.shouldRetry(req.Method, resp, err, attempt)
		if !retry {
			return resp, err
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// prepare clones the request with a fresh body and credentials applied.
func (t *Transport) prepare(ctx context.Context, req *http.Request) (*http.Request, error) {
	r := req.Clone(ctx)
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		r.Body = body
	}
	if t.userAgent != "" && r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", t.userAgent)
	}
	if t.auth != nil {
		if err := t.auth.Apply(ctx, r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// ensureReplayable buffers a body without GetBody (e.g. a proxied request)
// so it can be resent on retry.
func ensureReplayable(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody != nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, maxReplayBody+1))
	req.Body.Close()
	if err != nil {
		return err
	}
	if len(b) > maxReplayBody {
		return fmt.Errorf("eurodns: request body larger than %d bytes", maxReplayBody)
	}
	req.ContentLength = int64(len(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	req.Body, _ = req.GetBody()
	return nil
}

func (t *Transport) shouldRetry(method string, resp *http.Response, err error, attempt int) (bool, time.Duration) {
	if attempt >= t.maxRetries {
		return false, 0
	}
	idempotent := method == http.MethodGet || method == http.MethodHead
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, 0
		}
		return idempotent, t.backoff(attempt)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := t.backoff(attempt)
		if ra := retryAfter(resp.Header.Get("Retry-After")); ra > wait {
			wait = ra
		}
		return true, wait
	case resp.StatusCode >= 500 && idempotent:
		return true, t.backoff(attempt)
	}
	return false, 0
}

func (t *Transport) backoff(attempt int) time.Duration {
	d := t.backoffBase << attempt
	if d <= 0 || (t.backoffMax > 0 && d > t.backoffMax) {
		d = t.backoffMax
	}
	jitter := 0.5 + rand.Float64()
	return time.Duration(float64(d) * jitter)
}

func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		return time.Until(at)
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}
