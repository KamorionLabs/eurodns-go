package eurodns

import (
	"context"
	"errors"
	"net/http"
)

// Apply sets X-APP-ID and X-API-KEY and removes any bearer token.
func (a APIKeyAuth) Apply(_ context.Context, req *http.Request) error {
	if a.AppID == "" || a.APIKey == "" {
		return errors.New("eurodns: app id and api key are required")
	}
	req.Header.Del("Authorization")
	req.Header.Set("X-APP-ID", a.AppID)
	req.Header.Set("X-API-KEY", a.APIKey)
	return nil
}

// Apply sets Authorization: Bearer and removes any EuroDNS key headers.
func (a BearerAuth) Apply(ctx context.Context, req *http.Request) error {
	if a.Source == nil {
		return errors.New("eurodns: bearer auth requires a token source")
	}
	tok, err := a.Source.Token(ctx)
	if err != nil {
		return err
	}
	if tok == "" {
		return errors.New("eurodns: empty bearer token")
	}
	req.Header.Del("X-APP-ID")
	req.Header.Del("X-API-KEY")
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

// StaticToken is a TokenSource returning a fixed token.
type StaticToken string

func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }
