package eurodns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ErrNotGate is returned by GateInfo when the endpoint is plain EuroDNS.
var ErrNotGate = errors.New("eurodns: endpoint is not an eurodns-gate")

// APIError is returned for non-2xx responses.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Body       []byte
	Report     *ValidationReport // parsed when the body is a zone with a report
	Reason     string            // eurodns-gate error code, e.g. "foreign_rrset", "not_owner", "tainted"
	Message    string            // human-readable message (gate "message" or EuroDNS "title")
	Code       string            // EuroDNS error code, e.g. "FORBIDDEN_ACTION", "INVALID_API_KEY"
	Errors     []ErrorItem       // EuroDNS error list, as returned
}

// ErrorItem is one entry of the EuroDNS error body
// {"errors":[{"status":"403","code":"FORBIDDEN_ACTION","title":"...","meta":null}]}.
type ErrorItem struct {
	Status string          `json:"status"`
	Code   string          `json:"code"`
	Title  string          `json:"title"`
	Meta   json.RawMessage `json:"meta,omitempty"`
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("eurodns: %s %s: status %d", e.Method, e.Path, e.StatusCode)
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Code != "" {
		msg += ": " + e.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	} else if e.Reason == "" && e.Code == "" && len(e.Body) > 0 {
		body := e.Body
		if len(body) > 512 {
			body = body[:512]
		}
		msg += ": " + string(body)
	}
	return msg
}

func newAPIError(resp *http.Response, body []byte) *APIError {
	e := &APIError{StatusCode: resp.StatusCode, Body: body}
	if resp.Request != nil {
		e.Method = resp.Request.Method
		if resp.Request.URL != nil {
			e.Path = resp.Request.URL.Path
		}
	}
	var parsed struct {
		Reason  string            `json:"reason"`
		Message string            `json:"message"`
		Report  *ValidationReport `json:"report"`
		Errors  []ErrorItem       `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		e.Reason = parsed.Reason
		e.Message = parsed.Message
		e.Report = parsed.Report
		e.Errors = parsed.Errors
		if len(parsed.Errors) > 0 {
			e.Code = parsed.Errors[0].Code
			if e.Message == "" {
				e.Message = parsed.Errors[0].Title
			}
		}
	}
	return e
}

func statusIs(err error, code int) bool {
	var e *APIError
	return errors.As(err, &e) && e.StatusCode == code
}

func IsNotFound(err error) bool           { return statusIs(err, http.StatusNotFound) }
func IsPreconditionFailed(err error) bool { return statusIs(err, http.StatusPreconditionFailed) }
func IsRateLimited(err error) bool        { return statusIs(err, http.StatusTooManyRequests) }
func IsForbidden(err error) bool          { return statusIs(err, http.StatusForbidden) }
