package eurodns

import (
	"encoding/json"
	"strings"
)

// Severity of a validation problem.
type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
)

// RecordError is one entry of ValidationReport.RecordErrors.
type RecordError struct {
	Messages []string `json:"messages"`
	Record   *Record  `json:"record,omitempty"`
	Severity Severity `json:"severity"`
}

// ZoneError is one entry of ValidationReport.ZoneErrors (conflict between
// records, e.g. a missing ending dot).
type ZoneError struct {
	Message      string            `json:"message"`
	Records      []Record          `json:"records,omitempty"`
	URLForwards  []json.RawMessage `json:"urlForwards,omitempty"`
	MailForwards []json.RawMessage `json:"mailForwards,omitempty"`
	Severity     Severity          `json:"severity"`
}

// Problem is a flattened, readable validation problem.
type Problem struct {
	Severity Severity
	Message  string
	Host     string
	Type     string
}

func (p Problem) String() string {
	s := string(p.Severity) + ": " + p.Message
	if p.Host != "" || p.Type != "" {
		s += " (" + p.Host + "/" + p.Type + ")"
	}
	return s
}

// Problems flattens record, zone and forward errors. A zone error naming
// several records yields one problem per record. Unparseable entries are
// reported with their raw JSON as message.
func (r *ValidationReport) Problems() []Problem {
	if r == nil {
		return nil
	}
	var out []Problem
	for _, raw := range r.RecordErrors {
		var e RecordError
		if json.Unmarshal(raw, &e) != nil {
			out = append(out, Problem{Severity: SeverityError, Message: string(raw)})
			continue
		}
		p := Problem{Severity: e.Severity, Message: strings.Join(e.Messages, "; ")}
		if e.Record != nil {
			p.Host, p.Type = e.Record.Host, e.Record.Type
		}
		out = append(out, p)
	}
	for _, raw := range r.ZoneErrors {
		var e ZoneError
		if json.Unmarshal(raw, &e) != nil {
			out = append(out, Problem{Severity: SeverityError, Message: string(raw)})
			continue
		}
		if len(e.Records) == 0 {
			out = append(out, Problem{Severity: e.Severity, Message: e.Message})
		}
		for _, rec := range e.Records {
			out = append(out, Problem{Severity: e.Severity, Message: e.Message, Host: rec.Host, Type: rec.Type})
		}
	}
	for _, list := range [][]json.RawMessage{r.URLForwardErrors, r.MailForwardErrors} {
		for _, raw := range list {
			var e struct {
				Messages []string `json:"messages"`
				Message  string   `json:"message"`
				Severity Severity `json:"severity"`
			}
			if json.Unmarshal(raw, &e) != nil {
				out = append(out, Problem{Severity: SeverityError, Message: string(raw)})
				continue
			}
			msg := e.Message
			if len(e.Messages) > 0 {
				msg = strings.Join(e.Messages, "; ")
			}
			if e.Severity == "" {
				e.Severity = SeverityError
			}
			out = append(out, Problem{Severity: e.Severity, Message: msg})
		}
	}
	return out
}

// Errors returns only ERROR-severity problems (warnings do not block a save).
func (r *ValidationReport) Errors() []Problem {
	var out []Problem
	for _, p := range r.Problems() {
		if p.Severity != SeverityWarning {
			out = append(out, p)
		}
	}
	return out
}

// Valid reports whether the zone can be saved: isValid is not false and no
// ERROR-severity problem is present.
func (r *ValidationReport) Valid() bool {
	if r == nil {
		return true
	}
	if r.IsValid != nil && !*r.IsValid {
		return false
	}
	return len(r.Errors()) == 0
}
