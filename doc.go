// Package eurodns is a client for the EuroDNS User REST API
// (https://docapi.eurodns.com), focused on DNS zone management.
//
// The same client talks either to EuroDNS directly (X-APP-ID / X-API-KEY)
// or to an eurodns-gate instance (bearer token), through the Authenticator
// option. All requests go through a shared Transport that enforces the
// EuroDNS rate limit (10 requests per 10 seconds per source IP).
package eurodns
