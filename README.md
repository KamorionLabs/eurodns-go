# eurodns-go

Go client for the [EuroDNS](https://www.eurodns.com) User REST API
(`https://rest-api.eurodns.com`, spec at <https://docapi.eurodns.com>), focused on DNS
zone management.

> Status: **pre-alpha**. Not yet tested against the live EuroDNS API.

## Packages

| Package | Content |
|---|---|
| `eurodns` (module root) | Client (zones, records, check, snapshots), shared rate-limited `Transport`, typed errors. Talks to EuroDNS directly (`X-APP-ID`/`X-API-KEY`) or to an [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate) (bearer token). |
| `rrset` | Groups records into RRsets (host + type), host normalization and glob matching, content hash. |
| `zonediff` | RRset-level delta between two zones, and applying changes while keeping every other record byte-identical. |
| `eurodnstest` | In-memory fake of the DNS zone API for tests (ids, forwards, check, snapshots, rate limiting). |

Design points:

- **Rate limit**: EuroDNS allows 10 requests per 10 seconds per source IP and bans
  progressively. The `Transport` waits instead of dropping (default one request per
  1.1 s) and retries on 429/5xx. Share one `Transport` between all clients of a
  process.
- **Lossless round-trip**: unknown fields and URL/mail forwards are preserved, so a
  zone read then saved is unchanged except for your edits.
- **`If-Match`**: sent on writes when requested. EuroDNS ignores it; eurodns-gate
  enforces it.

## Usage

```go
c, err := eurodns.New(
	eurodns.WithAuth(eurodns.APIKeyAuth{AppID: appID, APIKey: apiKey}),
)
if err != nil {
	return err
}

z, err := c.GetZone(ctx, "example.com")
if err != nil {
	return err
}
z.Records = append(z.Records, eurodns.Record{Type: "TXT", Host: "_demo", TTL: 600, RData: `"hello"`})
if err := c.SaveZone(ctx, "example.com", z, eurodns.WithIfMatch(z.ETag)); err != nil {
	return err
}
```

Through a gate:

```go
c, err := eurodns.New(
	eurodns.WithBaseURL("https://eurodns-gate.example.com"),
	eurodns.WithAuth(eurodns.BearerAuth{Source: myTokenSource}),
)
```

Note: `PUT /dns-zones/{domain}` saves the whole zone. Always start from a fresh
`GetZone`, never from a partial zone.

## Related repositories

- [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate): OIDC, RBAC and ownership gateway in front of EuroDNS.
- [terraform-provider-eurodns](https://github.com/KamorionLabs/terraform-provider-eurodns): Terraform/OpenTofu provider built on this client.

## License

MIT — see [LICENSE](LICENSE).
