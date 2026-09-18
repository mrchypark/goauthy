# DCR software statements

GoAuthy accepts RFC 7591 `software_statement` values only when an operator
configures a static issuer-to-JWKS trust file with
`GOAUTHY_DCR_SOFTWARE_STATEMENT_TRUST_FILE`. The file is loaded at startup;
invalid configuration fails closed. Keys are public signing keys and are never
downloaded from a statement or from a remote `jwks_uri`.

Trust-file member names are case-sensitive and duplicate names (including
case-only variants at any nesting level) are rejected before decoding. This is
stricter than the signed JWT parser, which rejects duplicate exact member names
and otherwise retains RFC JSON member-name semantics; the distinction prevents
the Go trust-config decoder's case-insensitive struct matching from becoming a
policy ambiguity.

```json
{
  "issuers": [
    {
      "issuer": "https://publisher.example.test",
      "audience": "https://id.example.test/oidc/register",
      "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "...", "kid": "publisher-1", "use": "sig", "alg": "EdDSA"}]}
    }
  ]
}
```

The statement must be one compact JWS signed by exactly one configured public
key. Its verified `iss` must match the configured issuer. When `audience` is
configured, the statement must contain that audience; when it is empty,
the statement must omit `aud` (there is no recipient policy to validate).
Existing DCR validation still
controls redirect URIs, grants, response types, authentication method, scopes,
and anonymous-registration restrictions. Verified statement metadata takes
precedence over duplicate request JSON metadata, as required by RFC 7591.

An issuer absent from the static trust file returns the distinct
`unapproved_software_statement` signal intentionally: the configured issuer
allow-list is an operator-visible policy, not secret material. Statements from
an approved issuer that fail parsing, signature, key, claim, time, or audience
validation return the generic `invalid_software_statement` error.

Successful registration returns the original compact JWT unchanged in the
`software_statement` response member. Invalid and untrusted statements return
`invalid_software_statement` and `unapproved_software_statement`, respectively.
No statement claim can select a client ID, expose key material, or execute SQL.
