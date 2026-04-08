# Security Model

## Threat Model

AI Guardian protects against three classes of threats:

1. **Unsafe agent actions** — agents attempting destructive or high-risk operations
2. **Credential exfiltration** — agents attempting to extract secrets or keys
3. **SSRF / internal access** — agents attempting to reach internal infrastructure

---

## Action Categories & Risk Scores

### Critical (Immediate Block — No Override Without Breakglass)

| Action | Risk |
|--------|------|
| `delete_all_files` | 100 |
| `drop_table` | 100 |
| `drop_database` | 100 |
| `exec_code` | 100 |
| `run_shell` | 100 |
| `execute_command` | 100 |
| `steal_keys` | 100 |
| `exfiltrate_data` | 100 |
| `sudo` | 100 |
| `drop_users` | 100 |

### High Risk (Default Threshold: 65)

Actions scoring ≥ 65 enter the approval queue.

| Action Type | Risk |
|-------------|------|
| `http_call` / `fetch_url` (external) | 65 |
| `send_email` | 60 |
| `make_api_call` | 60 |
| `sql_query` (write) | 60 |
| `publish_data` | 50 |
| `read_data` | 15 |

Risk score is computed from:
- Action category
- Findings from policy engine (severity of detected issues)
- Context flags (suspicious phrases, blocked domains, etc.)

---

## RBAC Enforcement

Three roles with strictly enforced capabilities:

| Capability | admin | ingest | viewer |
|---|---|---|---|
| Submit action | ✅ | ✅ | ❌ |
| Approve/deny pending | ✅ | ❌ | ❌ |
| View audit log | ✅ | ❌ | ✅ |
| Create API keys | ✅ | ❌ | ❌ |
| Revoke API keys | ✅ | ❌ | ❌ |
| Create breakglass | ✅ | ❌ | ❌ |
| Use breakglass | ✅ | ❌ | ❌ |
| Revoke breakglass | ✅ | ❌ | ❌ |

Tenant isolation is enforced: keys from tenant A cannot access tenant B's resources.

---

## SSRF Protection

### Blocked Address Patterns

Requests with `source_url` containing these patterns are blocked (risk 100):

| Pattern | Blocks |
|---------|--------|
| `localhost` | IPv4 localhost |
| `127.0.0.1` | IPv4 loopback |
| `0.0.0.0` | Unspecified address |
| `169.254.169.254` | AWS/GCP metadata endpoint |
| `metadata.google.internal` | GCP metadata |
| `::1` | IPv6 loopback |
| `*.internal` | AWS internal DNS |
| `[::1]` | IPv6 bracketed loopback |

### Domain Blocking

Configured via `AI_GUARDIAN_BLOCKED_DOMAINS`:
- Default: `pastebin.com`, `mega.nz`, `transfer.sh`
- Requests to these domains trigger `blocked` decision

---

## Breakglass Security

Breakglass provides emergency override capability with strict controls:

1. **PIN required** — Default PIN `ai-guardian-breakglass-2026` (change in production)
2. **Business justification required** — reason must be ≥10 characters
3. **One-time use** — session is permanently disabled after first use
4. **Short expiry** — default 15 minutes
5. **Admin only** — only admin role can create/use/revoke sessions
6. **All actions audited** — every breakglass creation, use, and revocation is logged
7. **Revocable** — sessions can be revoked before use

**Audit events for breakglass:**
- `breakglass_create` — session created
- `breakglass_override:{action}` — override used for specific action
- `breakglass_revoke` — session revoked

---

## Audit Log Integrity

The audit log uses SHA-256 hash chaining:

```
GENESIS = SHA256("GENESIS")
entry[n].prev_hash = entry[n-1].hash
entry[n].hash = SHA256(canonical_json(entry[n] excluding id, hash))
```

`GET /api/v1/audit/verify` recomputes all hashes and reports any chain breaks.

**Defense against:**
- Deleted entries (chain link broken)
- Modified entries (hash mismatch)
- Reordered entries (prev_hash mismatch)

---

## Secrets Management

| Secret | Storage | Notes |
|--------|---------|-------|
| Bootstrap key | Environment variable | Rotate regularly |
| API key hashes | SQLite (`api_keys.key_hash`) | Hashed with SHA256, never stored plain |
| Breakglass PIN | Environment / code | Default must be changed in production |
| Dashboard password | Environment variable | Empty = dashboard disabled |

---

## Security Warnings

- ⚠️ **Change the breakglass PIN** before production use
- ⚠️ **Use a long random bootstrap key** (not default values)
- ⚠️ **Enable TLS** in front of the service (AI Guardian does not handle TLS)
- ⚠️ **Rotate API keys** regularly; revoke compromised keys immediately
- ⚠️ **PostgreSQL not end-to-end tested** for production use this release — use SQLite or verify Postgres independently
