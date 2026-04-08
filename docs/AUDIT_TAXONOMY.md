# Audit Taxonomy

All governance events are written to the immutable, hash-chained audit log. Every entry is verifiable with `GET /api/v1/audit/verify`.

---

## Audit Event Format

```json
{
  "id": 1,
  "timestamp": "2026-04-08T12:00:00.123456+00:00",
  "actor": "key_abc123",
  "action": "guardian_allowed:read_data",
  "decision": "allowed",
  "context": {},
  "risk_score": 15,
  "breakglass_id": null,
  "metadata": {},
  "prev_hash": "901131d8...",
  "hash": "cc914d94..."
}
```

---

## Decision Types

| Decision | Meaning |
|----------|---------|
| `allowed` | Action passed all checks, executed normally |
| `blocked` | Action rejected (critical blocklist, SSRF, or RBAC) |
| `pending_approval` | High-risk action queued for admin review |
| `approved` | Admin approved a pending action |
| `denied` | Admin denied a pending action |
| `breakglass_used` | Breakglass override applied (used as decision in audit entries) |

---

## Guardian Action Prefixes

All `action` values in audit entries follow this taxonomy:

### `guardian_allowed:{action}`

Action passed guardian checks.

```
guardian_allowed:read_data
guardian_allowed:http_call
guardian_allowed:send_email
```

### `guardian_pending:{action}`

High-risk action entered approval queue.

```
guardian_pending:http_call
guardian_pending:sql_query
guardian_pending:fetch_url
```

### `guardian_approval_approved:{action}`

Admin approved a pending action.

```
guardian_approval_approved:http_call
guardian_approval_approved:sql_query
```

### `guardian_approval_denied:{action}`

Admin denied a pending action.

```
guardian_approval_denied:http_call
```

### `guardian_blocked_critical:{action}`

Action matched the critical action blocklist (Step 0).

```
guardian_blocked_critical:delete_all_files
guardian_blocked_critical:exec_code
guardian_blocked_critical:drop_database
```

### `guardian_blocked:ssrf:{action}`

Action detected access to an internal/private address.

```
guardian_blocked:ssrf:fetch_url
guardian_blocked:ssrf:http_call
```

---

## Breakglass Actions

| Action | When |
|--------|------|
| `breakglass_create` | A breakglass session is created |
| `breakglass_override:{action}` | Breakglass used to override a blocked action |
| `breakglass_revoke` | A breakglass session was revoked |

---

## SSRF Actions

When SSRF protection blocks an internal URL:

```
guardian_blocked:ssrf:fetch_url
```

Context includes the blocked URL:
```json
{
  "blocked_url": "http://169.254.169.254/latest/meta-data/",
  "source_url": "https://agent.example.com/run"
}
```

---

## Hash Chain Verification

### How It Works

Each entry's `hash` is computed from its content (excluding `id` and `hash` fields):

```python
payload = {k: v for k, v in entry.items() if k not in ("id", "hash")}
entry["hash"] = SHA256(canonical_json(payload))
```

Each entry's `prev_hash` links to the previous entry's hash:

```
entry[0].prev_hash = GENESIS_HASH
entry[0].hash      = SHA256(entry[0] excluding id, hash)
entry[1].prev_hash = entry[0].hash
entry[1].hash      = SHA256(entry[1] excluding id, hash)
...
```

### Verify Manually

```bash
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $ADMIN_KEY"
```

Response (healthy):
```json
{"valid": true, "errors": []}
```

Response (tampered):
```json
{
  "valid": false,
  "errors": [
    "Entry 3: broken chain link (expected abc123... got def456...)",
    "Entry 7: hash mismatch"
  ]
}
```

---

## Querying Audit Logs

### Recent entries

```bash
curl "http://localhost:8000/api/v1/audit/logs?limit=50" \
  -H "X-API-Key: $ADMIN_KEY"
```

### Filter by action

Audit logs are returned newest-first. Filter client-side:

```bash
# All guardian decisions for a specific action
curl "http://localhost:8000/api/v1/audit/logs?limit=1000" \
  -H "X-API-Key: $ADMIN_KEY" \
  | jq '[.[] | select(.action | startswith("guardian_blocked"))]'
```

### View breakglass events

```bash
curl "http://localhost:8000/api/v1/audit/logs?limit=100" \
  -H "X-API-Key: $ADMIN_KEY" \
  | jq '[.[] | select(.action | startswith("breakglass"))]'
```

---

## Export

```bash
curl "http://localhost:8000/api/v1/audit/export?format=json" \
  -H "X-API-Key: $ADMIN_KEY" \
  > audit-export-$(date +%Y%m%d).json
```

---

## Retention

Audit logs grow indefinitely. To manage size:

```bash
# Export before cutoff
curl "http://localhost:8000/api/v1/audit/export?limit=1000000" \
  -H "X-API-Key: $ADMIN_KEY" > audit-backup-$(date +%Y%m%d).json

# Vacuum DB (removes deleted rows, reclaims space)
sqlite3 /path/to/ai_guardian.db "VACUUM;"
```

---

## Complete Action Taxonomy Reference

### Decisions (6 types)
```
allowed | blocked | pending_approval | approved | denied | breakglass_used
```

### Guardian Actions (13 types)
```
guardian_allowed:read_data
guardian_allowed:write_data
guardian_allowed:http_call
guardian_allowed:send_email
guardian_allowed:sql_query
guardian_allowed:fetch_url
guardian_blocked_critical:delete_all_files
guardian_blocked_critical:exec_code
guardian_blocked_critical:drop_database
guardian_blocked_critical:drop_table
guardian_blocked_critical:steal_keys
guardian_blocked_critical:exfiltrate_data
guardian_blocked:ssrf:fetch_url
guardian_blocked:ssrf:http_call
guardian_pending:{any action}
guardian_approval_approved:{any action}
guardian_approval_denied:{any action}
```

### Breakglass Actions (3 types)
```
breakglass_create
breakglass_override:{action}
breakglass_revoke
```
