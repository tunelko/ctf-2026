# Another Notes App

**CTF**: kashiCTF 2026
**Category**: Web
**Points**: 449
**Solves**: 40
**Flag**: `kashiCTF{67358e160ab0c131916f0c05aebf8aff_Pu7JAU1qBn}}`

## TL;DR

IDOR in download endpoint + crash the token cleanup coroutine via forged `alg:none` JWT with null subject → NPE kills coroutine → expired token survives in cache past 5-min download delay → read owner's notes.

## Analysis

Kotlin/Ktor web app with JWT auth, token caching, and a download feature with a 5-minute delay.

### Key Components

- **JwtConfig**: Generates HS256 JWTs with 3-minute expiry. `parseWithoutValidation()` strips the signature and uses `parseClaimsJwt()` (unsigned parsing). `getUsername()` returns `claims.subject` as non-nullable `String`.
- **TokenCache**: `ConcurrentHashMap<String, Claims>` with a single cleanup coroutine (`scope.launch`) that processes logouts and removes expired tokens every 5 seconds. `processLogoutInline()` has **no try-catch**.
- **Download endpoint**: `POST /notes/request-download` takes `username` from POST parameter (not JWT — **IDOR**). First call sets `downloadPermissions[token] = now + 300s`. After 300s, returns the requested user's notes.
- **Database**: Creates "owner" user with random password. Flag stored as owner's note: `"Something something $FLAG"`.

### The Race

| Timer | Event |
|-------|-------|
| T+0s | Register, get token T1 |
| T+0s | Request download for "owner" → `downloadPermissions[T1] = now+300s` |
| T+180s | JWT T1 expires (3 min) |
| T+300s | Download permission activates (5 min) |

**Problem**: Token expires at T+180s. The cleanup coroutine removes expired tokens every 5s. By T+300s, T1 is long gone from cache → `verifyToken(T1)` returns null → 401.

**Gap**: 120 seconds where the token is expired but the download isn't ready yet.

## Vulnerability

### 1. IDOR (CWE-639)
`/notes/request-download` reads `username` from POST body, not from the authenticated JWT. Any user can request any other user's notes.

### 2. Coroutine Crash via Forged JWT (CWE-755)
`processLogoutInline()` calls `parseWithoutValidation()` → `getUsername()` on the parsed claims. For a forged JWT with `alg:none` and no `sub` field:
- `parseClaimsJwt()` succeeds (unsigned JWT is valid for this parser)
- `claims.subject` returns `null`
- `getUsername()` declares return type `String` (non-nullable) → Kotlin null-safety violation → **NPE**
- `processLogoutInline()` has no try-catch → exception propagates up
- The `while(true)` loop in `start()` has no catch → **coroutine terminates**
- `SupervisorJob` keeps the scope alive but the cleanup coroutine is dead

### 3. Token Persistence
With the cleanup coroutine dead, expired tokens are never removed from the cache. Token T1 remains valid for `verifyToken()` lookups indefinitely.

## Exploitation

```
1. Register user → get JWT token T1
2. POST /notes/request-download (username=owner) → sets 5-min timer
3. Send forged alg:none JWTs (no sub field) via /logout → crash cleanup coroutine
4. Wait 5 minutes (T1 survives in cache because cleanup is dead)
5. POST /notes/request-download (username=owner) → returns owner's notes with flag
```

The forged JWT:
```json
Header: {"alg": "none"}
Payload: {"iat": <now>, "exp": <now+9999>}  // NO "sub" field
```

Sent via `SESSION` cookie to `/logout` endpoint, which feeds it to `processLogout()` → `logoutChannel` → `processLogoutInline()`.

## Key Takeaways

- **IDOR**: Always derive the authorized user from the session/JWT, never from user-supplied parameters
- **Error handling in coroutines**: A single unhandled exception kills the coroutine. Critical background tasks need try-catch
- **`parseClaimsJwt` vs `parseClaimsJws`**: Accepting unsigned JWTs (`alg:none`) is a well-known JWT attack vector
- **Kotlin null-safety at Java boundaries**: `claims.subject` from a Java library returns platform type `String!` — declaring it as `String` in Kotlin creates a runtime NPE risk
- **Time-gated access with shorter token expiry**: The 5-min download delay vs 3-min token expiry creates a fundamental design flaw exploitable when cleanup fails

## Files

- `solve.py` — Exploit script
- `flag.txt` — Captured flag
- `handout/` — Challenge source code
