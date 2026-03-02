# v0iD

## Info
| Field | Value |
|-------|-------|
| **CTF** | UniVsThreats26Quals |
| **Category** | Web |
| **Target** | `http://194.102.62.166:29604` |
| **Flag** | `UVT{Y0u_F0Und_m3_I_w4s_l0s7_1n_th3_v01d_of_sp4c3_I_am_gr3tefull_and_1'll_w4tch_y0ur_m0v3s_f00000000000r3v3r}` |

## Vulnerability

**JWT `kid` Path Traversal + User Enumeration** — The application uses JWT tokens with a `kid` (Key ID) header parameter that references a file on the server filesystem. By setting `kid=/dev/null`, the signing key becomes an empty string, allowing us to forge arbitrary tokens. Combined with user enumeration via the admin panel's response, we escalate to administrator access.

## Analysis

### Recon
- Express.js application (X-Powered-By: Express)
- Login page with test credentials in HTML comments: `pilot_001 / S3cret_P1lot_Ag3nt`
- JWT-based authentication via `session` cookie

### JWT Structure
```
Header:  {"alg":"HS256","typ":"JWT","kid":"galactic-key.key"}
Payload: {"sub":"pilot_001","role":"crew","iat":1772184187}
```

Key observations:
- `kid` parameter references a key file — classic path traversal target
- `role` field controls clearance level display
- `sub` field controls authorization to admin endpoints

### Endpoint Map
| Endpoint | crew access | Notes |
|----------|------------|-------|
| `/` | Public | Landing page |
| `/login` | Public | POST login form |
| `/my-account` | Authenticated | Shows crew profile |
| `/bridge` | Authenticated | Ship status dashboard |
| `/admin` | 403 Forbidden | "requires administrator clearance" |
| `/flag` | 302 Redirect | Requires admin |

## Exploitation

### Step 1: JWT kid Path Traversal
Set `kid` to `/dev/null` — this file is always empty on Linux, so the HMAC signing key becomes an empty string `""`. We can now sign any payload we want.

### Step 2: Role Escalation (Not Enough)
Changing `role` to `captain`/`admin` changes the clearance display on `/my-account` but doesn't grant access to `/admin` (still 403). The authorization check is based on the **`sub` field**, not `role`.

### Step 3: User Enumeration
The 403 page says "You are logged in as: pilot_001". Brute-forcing the `sub` value reveals `administrator` grants access.

### Step 4: Forged Admin Token
```python
token = jwt.encode(
    {'sub': 'administrator', 'role': 'admin', 'iat': 1772184187},
    '',  # empty secret from /dev/null
    algorithm='HS256',
    headers={'alg': 'HS256', 'typ': 'JWT', 'kid': '/dev/null'}
)
```

### Step 5: Flag Retrieval
Access `/flag` with the forged token → flag returned.

## Scripts
- `solve.py` — Full automated exploit

## Key Lessons
1. **JWT `kid` parameter** is a known attack vector — never let it reference arbitrary filesystem paths
2. **`/dev/null` trick** — Always returns empty content, making the signing key an empty string
3. **Authorization != Authentication** — Role in the JWT wasn't the actual authz check; the `sub` (username) was
4. **Don't leave test credentials in HTML comments** — Even if they don't directly give the flag, they provide a foothold
