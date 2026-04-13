# Ghost Draft — VishwaCTF 2026 (Web)

## TL;DR

Chain: URL fragment `#draft` reveals hidden API token → use token to list notes → access soft-deleted note 13 with `?deleted=true&pass=draftkey123` → base64-decode the content for the flag.

## Attack Chain

### Step 1: Portal Draft Mode

`/portal` has an HTML comment `<!--Status: Draft mode disabled-->` and loads `script.js`.

`script.js` checks for URL fragment `#draft`:
```
/portal#draft
```
This reveals:
- Base64 message: "Some records may persist beyond expected lifecycle."
- API endpoint: `/api/notes?token=draftkey123`

### Step 2: Note Discovery

`/api/notes?token=draftkey123` lists 15 notes. Note 13 is marked as `class='deleted'` with label "Archived Record (Unavailable)" and no link.

Direct access to `/note/13` returns `403 {"error":"This record has been deleted."}` — soft deletion.

### Step 3: PDF Hint

`/static/report.pdf` (prefetched by `script.js`) contains:
- "Soft deletion was used to prevent accidental data loss"
- "The server never saw everything"
- "Some parts of a request never leave the browser — yet they still change what you see"

### Step 4: Bypass Soft Delete

Fuzzing query parameters on `/note/13` reveals `?deleted=true` returns a different response:

```
{"error":"Password required","hint":"Provide 'pass' parameter"}
```

Using the draft token as password:

```
GET /note/13?deleted=true&pass=draftkey123
```

Returns:
```json
{"content":"cleanup pending – VmlzaHdhQ1RGe3MwRnRfZDNsZXQzXyFzX25PdF9kRWwzdGV9","deleted":true,"id":13,"title":"Archived Record"}
```

### Step 5: Decode Flag

```bash
echo "VmlzaHdhQ1RGe3MwRnRfZDNsZXQzXyFzX25PdF9kRWwzdGV9" | base64 -d
```

## Flag

```
VishwaCTF{s0Ft_d3let3_!s_nOt_dEl3te}
```

## Key Lessons

- URL fragments (`#draft`) can reveal hidden client-side functionality
- Soft-deleted records may remain accessible through undocumented query parameters
- Reusing tokens/keys across different access controls (API listing token = deletion bypass password) is a common weakness
- Always fuzz query parameters — `?deleted=true` changed the server behavior entirely
