# Three Questions Part 3

| Campo | Valor |
|-------|-------|
| **CTF** | BSidesSF CTF 2026 |
| **Categoria** | Web 101 |
| **Puntos** | 785 |
| **Flag** | `CTF{c00k13crumbsle4dth3w4y}` |

---

## TL;DR

HTML comment exposes debug endpoint `<!-- debug endpoints: /debug/game-state?... -->`. Decode Flask session cookie to get `_user_id`, query debug endpoint to get the secret character name, submit guess.

## Explotacion

1. Register + login → get Flask session cookie
2. HTML source reveals: `<!-- debug endpoints: /debug/game-state?... -->`
3. Decode session: `flask-unsign --decode` → `_user_id: 248`
4. `GET /debug/game-state?user_id=248` → `{"character_name": "Tracy Turnblad"}`
5. `GET /guess?guess=Tracy+Turnblad` → win → flag

## Flag

```
CTF{c00k13crumbsle4dth3w4y}
```
