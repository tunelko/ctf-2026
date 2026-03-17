# ClashOfFlans

| Field       | Value                                         |
|-------------|-----------------------------------------------|
| Platform    | MidnightFlagCTF                               |
| Category    | web                                           |
| Author      | fun88337766                                   |
| Connection  | `http://dyn-01.midnightflag.fr:10347`         |

## TL;DR

PHP 7.4 object injection via cookie deserialization, bypassing the word blacklist using array cookies. The gadget chain reads arbitrary files via `file_get_contents`, but the path always gets `.cof` appended. Bypass the `.cof` extension by crafting a path where `joinpath()` returns exactly 104 chars, so `substr(0, 100)` truncates the `.cof` suffix. Use `/proc/PID/root/` symlink chains to resolve the relative path to `/flag.txt`.

## Flag

```
MCTF{7hr33-ch4rs_pr0bl3m}
```

(Name references the 3-char problem: finding path components whose length × repetitions = 91)

## Vulnerability Analysis

### CWE
- CWE-502: Deserialization of Untrusted Data
- CWE-22: Path Traversal

### is_bad() Bypass (PHP 7.4 type coercion)

`is_bad()` checks if the serialized cookie contains class names (`Clash`, `Baker`):

```php
function is_bad($param) {
    foreach (['Clash', 'Baker'] as $word) {
        if (strpos($param, $word) != false) return true;  // buggy: 0 == false
    }
    return false;
}
```

Bypass: Send `flans[0]=PAYLOAD` (array cookie). PHP makes `$_COOKIE["flans"]` an array.
- PHP 7.4: `strpos(array, string)` returns `NULL` (warning, not error)
- `NULL != false` evaluates to `false` → bypass!

`getCookie()` calls `flatten()` → `implode(',', [PAYLOAD])` → returns the payload string.

### Gadget Chain

1. `Baker::load()` deserializes the cookie via `unserialize(getCookie("flans"))`
2. Payload: `{flans: [], xtra: Flan{name: Clash{flan1: Baker, flan2: Flan}}}`
3. The `xtra` key is ignored by `Baker::load()` but the object is created and then freed (refcount → 0)
4. `Flan::__destruct()` fires: `echo "<!--Flan {$this->name}-->"`
5. `$this->name` is a `Clash` object → `Clash::__toString()` → `getSummary()`
6. `getSummary()`: `$side = getParam("side")` = `"ClashSummaryByUuid"` (GET param)
7. `$this->flan1->$side` where `flan1` is `Baker` → `Baker::__get("ClashSummaryByUuid")`
8. `Baker::__get()`: calls `getClashSummaryByUuid(getParam("args"))`
9. `getClashSummaryByUuid($uuid)`: reads file and returns content embedded in HTML comment

### .cof Extension Bypass (Path Truncation)

`getClashSummaryByUuid` always appends `.cof`:
```php
$file = joinpath($CLASH_DIR . '/' . $uuid . '.cof');  // CLASH_DIR = 'records' (relative!)
$file = substr($file, 0, 100);  // truncates to 100 chars
if (file_exists($file)) return file_get_contents($file);
```

Key observations:
1. `CLASH_DIR = 'records'` is a **relative path** → `file_exists` uses CWD `/var/www/html/`
2. `joinpath()` allows `..` to bubble past the stack (when stack is empty, `..` is preserved)
3. `substr(0, 100)` truncates the result — if the joined path is > 100 chars, `.cof` can be removed

**Truncation math**: Need `joinpath(result)` to be exactly 104 chars so `substr(0,100)` removes `.cof`:
- `records` (1 segment) + 10× `../` (10 `..` segments, net 9 preserved after records pops one)
- 9 preserved `..` = `../../../../../../../../../` prefix (27 chars)
- 5× `proc/PID/root/` (13 chars each for 2-digit PID) = 65 chars
- `flag.txt.cof` = 12 chars
- Total: 27 + 65 + 12 = 104 ✓
- `substr(0,100)` = `../../../../../../../../../proc/PID/root/.../flag.txt` (no .cof)

**Path resolution** from `/var/www/html/`:
- 9 levels of `..` goes to `/` (Linux clamps at root)
- `/proc/PID/root/` is a symlink to `/` for any running PID
- 5 chains = `/proc/PID/root/proc/PID/root/.../flag.txt` = `/flag.txt`

## Exploit

```python
uuid = '../' * 10 + ('proc/28/root/') * 5 + 'flag.txt'
# Send via: GET /?side=ClashSummaryByUuid&args=UUID
# Cookie: flans[0]=URL_ENCODED_PAYLOAD
```

Full exploit: `exploit_clashofflans.py`

## Key Lessons

1. **PHP 7.4 `strpos(array, str)` = NULL** — the `!= false` check fails when result is NULL (neither 0 nor false, but NULL which != false evaluates to false)
2. **Array cookies bypass string checks** — `flans[0]=val` makes PHP treat `$_COOKIE["flans"]` as an array
3. **Relative CLASH_DIR** — path traversal works from `/var/www/html/` not from `/`
4. **`substr()` truncation as extension bypass** — if the path is long enough, the appended extension gets truncated
5. **`/proc/PID/root/` symlink chains** — resolve to `/`, allowing path traversal to root files; any running PID works
6. The 3-char problem: `13N = 91` → `N = 7` (2-digit PID gives 13-char segment); or `up=10, N=5` in the relative path version

## Discarded Approaches

1. **Stream wrappers** (`php://`, `file://`, `data://`): `joinpath()` collapses `//` → `/`
2. **`/proc/self/root/` chains**: segment = 15 chars, `15N = 91` has no integer solution
3. **`/proc/1/root/`**: segment = 12 chars, `12N = 91` has no integer solution
4. **Direct `/flag.cof`**: doesn't exist on server
5. **Absolute path joinpath assumption**: the real `joinpath()` returns relative paths (no leading `/`)

## References

- PHP deserialization gadget chains
- PHP 7.4 type coercion with `strpos()`
- Linux `/proc/PID/root` symlinks
