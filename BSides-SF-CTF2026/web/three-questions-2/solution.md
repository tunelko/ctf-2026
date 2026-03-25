# three-questions-2 — BSidesSF CTF 2026 | Web

**Category:** Web
**Points:** 101
**Author:** BSidesSF
**Flag:** `CTF{d3buggu3sseswith0utmess35}`

---

## TL;DR

Same 20-questions mechanic as part 1, but the answer is NOT revealed on failure. The character pool is much larger (all of musical theatre). Brute-force by registering fresh accounts, asking 3 profiling questions (human/alive/good) to narrow the pool, then guessing from a curated candidate list per profile. One attempt per account.

---

## Description

Identical game mechanic to three-questions-1, but two key differences:

1. **The answer is never revealed** — losing just says "wrong" with no hint
2. **The character pool is vastly larger** — drawn from all musical theatre characters

This turns the problem from decision-tree into brute-force: profile the target with 3 questions, build candidate lists per profile, and iterate accounts until a guess hits.

---

## Differences from Part 1

| Feature | Part 1 | Part 2 |
|---------|--------|--------|
| Answer revealed on loss | Yes | **No** |
| Character pool | 5 known | Large, unknown |
| Strategy | Decision tree | Profiling + brute-force |

---

## Approach

### Step 1: Profile with Q0/Q1/Q2

Ask 3 questions to determine the target's profile:
- **Q0**: Is the character human?
- **Q1**: Is the character alive at the end?
- **Q2**: Is the character good?

This yields `2^3 = 8` possible profiles, each narrowing candidates to a manageable list.

### Step 2: Curate Candidate Lists

For each profile `(Human?, Alive?, Good?)`, compile a list of musical theatre characters matching:

| Profile (H/A/G) | Candidates |
|------------------|-----------|
| Y/Y/Y | Elphaba, Glinda, Christine Daaé, Matilda, Eliza Hamilton, Anna, Dorothy Gale, Fiona, Maria, ... |
| Y/Y/N | Miss Trunchbull, Phantom, Aaron Burr, King George III, Javert, ... |
| Y/N/Y | Hamilton, Fantine, Eponine, Angel Dumott Schunard, ... |
| Y/N/N | Sweeney Todd, Wicked Witch of the East, ... |
| N/Y/Y | Simba, Lumiere, Olaf, ... |
| N/Y/N | Scar, Ursula, Audrey II, ... |
| N/N/Y | **Grizabella**, Mufasa, ... |
| N/N/N | ... |

### Step 3: Brute-Force

For each attempt:
1. Register a fresh account (new session)
2. Ask Q0, Q1, Q2
3. Look up the profile in the candidate table
4. Guess the next untried candidate for that profile
5. If correct → flag. If wrong → next account.

---

## Winning Guess

The flag-yielding character was profile **(!Human, !Alive, Good)** → **Grizabella** from *Cats*.

Reasoning:
- **Not human**: she's a cat
- **Not alive at the end**: she ascends to the Heaviside Layer (dies/transcends)
- **Good character**: sympathetic, redeemed in the finale

---

## Key Lessons

- When the oracle doesn't reveal the answer, profiling + brute-force replaces decision trees
- Musical theatre has deep character lore — non-obvious categorizations (Grizabella is "not alive" because ascending to the Heaviside Layer counts as death)
- Fresh accounts bypass per-account rate limiting
- 3 binary questions give 8 profiles, each with ~10-20 candidates — manageable brute-force

---

## Flag

```
CTF{d3buggu3sseswith0utmess35}
```
