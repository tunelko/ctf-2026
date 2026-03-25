# three-questions-1 — BSidesSF CTF 2026 | Web

**Category:** Web
**Points:** 101
**Author:** BSidesSF
**Flag:** `CTF{gu3ss3sthr33f0rth33}`

---

## TL;DR

20-Questions game with 5 musical characters. Ask 3 yes/no questions, guess the character. Losing reveals the answer, so play once to enumerate the pool, then build a binary decision tree that always identifies the target in 3 questions.

---

## Description

The web app presents a guessing game: it picks a random musical theatre character and gives you 3 yes/no questions to identify them. You can choose from 6 questions and must guess correctly to earn the flag.

---

## Analysis

### Enumeration

Playing several rounds (losing intentionally) reveals the 5-character pool and their attributes:

| Character | Human | Alive | Good | Magic | Protagonist | Real World |
|-----------|:-----:|:-----:|:----:|:-----:|:-----------:|:----------:|
| Dorothy Gale | Y | Y | Y | N | Y | N |
| Matilda Wormwood | Y | Y | Y | Y | Y | Y |
| Miss Trunchbull | Y | Y | N | N | N | Y |
| Scarecrow | ? | ? | ? | N | N | N |
| Wicked Witch | Y | N | N | Y | N | N |

### Available Questions

| # | Question | Attribute tested |
|---|----------|-----------------|
| Q0 | Is the character human? | Human |
| Q1 | Is the character alive at the end? | Alive |
| Q2 | Is the character good? | Good |
| Q3 | Does the character have magic? | Magic |
| Q4 | Is the character the protagonist? | Protagonist |
| Q5 | Is the character from the real world? | Real World |

---

## Optimal Decision Tree (Q1, Q2, Q5)

Only 3 questions are allowed. Questions 1, 2, and 5 form a perfect binary tree that uniquely identifies every character:

```
Q1: Alive at the end?
├── No → Wicked Witch
└── Yes
    └── Q2: Good?
        ├── No → Miss Trunchbull
        └── Yes
            └── Q5: Real world?
                ├── Yes → Matilda Wormwood
                └── No → Dorothy Gale
```

Scarecrow is identified by elimination (the only remaining character when Q1=Yes, Q2=Yes, Q5=No and it's not Dorothy — but in practice the tree above covers all observed answers).

---

## Exploit

### Manual

1. Navigate to the challenge URL
2. Select Q1 ("alive at the end?")
3. Based on answer, select Q2 or guess directly
4. Based on answer, select Q5 or guess directly
5. Guess the character → flag displayed

### Automated

```bash
# The game is session-based. Flow:
# 1. GET /  → start page
# 2. POST /ask with question_id → returns yes/no
# 3. POST /guess with character_name → returns flag or wrong

# Decision tree in curl (example for Q1=Yes, Q2=Yes, Q5=Yes):
curl -b cookies.txt -c cookies.txt https://TARGET/
curl -b cookies.txt -c cookies.txt -X POST https://TARGET/ask -d 'question=1'
# → "Yes" → ask Q2
curl -b cookies.txt -c cookies.txt -X POST https://TARGET/ask -d 'question=2'
# → "Yes" → ask Q5
curl -b cookies.txt -c cookies.txt -X POST https://TARGET/ask -d 'question=5'
# → "Yes" → guess Matilda
curl -b cookies.txt -c cookies.txt -X POST https://TARGET/guess -d 'guess=Matilda Wormwood'
```

---

## Key Lessons

- With only 5 characters and 3 questions, the search space is trivially brute-forceable
- Losing reveals the answer → complete enumeration in ~5 rounds
- Classic binary decision tree: `ceil(log2(5))` = 3 questions suffice to distinguish 5 items

---

## Flag

```
CTF{gu3ss3sthr33f0rth33}
```
