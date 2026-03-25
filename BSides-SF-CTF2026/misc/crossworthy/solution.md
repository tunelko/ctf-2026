# crossworthy2026 — BSidesSF CTF 2026 | Misc

**Category:** Misc
**Author:** BSidesSF
**Flag:** `CTF{mp3}`

---

## TL;DR

Crossword puzzle where 70 across is the flag. Cross-referencing clues reveals an audio encoding format that "breaks typical crossword rules" by containing a number: **MP3**.

---

## Description

A standard crossword puzzle provided as an HTML file (`crossworthy2026.html`) with grid image and clues. The flag is the answer to **70 Across**.

---

## Files

- `crossworthy2026.html` — interactive crossword
- `grid.png` / `grid.svg` — crossword grid
- `clues.txt` — full clue list

---

## Key Clues

| Clue # | Direction | Clue Text | Answer | Relevance |
|--------|-----------|-----------|--------|-----------|
| **70** | **Across** | "A format for encoding audio" | **MP3** | **The flag** |
| 15 | Across | "Like ZIPs (and 70 acrosses)" | COMPRESSED | MP3 is a compressed format |
| 41 | Across | "A binary-based system (also required to play 70 across!)" | COMPUTER | MP3 requires a computer/digital player |
| 58 | Across | "An audio file might have 44,100 of these per second" | SAMPLES | 44.1kHz = CD-quality sample rate |

### Why MP3?

| Property | MP3 | Match |
|----------|-----|-------|
| Audio encoding format | MPEG-1 Audio Layer III | yes |
| Compressed like ZIP | Lossy compression | yes |
| Played on a computer | Digital format | yes |
| 44,100 samples/sec | Standard sample rate | yes |
| **Breaks crossword rules** | Contains the digit "3" | yes |

The meta-clue "breaks a typical crossword rule" refers to crossword convention that answers should be all letters — **MP3** contains a number, which is unusual.

---

## Flag

```
CTF{mp3}
```
