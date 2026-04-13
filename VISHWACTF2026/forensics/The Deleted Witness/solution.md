# The Deleted Witness - VishwaCTF 2026 (Forensics)

## Flag
`VishwaCTF{br0ws3r_h1st0ry_1s_n0t_3n0ugh}`

## TL;DR
Android extraction tar archive. Flag is in the browser app's SQLite database `searches` table, stored as a search query.

## Solve
```bash
tar xf deleted_witness_challenge.tar.gz
sqlite3 android_extraction/apps/com.legitapp.browser/databases/browser.db "SELECT * FROM searches;"
```
Output:
```
1|how to permanently delete android app data|1710000150
2|does deleting app remove database|1710000160
3|VishwaCTF{br0ws3r_h1st0ry_1s_n0t_3n0ugh}|1710000170
```

## Red Herrings
- `family_photo.jpg` EXIF comment: `VishwaCTF{fake_flag_in_exif}` (fake)
- `trip_photo.jpg` EXIF comment: `Th1s_1s_N0t_Th3_K3y` (decoy)
- `note.txt`: hints at deleted app data, misdirects toward file recovery
- `img_cache_1.tmp`: data blob, not relevant
