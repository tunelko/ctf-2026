# Ransomware Hospital 2

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | Rooted 2026 / CaliphAllabs     |
| Category    | research (forensics / OSINT)   |
| Difficulty  | Medium                         |
| Author      | Kesero                         |

## Description
> El Hospital Aguilera ha sido victima de un ataque de ransomware a gran escala. Todavia no se sabe el alcance exacto del ciberataque, pero se confirma que ha comprometido archivos medicos criticos de los pacientes de todo el hospital. Como analista del equipo, debes apoyar al CISO (Adrian Jimenez) en la respuesta tecnica al incidente. Se te ha facilitado un volcado de los correos corporativos enviados el dia del ciberataque junto con el flujo de informacion interna generado tras detectar la intrusion. En este caso, deberas desenmascarar al atacante consiguiendo su nombre completo.
> Nota: Si el nombre completo es Antonio Maura Sanchez, la flag sera clctf{Antonio_Maura_Sanchez}

## TL;DR
From the forensic evidence in Part 1 (alias "Louden", C2, git repository), the ransomware negotiation .onion site is accessed. The attacker's chat reveals a trollface image containing a hidden URL to a newspaper article that identifies **Alberto Sanchez Trujillo** as the leader of the "Feudal Cats" CTF team, known by the alias **Louden**.

## Initial Analysis

### Prior Evidence (Part 1)
From the `bash_history` and C2 analysis in Part 1, key attacker data was obtained:
- **Alias:** `louden`
- **Email:** `louden@proton.me` (from git commit)
- **C2:** `http://challs.caliphallabs.com:18971` (credentials: `louden:M4st4rH4ck3r567!`)
- **Gitea:** `http://challs.caliphallabs.com:34698/louden/ransomware-hospital`
- **Victims on C2:** Bazar-alimentacion, Hospital, Jewlery, Kebab-house, Sport-center (5 compromised organizations)

### Attacker's Git Repository
```
$ git log --oneline
commit by "Louden <louden@proton.me>"
"Initial commit - Source code"
```
The repo contains the ransomware source code (Fernet encryption), with the banner `"Hospital Ransom by Louden"` in `ransom.py`. The `full_name` field in the Gitea profile is empty — it does not directly reveal the real identity.

## Solution Process

###  Access the .onion negotiation site

The challenge provides the onion address and an authentication code:
- **URL:** `http://4i27p33r6mcjwfazyf5oms3pua6cdssuckr4dsqg2g6vmt6v5o2lhiad.onion/`
- **Code:** `LOU-HOSP-8821`

Access via Tor Browser to the `/chat` endpoint and entering the authentication code initiates the negotiation with the attacker.

###  Trollface image with hidden URL

In the negotiation chat, the attacker sends an image: a **trollface** coming out of a printer (classic meme).

```
evidence/onion/Trollface.jpeg  (930 KB, 2268x4032)
```

The image contains no relevant EXIF metadata (no GPS, no author, no comments). However, on the printer next to the trollface there is a partially visible printed sheet containing a URL. This URL can be read directly from the image:

```
http://newspaper.challs.caliphallabs.com/exclusiva/feudal-cats
```

###  Newspaper article reveals the identity

The URL points to a fictitious newspaper article from **"La Cronica / Tech"** with the headline:

> **"Feudal Cats reach the world runner-up spot at GoogleCTF 2025"**

The article reveals:

> *"The team, led by the technical mastery of **Alberto Sanchez Trujillo** (known in the community as **Louden**), fielded a star-studded lineup for this edition."*

Key data from the article:
- **Real name:** Alberto Sanchez Trujillo
- **Alias:** Louden (confirmed as the same alias as the attacker)
- **CTF Team:** Feudal Cats (GoogleCTF 2025 runners-up)
- **Origin:** Galicia, Spain
- **Other members mentioned:** Eduardo Perez Fernandez, Sebastian Rodriguez Simon

###  Identity correlation

The connection alias `Louden` → real person is confirmed by multiple sources:

| Evidence | Alias | Source |
|----------|-------|--------|
| bash_history (C2 login) | `louden` | Part 1 - forensics |
| Git commit author | `Louden <louden@proton.me>` | Gitea repo |
| Ransomware banner | `"Hospital Ransom by Louden"` | ransom.py |
| Negotiation code | `LOU-HOSP-8821` | Part 2 - challenge |
| Newspaper article | `Louden` = Alberto Sanchez Trujillo | newspaper URL |

## Discarded Approaches
- **Gitea API:** The `full_name` field on Louden's profile is empty. Real name cannot be obtained from there.
- **EXIF metadata of Trollface.jpeg:** No useful data (no GPS, no author, no hidden comments).
- **Other Gitea users:** Only the `Louden` user exists on the instance.
- **C2 server exploration:** Victim directories (Hospital, Jewlery, etc.) only contain credentials and keys, no personal information about the attacker.

## Flag
```
clctf{Alberto_Sánchez_Trujillo}
```

## Key Lessons
- In forensic OSINT, attackers can be de-anonymized when they reuse aliases between legitimate activities (CTF) and malicious operations (ransomware)
- Ransomware negotiation channels (.onion) can leak attacker information if they leave clues (images with URLs, messages, etc.)
- Alias correlation across multiple sources (git commits, C2, source code, public articles) is a key attribution technique
- The attacker's OPSEC failed by using the same alias "Louden" in both public CTF competitions and ransomware operations

## References
- MITRE ATT&CK T1589 - Gather Victim Identity Information
- MITRE ATT&CK T1593 - Search Open Websites/Domains
- Tor Project: https://www.torproject.org/
