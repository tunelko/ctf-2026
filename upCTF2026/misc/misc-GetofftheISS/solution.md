# Get off the ISS — upCTF 2026

**Category:** MISC (SDR / Radio Triangulation)
**Flag:** `upCTF{fl4t_e4rth3rs_cou1d_n3v3r-YXla8Qimaa20b7a9}`

## TL;DR

Three rotating directional antennas in Porto record IQ signal at 146 MHz (European ISS uplink frequency). Each antenna completes one rotation (360°) every 10 seconds, starting at 0° = North at t=0. The jammer appears as a power peak when the antenna points in its direction. Extracting the peak time from each station yields the bearing (angle), and triangulating the three bearing lines locates the jammer with ~6 meter precision.

---

## Analysis

### Infrastructure

```
Web: Leaflet map centered on Porto (POST /verify with {lat, lon})
Handout: 3 SigMF files (station_a, station_b, station_c)
  - Format: cf32_le (complex float32 little-endian)
  - Sample rate: 500 kHz
  - Center frequency: 146 MHz (ISS European uplink ≈ 145.99 MHz)
  - Duration: 30 seconds per station
```

### Station Coordinates

| Station | Latitude | Longitude |
|---------|----------|-----------|
| A | 41.167916 | -8.688654 |
| B | 41.144564 | -8.675381 |
| C | 41.141390 | -8.609071 |

### Signal Model

Each antenna is **directional and rotating**:
- Starts pointing **North (0°)** at t=0
- Completes a full 360° rotation every **10 seconds** (36°/s)
- When the antenna points toward the jammer, received power increases

The power pattern shows **one bump every 10 seconds** — a single pass per rotation. The center of the bump indicates the exact moment when the antenna points directly at the jammer.

### Power Envelope

Computing the average power in 10ms windows:

**Station A:**
```
t=1.9s  ██████████
t=2.0s  ███████████████████
t=2.1s  ███████████████████████
...
t=2.8s  █████████████████████████████████████████  ← PEAK (2.813s)
...
t=3.5s  █████████████████████
t=3.7s  ████
```

**Station B:**
```
t=0.9s  ██████
t=1.0s  ██████████████████
...
t=1.8s  ████████████████████████████████████████  ← PEAK (1.836s)
...
t=2.7s  ███████
```

**Station C:**
```
t=7.9s  ████████████
t=8.0s  ████████████████████
...
t=8.8s  ██████████████████████████████████████████  ← PEAK (8.807s)
...
t=9.6s  ██████████████
```

### Bearing Calculation

```
bearing = (peak_time mod 10.0) / 10.0 × 360°
```

| Station | Peak time | Bearing |
|---------|-----------|---------|
| A | 2.813s | 101.28° |
| B | 1.836s | 66.08° |
| C | 8.807s | 317.04° |

---

## Triangulation

### Method

With 3 stations at known positions and a bearing from each one, the jammer is at the **intersection of the 3 bearing lines**.

A flat-earth approximation is used (valid for distances of a few km within the same city):

1. Convert bearing to direction vector: `(sin(b), cos(b))` = (east, north)
2. Scale longitudes by `cos(lat)` to compensate for meridian convergence
3. Solve linear system `P₁ + t₁·d₁ = P₂ + t₂·d₂` for each pair of stations
4. Average the 3 intersections

### Results

| Pair | Intersection |
|------|-------------|
| A + B | (41.159297, -8.631271) |
| A + C | (41.159287, -8.631204) |
| B + C | (41.159313, -8.631232) |

**Maximum dispersion: 6 meters** — the three lines converge almost perfectly.

**Jammer location: (41.159299, -8.631235)**

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
import numpy as np, math, requests

STATIONS = {
    'station_a': (41.16791628282458, -8.688654341122007),
    'station_b': (41.14456438258019, -8.675380772847733),
    'station_c': (41.1413904156136,  -8.609071069291119),
}
SAMPLE_RATE = 500_000
ROTATION_PERIOD = 10.0

def find_peak_bearing(filename):
    data = np.fromfile(filename, dtype=np.complex64)
    win = 5000  # 10ms windows
    n = len(data) // win
    powers = np.array([np.mean(np.abs(data[i*win:(i+1)*win])**2) for i in range(n)])
    times = np.arange(n) * (win / SAMPLE_RATE)

    # Find bumps above noise
    above = powers > 0.1
    segments, in_seg, start = [], False, 0
    for i in range(len(above)):
        if above[i] and not in_seg: start, in_seg = i, True
        elif not above[i] and in_seg: segments.append((start, i)); in_seg = False
    if in_seg: segments.append((start, len(above)))

    # Center-of-mass → peak time → bearing
    peak_t = np.average(times[segments[0][0]:segments[0][1]],
                        weights=powers[segments[0][0]:segments[0][1]])
    return (peak_t % ROTATION_PERIOD) / ROTATION_PERIOD * 360.0

def bearing_intersection(lat1, lon1, b1, lat2, lon2, b2):
    b1, b2 = math.radians(b1), math.radians(b2)
    dx1, dy1 = math.sin(b1), math.cos(b1)
    dx2, dy2 = math.sin(b2), math.cos(b2)
    s = math.cos(math.radians((lat1+lat2)/2))
    x1, y1, x2, y2 = lon1*s, lat1, lon2*s, lat2
    det = dx1*(-dy2) + dx2*dy1
    t1 = ((-dy2)*(x2-x1) + dx2*(y2-y1)) / det
    return y1 + t1*dy1, (x1 + t1*dx1) / s

bearings = {n: find_peak_bearing(f'handout/{n}.sigmf-data') for n in STATIONS}
pairs = [('station_a','station_b'), ('station_a','station_c'), ('station_b','station_c')]
pts = [bearing_intersection(*STATIONS[a], bearings[a], *STATIONS[b], bearings[b]) for a,b in pairs]
lat, lon = np.mean([p[0] for p in pts]), np.mean([p[1] for p in pts])

resp = requests.post('http://46.225.117.62:30028/verify', json={'lat': lat, 'lon': lon})
print(resp.json()['message'])
```

```bash
cd handout && python3 ../solve.py
# Signal Acquired! Flag: upCTF{fl4t_e4rth3rs_cou1d_n3v3r-YXla8Qimaa20b7a9}
```

---

## Discarded Approaches

| # | Approach | Why it was not needed |
|---|----------|-----------------------|
| 1 | Frequency analysis (FFT, spectrogram) | The relevant information is in the temporal power envelope, not in the spectrum |
| 2 | Jammer signal demodulation | There is no encoded data in the signal — we only need the direction |
| 3 | TDOA (Time Difference of Arrival) | The data is not synchronized between stations; the challenge uses bearing, not timing |

---

## Key Lessons

1. **SigMF is a standard SDR format**: `.sigmf-data` = raw IQ, `.sigmf-meta` = JSON with sample rate, frequency, data type
2. **Rotating antenna → temporal bearing**: the time of the power peak within the rotation period directly gives the bearing angle
3. **Flat-earth triangulation works at urban scale**: for distances of a few km, Earth curvature correction is negligible
4. **Center-of-mass > max**: to find the exact peak of a smooth bump, power-weighted center of mass is more robust than the maximum value
5. **146 MHz = ISS repeater**: European ISS uplink frequency, consistent with the challenge lore

## References

- [SigMF specification](https://github.com/gnuradio/SigMF/blob/main/sigmf-spec.md)
- [ISS Repeater frequencies](https://www.ariss.org/contact-the-iss.html)
- [Radio Direction Finding (RDF)](https://en.wikipedia.org/wiki/Direction_finding)
- [Triangulation](https://en.wikipedia.org/wiki/Triangulation)
