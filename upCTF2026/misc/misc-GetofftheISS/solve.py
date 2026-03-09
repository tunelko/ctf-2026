#!/usr/bin/env python3
"""
Challenge: Get off the ISS — upCTF 2026
Category:  misc (SDR / radio triangulation)
Flag:      upCTF{fl4t_e4rth3rs_cou1d_n3v3r-YXla8Qimaa20b7a9}

Three rotating directional antennas record IQ at 146MHz.
Find the jammer by extracting bearing angles from power envelope peaks
and triangulating the intersection of bearing lines.
"""
import numpy as np
import math
import requests

# === Station coordinates (from challenge.md) ===
STATIONS = {
    'station_a': (41.16791628282458, -8.688654341122007),
    'station_b': (41.14456438258019, -8.675380772847733),
    'station_c': (41.1413904156136,  -8.609071069291119),
}

SAMPLE_RATE = 500_000       # Hz
ROTATION_PERIOD = 10.0      # seconds per full 360° rotation
POWER_THRESHOLD = 0.1       # above noise floor
TARGET = "http://46.225.117.62:30028"


def find_peak_bearing(filename):
    """Load IQ data, compute power envelope, find peak time → bearing angle."""
    data = np.fromfile(filename, dtype=np.complex64)

    # 10ms windows for power envelope
    win = 5000
    n = len(data) // win
    powers = np.array([np.mean(np.abs(data[i*win:(i+1)*win])**2) for i in range(n)])
    times = np.arange(n) * (win / SAMPLE_RATE)

    # Find contiguous segments above threshold (signal bumps)
    above = powers > POWER_THRESHOLD
    segments, in_seg, start = [], False, 0
    for i in range(len(above)):
        if above[i] and not in_seg:
            start, in_seg = i, True
        elif not above[i] and in_seg:
            segments.append((start, i))
            in_seg = False
    if in_seg:
        segments.append((start, len(above)))

    # Center-of-mass of each bump → peak time
    peak_times = []
    for s, e in segments:
        t = np.average(times[s:e], weights=powers[s:e])
        peak_times.append(t)

    # First peak time modulo period → bearing angle
    peak_t = peak_times[0]
    bearing = (peak_t % ROTATION_PERIOD) / ROTATION_PERIOD * 360.0
    return bearing, peak_times


def bearing_intersection(lat1, lon1, b1_deg, lat2, lon2, b2_deg):
    """Intersect two bearing lines using flat-earth approximation."""
    b1, b2 = math.radians(b1_deg), math.radians(b2_deg)
    # Direction: bearing → (east, north) = (sin, cos)
    dx1, dy1 = math.sin(b1), math.cos(b1)
    dx2, dy2 = math.sin(b2), math.cos(b2)

    lat_mid = (lat1 + lat2) / 2
    s = math.cos(math.radians(lat_mid))  # longitude scale factor
    x1, y1 = lon1 * s, lat1
    x2, y2 = lon2 * s, lat2

    # P1 + t1·d1 = P2 + t2·d2
    det = dx1 * (-dy2) + dx2 * dy1
    if abs(det) < 1e-10:
        return None, None
    t1 = ((-dy2) * (x2 - x1) + dx2 * (y2 - y1)) / det
    return y1 + t1 * dy1, (x1 + t1 * dx1) / s


# === Extract bearings ===
bearings = {}
for name in STATIONS:
    bearing, peaks = find_peak_bearing(f'handout/{name}.sigmf-data')
    bearings[name] = bearing
    period = np.mean(np.diff(peaks)) if len(peaks) > 1 else ROTATION_PERIOD
    print(f'{name}: peaks={[f"{t:.3f}" for t in peaks]}, period={period:.3f}s, bearing={bearing:.2f}°')

# === Triangulate (3 pairs → average) ===
pairs = [('station_a', 'station_b'), ('station_a', 'station_c'), ('station_b', 'station_c')]
intersections = []
for n1, n2 in pairs:
    lat1, lon1 = STATIONS[n1]
    lat2, lon2 = STATIONS[n2]
    ilat, ilon = bearing_intersection(lat1, lon1, bearings[n1], lat2, lon2, bearings[n2])
    if ilat is not None:
        intersections.append((ilat, ilon))
        print(f'Intersection {n1}+{n2}: ({ilat:.6f}, {ilon:.6f})')

jammer_lat = np.mean([p[0] for p in intersections])
jammer_lon = np.mean([p[1] for p in intersections])
print(f'\nJammer location: ({jammer_lat:.6f}, {jammer_lon:.6f})')

# === Submit ===
resp = requests.post(f'{TARGET}/verify', json={'lat': jammer_lat, 'lon': jammer_lon})
data = resp.json()
print(f'\nResponse: {data["message"]}')
if data.get('success'):
    print(f'FLAG: {data["message"].split("Flag: ")[1]}')
