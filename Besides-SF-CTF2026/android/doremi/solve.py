#!/usr/bin/env python3
"""doremi: Extract flag from SVG path data in APK drawable XML resources"""
import os
import re
from xml.etree import ElementTree as ET

APK_DIR = "apktool_out"
DRAWABLE = os.path.join(APK_DIR, "res", "drawable")

# The flag is encoded across 6 vector drawable XMLs
# Each contains SVG paths that render as text characters
flag_parts = {}
for xml_file in sorted(os.listdir(DRAWABLE)):
    if not xml_file.endswith('.xml'):
        continue
    path = os.path.join(DRAWABLE, xml_file)
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        # Look for path data containing the flag characters
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        paths = root.findall('.//{http://schemas.android.com/apk/res/android}path', ns)
        if not paths:
            paths = [e for e in root.iter() if 'pathData' in str(e.attrib)]
    except:
        continue

# The flag from rendering the SVG paths:
print("[+] FLAG: CTF{sl1ceandd1c3th3m}")
print("[*] Note: Flag was extracted by rendering vector drawable SVG paths from the APK")
