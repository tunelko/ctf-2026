#!/usr/bin/env python3
"""
Mechanical Turk CAPTCHA Solver
Solves addition CAPTCHAs using tesserocr
"""

TARGET_URL = "https://bc21f57b7bf192c7.247ctf.com"

import requests
import cv2
import locale
import time
import re
locale.setlocale(locale.LC_ALL, 'C')
from tesserocr import PyTessBaseAPI, PSM, OEM
import numpy as np
from PIL import Image


def clean_noise(img):
    """Remove dark gray noise lines (color 140,140,140)"""
    lower = np.array([140, 140, 140], dtype="uint16")
    upper = np.array([141, 141, 141], dtype="uint16")
    mask = cv2.inRange(img, lower, upper)
    masked = cv2.bitwise_and(img, img, mask=mask)
    img = cv2.add(img, masked)
    return img


def upscale(img):
    """Scale image 5x using cubic interpolation"""
    return cv2.resize(img, None, fx=5, fy=5, interpolation=cv2.INTER_CUBIC)


def threshold_binary(img):
    """Apply binary threshold at 231"""
    _, result = cv2.threshold(img, 231, 255, cv2.THRESH_BINARY)
    return result


def threshold_otsu(img):
    """Apply Otsu's thresholding"""
    _, result = cv2.threshold(img, 0, 255, cv2.THRESH_OTSU)
    return result


def fix_contrast(img):
    """Adjust brightness and contrast"""
    return cv2.convertScaleAbs(img, alpha=1.0, beta=1)


TESS_PATH = "/usr/share/tesseract-ocr/5/tessdata"


def solve():
    with PyTessBaseAPI(psm=PSM.SINGLE_WORD, oem=OEM.TESSERACT_ONLY, path=TESS_PATH) as ocr:
        ocr.SetVariable("tessedit_char_whitelist", "0123456789+")

        session = requests.session()
        resp = session.get(TARGET_URL)
        cookies = {'PHPSESSID': resp.cookies['PHPSESSID']}

        start = time.time()
        correct = 0

        for i in range(500):
            if time.time() - start > 30:
                break

            # Fetch CAPTCHA
            raw = session.get(TARGET_URL + "/mturk.php", cookies=cookies, stream=True).raw
            data = np.asarray(bytearray(raw.read()), dtype="uint8")
            img = cv2.imdecode(data, cv2.IMREAD_COLOR)

            # Preprocess
            img = clean_noise(img)
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            img = fix_contrast(img)
            img = threshold_binary(img)
            img = upscale(img)
            img = threshold_otsu(img)

            # OCR
            ocr.SetImage(Image.fromarray(img))
            text = ocr.GetUTF8Text().replace(" ", "").rstrip()

            # Parse equation
            answer = None
            try:
                if '+' in text:
                    parts = text.split('+')
                    answer = int(parts[0]) + int(parts[1])
                else:
                    answer = int(text[:6]) + int(text[6:])
            except:
                continue

            # Submit
            resp = session.post(TARGET_URL, data={"captcha": answer}, cookies=cookies)

            if '247CTF' in resp.text:
                flag = re.search(r'247CTF\{[^}]+\}', resp.text)
                if flag:
                    print(f"FLAG: {flag.group(0)}")
                return True

            if 'Invalid' not in resp.text:
                correct += 1

        print(f"Solved {correct} in {time.time()-start:.1f}s")
        return False


if __name__ == "__main__":
    for attempt in range(10):
        print(f"Attempt {attempt + 1}")
        if solve():
            break
