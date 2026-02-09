#!/usr/bin/env python3
"""
WASM Secret - 247CTF Solver
Crackea la flag usando prefijos acumulados de bcrypt
"""

import bcrypt

hashes = [
    b"$2b$12$uAfq9EI1EoIC316VgA3azeOyogkKzG4zz2kF8M.l.D4h4nT4WsidK",
    b"$2b$12$NmhDm/LZzjanlv6xuHCsVe8JJNlvEb3uYUEQ03abPIlCuTE6qtrT.",
    b"$2b$12$8OhK6ZPoSuBujRxR3pz4g.vp6LvTqJe/NJZZHTHtOPkdIbDb1GDKS",
    b"$2b$12$PhFiPd28yDeXdZaJfUDjTOiAUQtpBJ2AjD5pFIG7CtUXQtWECGpre",
    b"$2b$12$DfQJicmUWZQ0EVGKxdQEN.yCj3s4o6GyMraqt514d3DRkAqH8PYq6",
    b"$2b$12$JikQohCsuFN6DO7q9ZHCTeHuzL3/Hb3diMYJsUGgAI4AH64x9jtyO",
    b"$2b$12$4C2jJ0QxCKdqyrBTIhqEGeeq1IMOZJs7DllwqtMWbp.rM7BPsbDwG",
    b"$2b$12$FI45z3VbyCC4Bb5rVJsLb./Od6aSnT8tHIPkwmZCgGNNrXwpJqkO6",
    b"$2b$12$tFkj/QdzBVsk8XjjjH91eefYY/lx6YX/4lnB9T/GKSIvpmx7mEEG2",
    b"$2b$12$Il.BDj/qxIkgROEZN4/Te.QJawuPW18MHU1hVQzNIC9SW7H.Mo9.2",
    b"$2b$12$3UOGifrFe0iGGh4sSWx1JeB919LDApovzwbYIQqniIFVE3/mgEFkW",
    b"$2b$12$5voYYJHxGJVy3ITneNhk/.XbcfOKDDnMHiS2CTri0ncFQ/jUgND.e",
    b"$2b$12$cDvS2AqrJ72gvUP5wSnjSOqdsFIKcsGI863NxXgdedYzMV0YzOZmW",
    b"$2b$12$pIcJfpN7L0SGQtA/4bcX.ewqrSkeUzCeq4mrjHCzhwQKB2LTc4tJe",
    b"$2b$12$4xjImCcvXpgG.WFwjlryEONm4gFy3/O2VSCsrL1lX38f0XDPKc6Hm",
    b"$2b$12$gIWlY5GubfJ1kIhMEO9GnuTbalD8aPc6ECdNIq.4Vjx6S38nKLG8S",
    b"$2b$12$9UpsAlXYVpPw4B93u2WBm.Ve0JMqdkQ0wxvuAPqnXmtzjmvXm0hea",
    b"$2b$12$QqTL8meoLdWMnipKwuRoC.d9ei6TU2ev1Ggu0VsC2gLGMfF7QWOPi",
    b"$2b$12$8M.Z95IrSP64adu2LiOhzO4vhtmfjBx45Pp.FJsq4Tqe/t5GaPeA2",
    b"$2b$12$GNWfLovpvpMcoK89QdZzt.u8XibRtwo0aFFnUSBcqs0SjocL6hgVS",
    b"$2b$12$mLzTYglkEg3iqusfz8lOOuH548ezA.mgfr8pYI7cd3ozU8aPJBhAC",
    b"$2b$12$6GTg.qAyDUQorM1BwcIXRe7Ab.L3ZXqJhI0xg2G.OtCVf5W1BH7zu",
    b"$2b$12$Nxd1aKxcgV4s51dN5nc2puAtG8J6asT8vcvB0kfWhcfYp868nza7.",
    b"$2b$12$Z2/4n8JEXI19ZFL7A4ojEOiSbfAeV3KZj5Nc0.Uu6sXG6KHvtPCLi",
    b"$2b$12$AEiJfo2eTPnTCU.NL2jJeOifcw/TOAZaOLjMAPKEdfJmgdQy/WoYC",
    b"$2b$12$8pA4oDi3uovODvOuf2GrteqltIOhDUH/AI07H1NrvCoA5AvL9vKJe",
    b"$2b$12$Kke80penOJ8l7/EBoDZCWufdwdWju/Twb6.9DSm498.I922qNBfBK",
    b"$2b$12$xOcqWzPSMN3VgbsmEmZbYe98NBK1Qxpp6fAZNYCEiU/Lw5vsbIOz.",
    b"$2b$12$OnXeQsiQyBpIZzciVGSkUuBwcr62OoirL8Ebb9QczH7AAFdIsrbxi",
    b"$2b$12$3c8V9ss5ATsQkkz0ZUg2T.x0qCBszvuetJPX.vm9XPgsGBwhedfhy",
    b"$2b$12$xVrrb1qPs3mHX2kp6vo10e8zsUqDxXxlmptJnFBT/5YVDeSGAJsty",
    b"$2b$12$BA5vnPd.oxWN4BEn6PybEeXgWYrX02k9rHXLnDAiDedUilCuiv2jy",
    b"$2b$12$7p6s4NoKXsjqD/0wnuO2b.2ux70dPNcN5wBYccuzz8vm1ZZ9iPPLu",
    b"$2b$12$oXuFS3O5Td3knq2gRyf5XOhwj1.IYOWQ9fSvGY05YU0MwizIm18Ru",
    b"$2b$12$l3wvb/fiYbkzoqWv1.ulMuQPTn6xP67D0/YkjNzwJi1bK30qJAZWu",
    b"$2b$12$3eFpVZJh6TfrnbE.hdfitu8UiqLei7u2vEjFPecu6O5FqNqyOYOs.",
    b"$2b$12$XtrkQGAyvRcIdCtW4AK9/.9oSlP2rAwE.KNk5f2sKuyhhDNzIAvzC",
    b"$2b$12$zrsIpC4WnPVjcCRODlRXT.IDPIZwBEP2VwTv.q5/DIfCpdD44zoam",
    b"$2b$12$Lr3UiwLPab6yEw.TERhNAu1/qlQelYuqmF/Wcg3UtrzslAzrf3/di",
    b"$2b$12$RtpdIcXU8hH8pnDGQHCupu5l2mw872X6SFamb20w9A.sieVEk7Xba",
]

# Caracteres posibles en la flag: 247CTF{} + hex
charset = "0123456789abcdefCTF{}247"

def crack():
    flag = ""

    print("Crackeando flag por prefijos acumulados...")
    print("=" * 50)

    for i, h in enumerate(hashes):
        found = False
        for c in charset:
            candidate = flag + c
            if bcrypt.checkpw(candidate.encode(), h):
                flag = candidate
                print(f"[{i:02d}] {flag}")
                found = True
                break

        if not found:
            print(f"[{i:02d}] ERROR: No se encontro caracter despues de '{flag}'")
            return None

    print("=" * 50)
    return flag

if __name__ == "__main__":
    result = crack()
    if result:
        print(f"\nFLAG: {result}")
