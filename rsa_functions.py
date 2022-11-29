from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256


def create_RSAKey():
    key = RSA.generate(2048)

    return key


def save_RSAKey_Private(fichero, key, password):
    key_cifrada = key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
    file_out = open(fichero, "wb")
    file_out.write(key_cifrada)
    file_out.close()


def load_RSAKey_Private(fichero, password):
    key_cifrada = open(fichero, "rb").read()
    key = RSA.import_key(key_cifrada, passphrase=password)

    return key


def save_RSAKey_Public(fichero, key):
    key_pub = key.publickey().export_key()
    file_out = open(fichero, "wb")
    file_out.write(key_pub)
    file_out.close()


def load_RSAKey_Public(fichero):
    keyFile = open(fichero, "rb").read()
    key_pub = RSA.import_key(keyFile)

    return key_pub


def cipherRSA_OAEP(cadena, key):
    datos = cadena
    engineRSACifrado = PKCS1_OAEP.new(key)
    cifrado = engineRSACifrado.encrypt(datos)

    return cifrado


def decipherRSA_OAEP(cifrado, key):
    engineRSADescifrado = PKCS1_OAEP.new(key)
    datos = engineRSADescifrado.decrypt(cifrado)
    cadena = datos

    return cadena


def cipherRSA_OAEP_BIN(datos, key):
    engineRSACifrado = PKCS1_OAEP.new(key)
    cifrado = engineRSACifrado.encrypt(datos)

    return cifrado


def decipherRSA_OAEP_BIN(cifrado, key):
    engineRSADescifrado = PKCS1_OAEP.new(key)
    datos = engineRSADescifrado.decrypt(cifrado)

    return datos


def signatureRSA_PSS(datos, key_private):
    h = SHA256.new(datos)
    signature = pss.new(key_private).sign(h)

    return signature


def checkRSA_PSS(datos, firma, key_public):
    h = SHA256.new(datos)
    verifier = pss.new(key_public)

    verifier.verify(h, firma)
    return True
