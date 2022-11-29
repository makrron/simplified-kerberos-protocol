import json
import sys

import aes_functions
import rsa_functions
from exceptions.Exceptions import IncorrectData
from socket_class import SOCKET_SIMPLE_TCP


def receiveAESMessage(s):
    return s.receive(), s.receive(), s.receive()


def checkMessageGCM(key, iv, cif, mac):
    res = aes_functions.decipherAES_GCM(key, iv, cif, mac)
    if res is not False:
        return res
    else:
        print("AIUDAAAA :(")
        print("Corrupted Message")


def sendAESMessage(socket, criptograma, mac, nonce):
    socket.send(criptograma)
    socket.send(mac)
    socket.send(nonce)


def bob_socket(port):
    return SOCKET_SIMPLE_TCP('127.0.0.1', port)


class Bob:
    def __init__(self):
        self.name = "Bob"
        self.port = 5552
        self.PK_BOB = rsa_functions.create_RSAKey()
        self.KBT = aes_functions.create_AESKey()
        self.KPT = rsa_functions.load_RSAKey_Public("TTP.pub")

    def savePK(self):
        return rsa_functions.save_RSAKey_Public("Bob.pub", self.PK_BOB)


if __name__ == '__main__':
    """--STEP 0--"""
    bob = Bob()
    bob.savePK()
    print(bob.PK_BOB.public_key().export_key())

    try:
        socket = bob_socket(bob.port)
        socket.connect()
    except Exception as e:
        sys.exit(f"An error occurred creating the socket with TTP: {e}")

    """--STEP 2--"""
    print("Establishing a connection with TTP...")
    try:
        engineKAT = aes_functions.startAES_GCM(bob.KBT)

        print("Sending data to TTP...")
        message = [bob.name, bob.KBT.hex()]
        json_AT = json.dumps(message)

        print("Message B -> T (decryption): " + json_AT)

        # Encrypt data
        encrypted_message = rsa_functions.cipherRSA_OAEP(json_AT.encode("utf-8"), bob.KPT.public_key())
        encrypted_signature = rsa_functions.signatureRSA_PSS(bob.KBT.hex().encode("utf-8"), bob.PK_BOB)

        # Send encrypted data
        socket.send(encrypted_message)
        socket.send(encrypted_signature)
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 2: {e}")
    finally:
        print("END STEP 2")
        input("Press any key to continue")

    """--Step 5--"""
    try:
        socket = bob_socket(5555)
        socket.listen()
    except Exception as e:
        sys.exit(f"An error occurred creating the socket with Alice: {e}")

    try:
        print("Waiting for Alice...")
        msg = socket.receive()
        cipher_BT, mac_BT, iv_BT, cif_AB, mc_AB, iv_AB = json.loads(msg)

        decrypted_message = checkMessageGCM(bob.KBT, bytes.fromhex(iv_BT), bytes.fromhex(cipher_BT),
                                            bytes.fromhex(mac_BT))
        TS, KAB = json.loads(decrypted_message.decode('utf-8'))

        KAB = bytearray.fromhex(KAB)

        decrypted_message = checkMessageGCM(KAB, bytes.fromhex(iv_AB), bytes.fromhex(cif_AB),
                                            bytes.fromhex(mc_AB))
        sessionName, aux = json.loads(decrypted_message)

        if sessionName != 'Alice' and aux != TS:
            raise IncorrectData("Possible data modification  during communication")
        else:
            print("Reliable data, continued")
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 5: {e}")
    finally:
        print("END STEP 5")
        input("Press any key to continue")

    """--Step 6--"""
    try:
        resolution = float(TS) + 1

        engineKAB = aes_functions.startAES_GCM(KAB)
        cif, mac, iv = aes_functions.cipherAES_GCM(engineKAB, str(resolution).encode("utf-8"))
        sendAESMessage(socket, cif, mac, iv)
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 6: {e}")
    finally:
        print("END STEP 6")
        input("Press any key to continue")

    """--Step 7--"""
    try:
        print("Waiting for Alice")
        cif, mac, iv = receiveAESMessage(socket)
        textoClaro = checkMessageGCM(KAB, iv, cif, mac)
        msg = textoClaro.decode("utf-8")
        print("Message ->" + msg)
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 7: {e}")
    finally:
        print("END STEP 7")
        input("Press any key to continue")

    """--Step 8--"""
    try:
        msg = "Hello Word!"
        engineKAB = aes_functions.startAES_GCM(KAB)
        cif, mac, iv = aes_functions.cipherAES_GCM(engineKAB, msg.encode("utf-8"))
        sendAESMessage(socket, cif, mac, iv)
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 8: {e}")
    finally:
        print("END STEP 8")
