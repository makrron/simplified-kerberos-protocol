import json
import sys

import aes_functions
import rsa_functions
from exceptions.Exceptions import ChallengeFailed
from socket_class import SOCKET_SIMPLE_TCP


def checkMessageGCM(key, iv, cif, mac):
    res = aes_functions.decipherAES_GCM(key, iv, cif, mac)
    if res is not False:
        return res
    else:
        sys.exit("Corrupted Message")


def sendAESMessage(socket, encrypted_data, mac, nonce):
    socket.send(encrypted_data)
    socket.send(mac)
    socket.send(nonce)


def receiveAESMessage(s):
    return s.receive(), s.receive(), s.receive()


def alice_socket(port):
    return SOCKET_SIMPLE_TCP('127.0.0.1', port)


class Alice:
    def __init__(self):
        self.name = "Alice"
        self.port = 5551
        self.PK_ALICE = rsa_functions.create_RSAKey()
        self.KAT = aes_functions.create_AESKey()
        self.KPT = rsa_functions.load_RSAKey_Public("TTP.pub")

    def savePK(self):
        return rsa_functions.save_RSAKey_Public("Alice.pub", self.PK_ALICE)

    def getPK(self):
        return self.PK_ALICE


if __name__ == '__main__':
    """--STEP 0--"""
    alice = Alice()
    alice.savePK()
    print(alice.PK_ALICE.public_key().export_key())
    try:
        socket = alice_socket(alice.port)
        socket.connect()
    except Exception as e:
        sys.exit(f"An error occurred creating the socket with TTP: {e}")

    """--STEP 1"""
    print("Establishing a connection with TTP...")
    try:
        engineKAT = aes_functions.startAES_GCM(alice.KAT)

        print("Sending data to TTP...")
        message = [alice.name, alice.KAT.hex()]
        json_AT = json.dumps(message)

        print("Message A -> T (decryption): " + json_AT)

        # Encrypt data

        encrypted_message = rsa_functions.cipherRSA_OAEP(json_AT.encode("utf-8"), alice.KPT.public_key())
        encrypted_signature = rsa_functions.signatureRSA_PSS(alice.KAT.hex().encode("utf-8"), alice.PK_ALICE)

        # Send encrypted data
        socket.send(encrypted_message)
        socket.send(encrypted_signature)

    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 1: {e}")
    finally:
        print("END STEP 1")
        input("Press any key to continue")

    """--STEP 3--"""
    try:
        communication = ["Alice", "Bob"]
        communication_request = json.dumps(communication).encode("utf-8")
        socket.send(communication_request)
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 3: {e}")
    finally:
        print("END STEP 3")
        input("Press any key to continue")

    """--STEP 4--"""
    try:
        print("Waiting for TTP")
        cif = socket.receive()
        mac = socket.receive()
        iv = socket.receive()

        msg = aes_functions.decipherAES_GCM(alice.KAT, iv, cif, mac)
        Ts, KAB_str, cipher_BT, mac_BT, iv_BT = json.loads(msg.decode("utf-8"))

        KAB = bytearray.fromhex(KAB_str)

        msg_KAB_aux = ["Alice", Ts]
        msg_KAB = json.dumps(msg_KAB_aux)
        engineKAB = aes_functions.startAES_GCM(KAB)
        cif_AB, mc_AB, iv_AB = aes_functions.cipherAES_GCM(engineKAB, msg_KAB.encode("utf-8"))

        print("TS: " + Ts)
        print("KAB: " + KAB_str)
        print("Decrypted Message: " + msg_KAB)
    except Exception as e:
        sys.exit(f"An error occurred in step 4: {e}")
    finally:
        socket.close()
        print("END STEP 4")
        input("Press any key to continue")

    """--Step 5--"""  # EKBT(Ts, KAB)+EKAB(“Alice”, Ts)
    try:
        socket = alice_socket(5555)  # socket with Bob
        socket.connect()
    except Exception as e:
        sys.exit(f"An error occurred creating the socket with Bob: {e}")

    try:  # msg = json.dumps([cifM_S, macM_S, ivM_S, cifrado.hex(), mac.hex(), iv.hex()])
        #           cipher_BT, mac_BT, iv_BT              cif_AB, mc_AB, iv_AB
        print(cipher_BT, mac_BT, iv_BT, cif_AB.hex(), mc_AB.hex(), iv_AB.hex())
        pk = json.dumps([cipher_BT, mac_BT, iv_BT, cif_AB.hex(), mc_AB.hex(), iv_AB.hex()])
        socket.send(pk.encode("utf-8"))
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 5: {e}")
    finally:
        print("END STEP 5")
        input("Press any key to continue")

    """--Step 6--"""
    try:
        print("Waiting for Bob")
        cif, mac, iv = receiveAESMessage(socket)

        msg = aes_functions.decipherAES_GCM(KAB, iv, cif, mac)
        bob_TS = json.loads(msg.decode("utf-8"))
        bob_ts_aux = bob_TS

        alice_ts = float(Ts)
        alice_ts = alice_ts + 1
        alice_ts_aux = str(alice_ts)

        if str(bob_ts_aux) == alice_ts_aux:
            print("The message from step 6 has not been intercepted. Continuing...")
        else:
            raise ChallengeFailed("Challenge failed")
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 6: {e}")
    finally:
        print("END STEP 6")
        input("Press any key to continue")

    """--Step 7--"""
    try:
        msg = "HI!"
        engineKAB = aes_functions.startAES_GCM(KAB)
        cif, mac, iv = aes_functions.cipherAES_GCM(engineKAB, msg.encode("utf-8"))

        sendAESMessage(socket, cif, mac, iv)
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 7: {e}")
    finally:
        print("END STEP 7")
        input("Press any key to continue")

    """--Step 8--"""
    try:
        print("Waiting for Bob")
        c, m, i = receiveAESMessage(socket)
        msg = checkMessageGCM(KAB, i, c, m)
        msg = msg.decode("utf-8")
        print("Message ->" + msg)
    except Exception as e:
        socket.close()
        sys.exit(f"An error occurred in step 8: {e}")
    finally:
        print("END STEP 8")
