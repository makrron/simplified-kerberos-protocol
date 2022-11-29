import json
import sys
from datetime import datetime

import aes_functions
import rsa_functions
from exceptions.Exceptions import InvalidSignature, OperationDenied
from socket_class import SOCKET_SIMPLE_TCP


class TTP:

    def __init__(self):
        self.PK_TTP = rsa_functions.create_RSAKey()

    def savePK(self):
        rsa_functions.save_RSAKey_Public("TTP.pub", self.PK_TTP)

    def getSessionKey(self, encrypted_message, encrypted_signature):
        print("Encrypted message received: " + encrypted_message.hex())
        print("Signature received: " + encrypted_signature.hex())
        decrypted_message = rsa_functions.decipherRSA_OAEP_BIN(encrypted_message, self.PK_TTP)

        _, sessionKey = json.loads(rsa_functions.decipherRSA_OAEP_BIN(encrypted_message, self.PK_TTP))
        print("Decrypted message: " + decrypted_message.decode("utf-8"))

        return bytes.fromhex(sessionKey)


if __name__ == '__main__':
    """--STEP 0--"""
    t_p = TTP()  # Create TTP
    t_p.savePK()  # Save the PK of TTP

    """--STEP 1--"""
    print("Waiting for Alice...")
    try:
        alice_socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
        alice_socket.listen()

        alicePK = rsa_functions.load_RSAKey_Public('Alice.pub')
        encrypted_message_Alice = alice_socket.receive()
        encrypted_signature_Alice = alice_socket.receive()

        KAT = t_p.getSessionKey(encrypted_message_Alice, encrypted_signature_Alice)
        if not rsa_functions.checkRSA_PSS(KAT.hex().encode('utf-8'), encrypted_signature_Alice, alicePK):
            raise InvalidSignature("Invalid Signature Exception")
    except Exception as e:
        sys.exit(f"An error occurred in step 1: {e}")
    finally:
        print("END STEP 1")

    """--Step 2--"""
    try:
        print("Waiting for Bob...")
        bob_socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
        bob_socket.listen()

        bobPK = rsa_functions.load_RSAKey_Public('Bob.pub')
        encrypted_message_Bob = bob_socket.receive()
        encrypted_signature_Bob = bob_socket.receive()

        KBT = t_p.getSessionKey(encrypted_message_Bob, encrypted_signature_Bob)
        if not rsa_functions.checkRSA_PSS(KBT.hex().encode('utf-8'), encrypted_signature_Bob, bobPK):
            raise InvalidSignature("Invalid Signature Exception")
    except Exception as e:
        sys.exit(f"An error occurred in step 2: {e}")
    finally:
        print("END STEP 2")

    """--Step 4--"""  # Enviar KAB como: KXT->[Ts, KAB, KYT->[TS, KAB] == M]
    try:
        print("Waiting for Alice...")
        msg = alice_socket.receive()
        origen, destino = json.loads(msg.decode('utf-8'))
        if origen != "Alice" and destino != "Bob":
            print("Operation Denied")
            raise OperationDenied()
        else:
            TS = datetime.timestamp(datetime.now())

            KAB = aes_functions.create_AESKey()
            engineKAB = aes_functions.startAES_GCM(KAB)

            msg = [str(TS), KAB.hex()]
            msg_KBT = json.dumps(msg)

            engineKBT = aes_functions.startAES_GCM(KBT)

            cipher, mac, ts2 = aes_functions.cipherAES_GCM(engineKBT, msg_KBT.encode("utf-8"))
            msg = json.dumps([str(TS), KAB.hex(), cipher.hex(), mac.hex(), ts2.hex()])

            engineKAT = aes_functions.startAES_GCM(KAT)
            cif, mc, ts3 = aes_functions.cipherAES_GCM(engineKAT, msg.encode("utf-8"))

            alice_socket.send(cif)
            alice_socket.send(mc)
            alice_socket.send(ts3)
            print("TTP function completed")
            exit()
    except Exception as e:
        sys.exit(f"An error occurred in step 4: {e}")
    finally:
        alice_socket.close()
        print("END STEP 4")
