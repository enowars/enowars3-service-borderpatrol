from pypuf import tools
from pypuf.learner.regression.logistic_regression import LogisticRegression
from pypuf.simulation.arbiter_based.ltfarray import LTFArray
import numpy as np
from Crypto.Random import random
from Crypto.Util import number
import socket
import struct
import threading
import construct

HOST = "::"
PORT = 8888

class ConnectionThread(threading.Thread):
    def __init__(self, address, socket):
        threading.Thread.__init__(self)
        self.address = address
        self.socket = socket
        print("[+] New Connection {}".format(address))

    def run(self):
        r = self.socket.recv(64)
        if r[0:8] != b"ENO/GET/":
            print("[*] Invalid Packet")
            p_dny = b"ENO/DNY/\x00\x10/" + b'\x00'*32 + b'/' + b'\x00'*17
            self.socket.send(p_dny)
            return

        if b"dbg=1" in r:
            info = b"""
=========================================================================
    MAGIC DRAGON MASTER AUTHORITY

    Cert Level 1: Strong Prime Number for Certificate self-signing
                  Authentication: None

    Cert Level 2: Privileged Certificate for Border Authorities
                  Authentication: Challenge Response Protocol
                  System Details: 64 Round 48-Bit 4-XOR Arbiter PUF
=========================================================================
"""
            self.socket.send(info)

        elif b"cert_level=1" in r:
            p = number.getPrime(64)
            print(p)
            self.socket.send(struct.pack(">Q", p))
            print("[*] CERT LVL 1 OK")
        elif b"cert_level=2" in r:
            try:
                with open('weights.txt', 'rb') as f:
                    weights = np.load(f)
            except:
                weights = LTFArray.normal_weights(n=48, k=4)
                with open('weights.txt', 'wb') as f:
                    np.save(f, weights, allow_pickle=False)
            # print(weights)

            instance = LTFArray(
                weight_array=weights,
                transform=LTFArray.transform_atf,
                combiner=LTFArray.combiner_xor,
            )

            challenges = []
            c_string = b""
            for n in range(0, 64):
                c = np.zeros(48, dtype=np.int8)
                for i in range(0, 48):
                    c[i] = random.choice([-1, 1])
                challenges.append(c)
                
                # prepare message 
                c = np.copy(c)
                c[c == 1] = 0
                c[c == -1] = 1
                
                cm = b""
                for b in c:
                    cm += str(b).encode()
                c_string += cm + b'\n'
            
            print("[*] Challenges prepared")
            challenges = np.array(challenges)
            correct_response = instance.eval(challenges)

            self.socket.send(c_string)
            print("[*] Expect Response")
            r = self.socket.recv(64)
            if len(r) != 64:
                print("[*] Invalid Response")
            else:  
                given_response = np.zeros(64, dtype=np.int8)
                for i in range(0, 64):
                    given_response[i] = np.int8(r[i])
                correct_response[correct_response == 1] = 0
                correct_response[correct_response == -1] = 1
                print(correct_response)

                if (given_response==correct_response).all():
                    print("[*] ACCEPT")
                    x = 12074235067132104677358030448740169086211171545373284647579234906840326968311237601092259613113724502049948022317426840853777753513486274652991559584610574
                    self.socket.send(construct.BytesInteger(64).build(x))
                else:
                    print("[*] REJECT")
                    cm = b""
                    for b in correct_response:
                        cm += str(b).encode()
                    self.socket.send(cm)
        self.socket.close()


def main():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        s.close()
        print("[*] ERROR")
        return

    print("[*] MDMA started successfully")
    while True:
        s.listen(5)
        (client_sock, address) = s.accept()
        newthread = ConnectionThread(address, client_sock)
        newthread.start()
    
    s.close()


def train():
    instance = LTFArray(
        weight_array=LTFArray.normal_weights(n=48, k=4),
        transform=LTFArray.transform_atf,
        combiner=LTFArray.combiner_xor,
    )

    N = 18000

    # learn and test the model
    lr_learner = LogisticRegression(
        t_set=tools.TrainingSet(instance=instance, N=N),
        n=48,
        k=4,
        transformation=LTFArray.transform_atf,
        combiner=LTFArray.combiner_xor,
    )
    
    model = lr_learner.learn()
    accuracy = 1 - tools.approx_dist(instance, model, 10000)

    print('Learned a 48bit 4-xor XOR Arbiter PUF from %d CRPs with accuracy %f' % (N, accuracy))


if __name__=="__main__":
    main()
    # train()