from pwn import *
import numpy as np

import argparse
from pypuf import tools
from pypuf.learner.regression.logistic_regression import LogisticRegression
from pypuf.simulation.arbiter_based.ltfarray import LTFArray

def CRT():
    n = 256
    challenges = np.zeros([n*64, 48], dtype=np.int8)
    responses = np.zeros([n*64], dtype=np.int8)
    for i in range(0, n):
        c = remote("localhost", 8888)
        resp = c.recv().split(b'\n')
        challs = np.zeros([64, 48], dtype=np.int8)
        for x in range(0, 64):
            for b in range(0, 48):
                challs[x, b] = np.int8(chr(resp[x][b]))
            challenges[i*64 + x] = np.copy(challs[x])
        # print(challs)
        c.send(b'A'*64)
        r = c.recv()
        for p in range(len(r)):
            responses[i*64 + p] = np.int8(chr(r[p]))
        
        c.close()

    challenges[challenges == 1] = -1
    challenges[challenges == 0] = 1
    responses[responses == 1] = -1
    responses[responses == 0] = 1

    model = train(challenges, responses, n*64)
    model.eval()

def uint(val):
    """
    Assures that the passed integer is positive.
    """
    ival = int(val)
    if ival <= 0:
        raise argparse.ArgumentTypeError('{} is not a positive integer'.format(val))
    return ival


def train(challenges, responses, t_pairs):
    try:
        with open('weights.txt', 'rb') as f:
            weights = np.load(f)
    except:
        print("[*] ENOWEIGHTS")

    # create instance frome same weights for accuracy calculation
    instance = LTFArray(
        weight_array=weights,
        transform=LTFArray.transform_atf,
        combiner=LTFArray.combiner_xor,
    )

    # train model from obtained CRPs
    training_set = tools.ChallengeResponseSet(challenges, responses)
    lr_learner = LogisticRegression(
        t_set=training_set,
        n=48,
        k=4,
        transformation=LTFArray.transform_atf,
        combiner=LTFArray.combiner_xor,
    )

    # learn and test the model
    model = lr_learner.learn()
    accuracy = 1 - tools.approx_dist(instance, model, 10000)

    print('Learned a 48-bit 4-xor XOR Arbiter PUF from {} CRPs with accuracy {}'.format(t_pairs, accuracy))
    
    return model


if __name__=='__main__':
    CRT()