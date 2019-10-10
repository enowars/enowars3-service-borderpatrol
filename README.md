# Border Patrol Writeup

## Intro
Borderpatrol implements a simple TCP server communicating via a custom layer 4 protocol.
Primarily, the service exposes means to read/write logs and memory dumps after authenticating successfully. The flags are stored as log messages.
Packets are encrypted (i.e. xored) with a key before being sent, which is mainly done to make 
traffic analysis/ replayability a little harder. It is still trivial to circumvent as the first exchanged packet
of a new connection will contain the key.

## The Zero Knowledge Proof Protocol
For authentication, a Zero Knowledge Proof based on the Discrete Logarithm Problem is used (cf. [Wikipedia](https://en.wikipedia.org/wiki/Zero-knowledge_proof#Discrete_log_of_a_given_value)). 
The following points are important to know:
- the protocol enables a prover to prove knowledge of a certain (secret) value _x_ to a verifier, while the verifier is not able to learn anything about the secret
- the protocol involves the mathimatical commitment of the prover to a certain value, the verifier randomly asking for one of two values and the prover finally transmitting the requested value
- the prover knows the answer to both possible questions if and only if she knows the secret. The prover can always know the answer to one of the questions, thus cheating the protocol with probability 0.5. Hence, the protocol  needs to be repeated mutliple times (32 in this case).

A flaw in the protocol state tracker of the connection handler enables an attacker to skip the first 31 rounds of authentication by sending multiple ACC packets with a sequence number of 1 or 2, as the user submitted sequence number is not checked against the server sided value:
```golang
if currSession.protocolState.protocol == "ZKP" {
    if tp := currSession.inPackets[len(currSession.inPackets)-1]; string(tp.operation) == "ACC" {
        if binary.BigEndian.Uint16(tp.payload[:2]) == 1 {
            currSession.protocolState.sequenceNumber++
            prepareAWS(&currSession, 256)
            currSession.inWindowSize = 256
        } else if binary.BigEndian.Uint16(tp.payload[:2]) == 2 {
            currSession.protocolState.sequenceNumber++
            prepareACC(&currSession)
        }
    }
}
```
This leaves her at a 0.5 probability of successfully authenticating without knowing the secret.

## Central 'Certificate Authority'
The server also gives players a hint about another endpoint existing in the game network: _borderpatrol.enowars.com:8888_

Sending the server a correctly formatted GET packet with payload 'dbg=1' gives us the following message:
```
=========================================================================
    MAGIC DRAGON MASTER AUTHORITY

    Cert Level 1: Strong Prime Number for Certificate self-signing
                  Authentication: None

    Cert Level 2: Privileged Certificate for Border Authorities
                  Authentication: Challenge Response Protocol
                  System Details: 64 Round 48-Bit 4-XOR Arbiter PUF
=========================================================================
```
While a random, strong prime number doesn't sound too interesting, 'privileged certificate' does.
The centrally hosted server implements a simulated [PUF](https://en.wikipedia.org/wiki/Physical_unclonable_function). Upon requesting a 'cert_level=2', the server answers with 64 challenges, each consisting of 48 bits. Accordingly, it expects 64 bits as a response. Giving an invalid answer of length 64, the server presents us with the expected bit sequence. This behaviour enables an attacker to exploit the inherently linear dependencies of a PUF and she can learn to predict the correct answer. Training a linear regression model with about 16000 Challenge-Response-Pairs (i.e. ~250 requests), leaves an attacker at about 0.99 accuracy which allows her to predict the full 64 rounds with a probability of about 0.5. Upon successful authentication with the server, it will greet us with a 512 bit integer, the hardcoded secret value _x_ of the Zero Knowledge Proof Protocol. It is now possible to authenticate with each team's service to extract logs and flags, this is intentionally unpatchable.