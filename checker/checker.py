import time
import asyncio
import logging
import sys
import numpy as np
import struct
import construct
import lzma
import socket
from Crypto.Random import random

from enochecker import BaseChecker, BrokenServiceException, create_app, OfflineException, ELKFormatter, CheckerTask
from logging import LoggerAdapter


class BorderPatrolAsyncChecker(BaseChecker):
    PAYLOAD_OFFSET = 11
    ip = "fd00:1337:0:cecc::1"
    port = 41314

    def __init__(self):
        super(BorderPatrolAsyncChecker, self).__init__("BorderPatrol")


    def xor(self, _input):
        output = b""
        for i in range(len(_input)):
            output += bytes([_input[i]^self.key[i%len(self.key)]])

        print(output)
        return output


    async def putflag(self, logger: LoggerAdapter, task: CheckerTask) -> None:
        logger.debug("Putting Flag...")
        reader, writer = await asyncio.open_connection(socket.getaddrinfo(task.address, None, socket.AF_INET6)[0][4][0], self.port)
        writer.write(b'\n')
        self.key = await reader.read(32)

        await self.authenticate(reader, writer, size=16)
        p_log = b"ENO/LOG/\x01\x00/" + task.flag.encode() + b'\x00'*(257-len(task.flag.encode()))
        writer.write(self.xor(p_log))

        if random.choice([0, 1, 2]) == 0:
            p_cls = b"ENO/CLS/\x01\x00/" + b'\x00'*257
            writer.write(self.xor(p_cls))
        writer.close()
        await writer.wait_closed()


    async def getflag(self, logger: LoggerAdapter, task: CheckerTask) -> None:
        reader, writer = await asyncio.open_connection(socket.getaddrinfo(task.address, None, socket.AF_INET6)[0][4][0], self.port)
        writer.write(b'\n')
        self.key = await reader.read(32)
        
        await self.authenticate(reader, writer)

        found = -1
        i = 1
        while found == -1 and i <= 3:
            req = b"type=file&name=log.00" + str(i).encode()
            p_get = b"ENO/GET/\x01\x00/" + req + b'\x00'*(257-len(req))
            writer.write(self.xor(p_get))
            r = self.xor(await reader.read(268))
            if b"EXP" not in r:
                raise BrokenServiceException("GET was unsuccessful")

            file_size = struct.unpack(">I", r[self.PAYLOAD_OFFSET:self.PAYLOAD_OFFSET+4])[0]
            r = await reader.readexactly(file_size)

            if len(r) != file_size:
                logger.debug("ERROR IN SIZE")

            decompressed = lzma.decompress(r)
            found = decompressed.find((task.flag).encode())
            i += 1         
        
        if found == -1:
            raise BrokenServiceException("Flag could not be found")
        else:
            logger.debug("Flag successfully retrieved")
        
        writer.close()
        await writer.wait_closed()


    async def putnoise(self, logger: LoggerAdapter, task: CheckerTask) -> None:
        reader, writer = await asyncio.open_connection(socket.getaddrinfo(task.address, None, socket.AF_INET6)[0][4][0], self.port)
        writer.write(b'\n')
        self.key = await reader.read(32)

        choice = random.choice([0,1,2])
        if choice == 0:
            p_aws = b"ENO/AWS/\x00\x10/" + b'\x00\x20' + 15*b'\x00'
            writer.write(self.xor(p_aws))
            r = self.xor(await reader.read(512))
            if b"ACC" not in r:
                raise BrokenServiceException("AWS got not accepted")
            
            if random.choice([0,1]) == 0:
                p_acc = b"ENO/ACC/\x00\x20/" + 33*b'\x00'
            else:
                random_payload = struct.pack(">I", random.randint(65536, 4294967295))
                p_acc = b"ENO/ACC/\x00\x20/" + random_payload + b'\x00'*(33-len(random_payload))
            writer.write(self.xor(p_acc))
            r = self.xor(await reader.read(512))
            if b"ACC" not in r:
                raise BrokenServiceException("Valid packet got rejected")

            if random.choice([0, 1]) == 0:
                p_cls = b"ENO/CLS/\x00\x20/" + b'\x00'*33
                writer.write(self.xor(p_cls))
        elif choice == 1:
            p_aws = b"ENO/AWS/\x00\x10/" + b'\x00\x08' + b'\x00'*15
            writer.write(self.xor(p_aws))
            r = self.xor(await reader.read(512))
            if b"ACC" not in r:
                raise BrokenServiceException("AWS got not accepted")

            if random.choice([0,1]) == 0:
                p_acc = b"ENO/ACC/\x00\x08/" + b'\x00'*9
                writer.write(self.xor(p_acc))
                r = self.xor(await reader.read(512)) # should be ACC
                if b"ACC" not in r:
                    raise BrokenServiceException("Valid packet got rejected")
            else:
                p_acc = b"ENO/ACC/\x00\x20/" + b'\x00'*33
                writer.write(self.xor(p_acc))
                r = self.xor(await reader.read(256)) # should be DNY (Invalid Package)
                if b"DNY" not in r:
                    raise BrokenServiceException("Packet of invalid size got not denied")
            
            if random.choice([0, 1]) == 0:
                p_cls = b"ENO/CLS/\x00\x08/" + b'\x00'*9
                writer.write(self.xor(p_cls))
        elif choice == 2:
            pass
        elif choice == 3:
            await self.authenticate(reader, writer)
            p_aws = b"ENO/GET/\x01\x00/" + b'type=cert' + b'\x00'*248
            writer.write(self.xor(p_aws))
            r = self.xor(await reader.read(512))
            if not b'EXP' in r:
                raise BrokenServiceException("GET cert was unsuccessful")
            if random.choice([0, 1]) == 0:
                p_cls = b"ENO/CLS/\x01\x00/" + b'\x00'*257
                writer.write(self.xor(p_cls))

        if random.choice([0, 1, 2]) != 0:
            writer.close()
            await writer.wait_closed()


    async def getnoise(self, logger: LoggerAdapter, task: CheckerTask) -> None:
        pass


    async def havoc(self, logger: LoggerAdapter, task: CheckerTask) -> None:
        pass


    async def exploit(self, logger: LoggerAdapter, task: CheckerTask) -> None:
        pass


    async def authenticate(self, reader, writer, size=16):
        g = 2
        x = 12074235067132104677358030448740169086211171545373284647579234906840326968311237601092259613113724502049948022317426840853777753513486274652991559584610574
        prime = 7211120725388770757449064920117053258626350409292518732487977076334774457178724668781927073094705280276788047107026280406597259439312993043207548964593709
        y = 3791681507150338158995503145950387058281565872405011862192137930605710794447294645064985636919183844757477896341909957083567025441343602771513168204170391 # g**x % prime

        size_packed = struct.pack(">H", size)
        p = b"ENO/ZKP/" + size_packed + b"/" + b'\x00'*(size+1)
        writer.write(self.xor(p))
        r = self.xor(await reader.read(512))

        if r[4:7] != b"ESQ":
            logger.debug("error1")
            raise BrokenServiceException("Wrong Packet")
        p = b"ENO/ACC/" + size_packed + b"/" + b"\x00\x01" + b'\x00'*(size+1)
        writer.write(self.xor(p))
        r = self.xor(await reader.read(512))
        if r[4:7] != b"AWS":
            logger.debug("error2")
            raise BrokenServiceException("Wrong Packet")
        p = b"ENO/ACC/\x01\x00/" + b"\x00\x02" + b'\x00'*255
        writer.write(self.xor(p))
        r = self.xor(await reader.read(512))
        if r[4:7] != b"ACC":
            logger.debug("error3")
            raise BrokenServiceException("Wrong Packet")

        for i in range(0, 64):
            # send random r
            r = random.randint(0, prime - 1)
            c = pow(g, r, prime)
            c = construct.BytesInteger(64).build(c)
            p = b"ENO/ZKP/\x01\x00/" + b"\x00\x02" + c + b'\x00'*(255-len(c))
            writer.write(self.xor(p))
            re = self.xor(await reader.read(512))
            opt = re[self.PAYLOAD_OFFSET + 16:self.PAYLOAD_OFFSET + 17]
            
            # disclose info
            if opt == b"0":
                r = construct.BytesInteger(64).build(r)
                p = b"ENO/ZKP/\x01\x00/" + b"\x00\x02" + r + b'\x00'*(255-len(r))
            else:
                v = (x + r) % (prime - 1)
                v = construct.BytesInteger(64).build(v)
                p = b"ENO/ZKP/\x01\x00/" + b"\x00\x02" + v + b'\x00'*(255-len(v))
            writer.write(self.xor(p))
            re = self.xor(await reader.read(512))
            if re[4:7] == b"DNY":
                raise BrokenServiceException("Unable to authenticate with hardcoded secret")
                break
            elif re[4:7] == b"ZKP" and b"SUCCESS" in re:
                logger.debug("Authenticated successfully")
                break


logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
#handler.setFormatter(ELKFormatter("%(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

app = create_app(BorderPatrolAsyncChecker())