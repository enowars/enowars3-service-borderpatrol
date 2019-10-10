FROM ubuntu:18.04

RUN apt-get update -y && apt-get install -y curl iproute2 python3.7 git tar xz-utils python3-pip

RUN mkdir /magic_dragon
WORKDIR /magic_dragon

RUN git clone https://github.com/nils-wisiol/pypuf.git
WORKDIR /magic_dragon/pypuf
RUN pip3 install -r requirements.txt
RUN pip3 install construct

COPY ./magic_dragon.py /magic_dragon/pypuf/
COPY ./weights.txt /magic_dragon/pypuf/

RUN groupadd -g 1001 bp
RUN useradd -ms /bin/bash -g 1001 -u 1001 bp
USER bp
CMD ["bash", "-c", "python3 ./magic_dragon.py"]
