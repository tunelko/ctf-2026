FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    autoconf bison flex gcc g++ git libprotobuf-dev \
    libnl-route-3-dev make pkg-config protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/google/nsjail.git /nsjail_src && \
    cd /nsjail_src && make && mv /nsjail_src/nsjail /usr/bin/nsjail && \
    rm -rf /nsjail_src

RUN mkdir /challenge
COPY jail.sh /challenge/jail.sh
COPY nsjail.cfg /challenge/nsjail.cfg
RUN chmod +x /challenge/jail.sh

RUN echo "HackOn{Fake_Fl4g}" > /flag.txt

RUN useradd -m ctfuser

EXPOSE 1337

RUN apt-get update && apt-get install -y socat
RUN sed -i 's/\r//g' /challenge/nsjail.cfg
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"nsjail --config /challenge/nsjail.cfg -- /challenge/jail.sh",pty,stderr
