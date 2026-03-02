FROM ubuntu:24.04

EXPOSE 1337

RUN apt update && apt install socat -y

COPY matrices-inestables flag.txt /

CMD [ "socat", "tcp-listen:1337,fork,reuseaddr", "EXEC:/matrices-inestables" ]
