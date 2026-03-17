FROM ubuntu:22.04

# Set working directory
WORKDIR /challenge/

# Install dependecies
RUN apt-get update && \
    apt-get install -y socat gcc python3 qemu-user

# Cleanup
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* \
        /tmp/* \
        /var/tmp/* \
        /var/cache/apt/archives/* \
        /usr/share/man/* \
        /usr/share/doc/* \
        /usr/share/locale/*

# Create User
RUN adduser --disabled-password --gecos "" user && \
    echo 'user:password' | chpasswd

# Setup user
RUN groupadd ctf && \
    useradd -G ctf --home=/challenge player

# Copy ressources
COPY ./ynetd .
COPY ./challenge/jail.py /challenge/
COPY ./challenge/entrypoint.sh /challenge/

# Write flag
COPY ./challenge/flag.txt /flag.txt
RUN chmod 755 /flag.txt
RUN mv /flag.txt /flag-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1).txt

# Set permissions
RUN chmod 755 /challenge/jail.py /challenge/entrypoint.sh

# Expose port
EXPOSE 50001
CMD ["/challenge/entrypoint.sh"]