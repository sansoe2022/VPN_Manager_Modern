ARG DISTRO=ubuntu:22.04
FROM ${DISTRO}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::Retries=3 update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends python3 openssh-server openssh-client sshpass openssl ca-certificates iproute2 procps squid stunnel4 openvpn easy-rsa iptables systemd dropbear-bin sslh && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN python3 -m unittest discover -s tests -v
CMD ["python3", "tests/distro_smoke.py"]
