FROM kalilinux/kali-rolling

ARG USERNAME=sentinel
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        aircrack-ng \
        ca-certificates \
        curl \
        dnsutils \
        git \
        golang-go \
        hashcat \
        hping3 \
        libcap2-bin \
        make \
        metasploit-framework \
        nmap \
        set \
        skipfish \
        sqlmap \
        sudo \
        tshark \
        whatweb \
        wireshark-common \
    && groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USERNAME}" \
    && usermod --append --groups wireshark "${USERNAME}" \
    && echo "${USERNAME} ALL=(root) NOPASSWD:ALL" > "/etc/sudoers.d/${USERNAME}" \
    && chmod 0440 "/etc/sudoers.d/${USERNAME}" \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap \
    && if [ -x /usr/sbin/hping3 ]; then setcap cap_net_raw+eip /usr/sbin/hping3; fi \
    && if [ -x /usr/bin/hping3 ]; then setcap cap_net_raw+eip /usr/bin/hping3; fi \
    && if [ -x /usr/sbin/airodump-ng ]; then setcap cap_net_raw,cap_net_admin+eip /usr/sbin/airodump-ng; fi \
    && if [ -x /usr/sbin/aireplay-ng ]; then setcap cap_net_raw,cap_net_admin+eip /usr/sbin/aireplay-ng; fi \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/home/${USERNAME}/go/bin:${PATH}"

USER ${USERNAME}
