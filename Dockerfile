FROM debian:12

SHELL ["/bin/bash", "-l", "-c"]

# Update and install necessary packages
RUN sed -i 's/main/main contrib non-free/g' /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y && apt-get autoremove -y
RUN apt-get install -y xfce4 xfce4-goodies
RUN apt-get install -y software-properties-common qemu-system 
RUN apt-get install -y build-essential gdb cmake automake autoconf nodejs npm yarnpkg neovim zip unzip p7zip-full tar gzip git
RUN apt-get install -y w3m links2 lynx chromium nginx openssh-server uvicorn wget curl traceroute tcpdump wireshark nmap dnsutils inetutils-ping inetutils-telnet netcat-openbsd dnsenum dnsmap fail2ban forensics-extra gwhois whois irssi irssi-scripts prips urlextractor strace socat ufw
RUN apt-get install -y sudo apt-transport-https ca-certificates gnupg lsb-release apt-utils tmux fortune cowsay lolcat caca-utils libcaca-dev ffmpeg ffmpeg-doc libavcodec-dev libavcodec-extra libavdevice-dev libavfilter-dev libavfilter-extra libavformat-dev libavformat-extra-dev libavutil-dev mpv vlc
RUN apt-get install -y python3-full libpython3-dev python3-pip pipx python3-venv python3-fastapi python3-requests python3-starlette python3-whois python3-dotenv python3-uvicorn
RUN apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y && apt-get autoremove -y

RUN ufw default allow outgoing && ufw default deny incoming && ufw allow 22/tcp && ufw allow 2222/tcp && ufw allow 80/tcp && ufw allow 8080/tcp && ufw allow 8000/tcp && ufw allow 8888/tcp && ufw allow 443/tcp && ufw allow 5002/tcp && ufw allow 9903/tcp # && yes | ufw enable

# Allow sudo without a password for the container's user
RUN groupadd -g 1001 tuesday && useradd -m -u 1001 -g 1001 -G users,sudo,tty,video,mail -s /bin/bash tuesday && mkdir /app && \
    echo "tuesday ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN curl -fsSL https://get.docker.com | sh; \
    gpasswd -a tuesday docker; \
    apt-get install -y uidmap

USER tuesday

ENV HOME=/home/tuesday

RUN mkdir -p "$HOME/Downloads" && cd "$HOME/Downloads"; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup-init && chmod 755 rustup-init && ./rustup-init -y --default-host x86_64-unknown-linux-gnu --default-toolchain nightly --profile complete; cd "$HOME"; . "$HOME/.cargo/env" && which rustc && which cargo && rustc -V && cargo -V

RUN cd "$HOME" && mkdir -p ~/.venvs && python3 -m venv ~/.venvs/tuesday || true && if [ $(grep -v -e ".venvs/tuesday/bin" ~/.profile >/dev/null; echo $?) -eq 0 ]; then echo 'PATH="$HOME/.venvs/tuesday/bin:$PATH"' >> ~/.profile && echo 'export VIRTUAL_ENV="$HOME/.venvs/tuesday"' >> ~/.profile; fi || true && source ~/.profile && which python3 && which pip && pip install wheel

RUN source ~/.profile && pip install gptme
RUN source ~/.profile && pip install llm-workflow-engine
RUN source ~/.profile && pip install llm
RUN source ~/.profile && pip install -U g4f[all]

RUN sudo install -d -m 0755 /etc/apt/keyrings && wget -q https://packages.mozilla.org/apt/repo-signing-key.gpg -O- | sudo tee /etc/apt/keyrings/packages.mozilla.org.asc > /dev/null && gpg -n -q --import --import-options import-show /etc/apt/keyrings/packages.mozilla.org.asc | awk '/pub/{getline; gsub(/^ +| +$/,""); if($0 == "35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3") print "\nThe key fingerprint matches ("$0").\n"; else print "\nVerification failed: the fingerprint ("$0") does not match the expected one.\n"}' && echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" | sudo tee -a /etc/apt/sources.list.d/mozilla.list > /dev/null && echo '\
Package: *\
Pin: origin packages.mozilla.org\
Pin-Priority: 1000\
' | sudo tee /etc/apt/preferences.d/mozilla && sudo apt-get update && sudo apt-get install firefox

RUN cd "$HOME" && wget https://github.com/browsh-org/browsh/releases/download/v1.8.0/browsh_1.8.0_linux_amd64.deb && sudo apt install -y ./browsh_1.8.0_linux_amd64.deb && rm ./browsh_1.8.0_linux_amd64.deb

WORKDIR /app

COPY . /app

ENTRYPOINT ["uvicorn", "--host", "0.0.0.0", "--port", "5002", "main:app"]
#ENTRYPOINT ["uvicorn", "--reload", "--host", "0.0.0.0", "--port", "5002", "main:app"]

