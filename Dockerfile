# CTF-Agent Standalone Toolchain Container (v2.0)
# Multi-Platform Linux Security Workstation containing all 15 category profiles

FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH="/root/.foundry/bin:/root/.ctf-tools/venv/bin:$PATH"

# 1. System packages & security utilities across all Tier 1 & Tier 2 profiles
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core & Build Essentials
    build-essential \
    cmake \
    g++ \
    gcc \
    make \
    git \
    curl \
    wget \
    jq \
    ripgrep \
    tmux \
    file \
    xxd \
    bsdmainutils \
    netcat-traditional \
    socat \
    # Python Environment
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Libraries
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libssl-dev \
    libffi-dev \
    # Compilers & Runtimes
    ruby \
    ruby-dev \
    golang \
    # Binary Analysis & Pwn
    gdb \
    radare2 \
    binutils \
    strace \
    ltrace \
    qemu-user \
    qemu-system-x86 \
    patchelf \
    checksec \
    elfutils \
    ropper \
    python3-filebytes \
    python3-pwntools \
    # Reverse Engineering & WASM
    upx-ucl \
    wabt \
    # Forensics & Steganography
    binwalk \
    foremost \
    libimage-exiftool-perl \
    sleuthkit \
    ffmpeg \
    steghide \
    pngcheck \
    qpdf \
    testdisk \
    pcapfix \
    tshark \
    imagemagick \
    yara \
    bulk-extractor \
    # Cryptography
    pari-gp \
    hashcat \
    john \
    qrencode \
    python3-fpylll \
    # Web Exploitation
    sqlmap \
    nikto \
    # Mobile
    adb \
    apktool \
    # Cloud & Container
    docker.io \
    skopeo \
    # Active Directory & Windows
    smbclient \
    ldap-utils \
    # Kernel & Tracing
    pahole \
    # Hardware & IoT
    openocd \
    minicom \
    flashrom \
    u-boot-tools \
    gdb-multiarch \
    # Networking Recon
    nmap \
    whois \
    bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*

# 2. Ruby Gems (Pwn & Stego)
RUN gem install one_gadget seccomp-tools zsteg --no-document

# 3. Go Tools (Reproducible versions)
RUN go install github.com/ffuf/ffuf/v2@v2.1.0 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.8 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.1.2 && \
    cp /root/go/bin/* /usr/local/bin/

# 4. Web3 Tools (Foundry: cast, forge, anvil)
RUN curl -sSfL https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup || true

# 5. Dedicated Python Virtualenv with CTF packages (Matching ctf-tools.lock)
RUN python3 -m venv --system-site-packages /root/.ctf-tools/venv && \
    /root/.ctf-tools/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /root/.ctf-tools/venv/bin/pip install --no-cache-dir \
    # Core & Networking
    requests==2.32.5 \
    shodan==1.31.0 \
    scapy==2.7.0 \
    dnspython==2.8.0 \
    dnslib==0.9.26 \
    # Pwn & Binary
    ROPgadget==7.7 \
    capstone==5.0.9 \
    unicorn==2.1.2 \
    qiling==1.4.6 \
    # Reverse Engineering
    angr==9.3.4 \
    lief==0.17.6 \
    frida-tools==14.10.4 \
    # Cryptography
    pycryptodome==3.23.0 \
    z3-solver==4.13.0.0 \
    sympy==1.14.0 \
    gmpy2==2.3.0 \
    py_ecc==8.0.0 \
    hashpumpy==1.2 \
    # Forensics
    volatility3==2.27.0 \
    pefile==2024.8.26 \
    oletools==0.60.2 \
    Pillow==11.3.0 \
    dissect.cobaltstrike==1.2.1 \
    # Modern Web
    pyjwt==2.10.1 \
    flask-unsign==1.2.1 \
    httpx==0.28.1 \
    mitmproxy==11.1.3 \
    playwright==1.50.0 \
    # Mobile
    objection==1.11.0 \
    # Active Directory & Windows
    impacket==0.12.0 \
    certipy-ad==4.8.2 \
    bloodhound==1.7.2 \
    # Hardware
    esptool==4.8.1 \
    # Web3
    slither-analyzer==0.10.4 \
    solc-select==1.2.0 \
    # AI & ML Security
    safetensors==0.5.3 \
    numpy==2.2.6 \
    matplotlib==3.10.8 && \
    /root/.ctf-tools/venv/bin/pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.6.0 && \
    /root/.ctf-tools/venv/bin/pip install --no-cache-dir transformers==4.49.0

WORKDIR /workspace
COPY . /workspace/
RUN /root/.ctf-tools/venv/bin/pip install -e /workspace

CMD ["/bin/bash"]
