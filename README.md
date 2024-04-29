# 6point6 Modified DRAKVUF&copy;

[Original README](ORIGINAL_README.md)

## Installation

### Required Dependencies
```bash
sudo apt install -y \
    libcurl4-openssl-dev \
    autoconf-archive \
    libvncserver-dev \
    build-essential \
    libncurses5-dev \
    libpixman-1-dev \
    libsystemd-dev \
    linux-libc-dev \
    libglib2.0-dev \
    libjson-c-dev \
    ocaml-findlib \
    bridge-utils \
    redis-server \
    e2fslibs-dev \
    libyajl-dev \
    libfuse-dev \
    liblzma-dev \
    python3-dev \
    python3-pip \
    ninja-build \
    zlib1g-dev \
    libssl-dev \
    libsdl-dev \
    libaio-dev \
    libfdt-dev \
    cabextract \
    libpci-dev \
    libbz2-dev \
    python-dev \
    libx11-dev \
    libc6-dev \
    iproute2 \
    git-core \
    uuid-dev \
    autoconf \
    automake \
    xz-utils \
    gettext \
    libtool \
    kpartx \
    golang \
    ocaml \
    bison \
    patch \
    bzip2 \
    bin86 \
    clang \
    iasl \
    flex \
    nasm \
    llvm \
    gawk \
    make \
    wget \
    git \
    bcc \
    gcc \
    lld
```

### Drakvuf
```bash
cd ~
git clone https://github.com/tklengyel/drakvuf
cd drakvuf
git submodule update --init
cd xen
./configure --enable-githttp --enable-systemd --enable-ovmf --disable-pvshim
make -j4 dist-xen
make -j4 dist-tools
make -j4 debball
```

### Install LibVMI
```bash
cd ~/drakvuf/libvmi
autoreconf -vif
./configure --disable-kvm --disable-bareflank --disable-file
make
sudo make install
sudo echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib" >> ~/.bashrc
```

### Install Volatility3
```bash
cd ~/drakvuf/volatility3
python3 ./setup.py build
sudo python3 ./setup.py install
```

### Configure Volatility3
```bash
sudo xl list
```

```
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  4024     4     r-----     848.8
windows7-sp1-x86                             7  3000     1     -b----      94.7
```

```bash
sudo vmi-win-guid name windows7-sp1-x86
```

```
Windows Kernel found @ 0x2604000
	Version: 32-bit Windows 7
	PE GUID: 4ce78a09412000
	PDB GUID: 684da42a30cc450f81c535b4d18944b12
	Kernel filename: ntkrpamp.pdb
	Multi-processor with PAE (version 5.0 and higher)
	Signature: 17744.
	Machine: 332.
	# of sections: 22.
	# of symbols: 0.
	Timestamp: 1290242569.
	Characteristics: 290.
	Optional header size: 224.
	Optional header type: 0x10b
	Section 1: .text
	Section 2: _PAGELK
	Section 3: POOLMI
	Section 4: POOLCODE
	Section 5: .data
	Section 6: ALMOSTRO
	Section 7: SPINLOCK
	Section 8: PAGE
	Section 9: PAGELK
	Section 10: PAGEKD
	Section 11: PAGEVRFY
	Section 12: PAGEHDLS
	Section 13: PAGEBGFX
	Section 14: PAGEVRFB
	Section 15: .edata
	Section 16: PAGEDATA
	Section 17: PAGEKDD
	Section 18: PAGEVRFC
	Section 19: PAGEVRFD
	Section 20: INIT
	Section 21: .rsrc
	Section 22: .reloc
```

**The important fields are:**
```
PDB GUID: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Kernel filename: XXXXXXXX.pdb
```

#### Generate the Volatility File
```bash
python3 ~/drakvuf/volatility3/volatility3/framework/symbols/windows/pdbconv.py \
    --guid 684da42a30cc450f81c535b4d18944b12 \
    -p ntkrpamp.pdb \
    -o win10.json
```

#### Create the LibVMI Config
```bash
sudo printf "<VM NAME> {\n\tvolatility_ist = \"/path/to/file/<win10>.json\";\n}" >> /etc/libvmi.conf
```

#### Build Drakvuf
```bash 
cd /path/to/drakvuf && \
rm -rf build/ && \
meson setup build --native-file llvm.ini && \
ninja -C build
```
