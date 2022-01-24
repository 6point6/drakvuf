# DRAKVUF&trade;

## Introduction

DRAKVUF is a virtualization based agentless black-box binary analysis system. DRAKVUF
allows for in-depth execution tracing of arbitrary binaries (including operating
systems), all without having to install any special software within the virtual machine
used for analysis.

## Hardware requirements

DRAKVUF uses hardware virtualization extensions found in Intel CPUs. You will need an
Intel CPU with virtualization support (VT-x) and with Extended Page Tables (EPT). DRAKVUF
 is not going to work on any other CPUs (such as AMD) or on Intel CPUs without the
required virtualization extensions.

## Supported guests

DRAKVUF currently supports:
 - Windows 7 - 8, both 32 and 64-bit
 - Windows 10 64-bit
 - Linux 2.6.x - 5.x, both 32-bit and 64-bit

## Pre-built Debian packages

You can find pre-built Debian packages of the latest DRAKVUF builds at
https://github.com/tklengyel/drakvuf-builds/releases
 
## Malware analysis

DRAKVUF provides a perfect platform for stealthy malware analysis as its footprint is
nearly undectebable from the malware's perspective. While DRAKVUF has been mainly
developed with malware analysis in mind, it is certainly not limited to that task as it
can be used to monitor the execution of arbitrary binaries.

## Graphical frontend

If you would like a full-featured DRAKVUF GUI to setup as automated analysis sandbox, check out the
[DRAKVUF Sandbox project](https://github.com/CERT-Polska/drakvuf-sandbox).

## APIMON plugin
The `apimon` plugin has been modified to update a struct named `usri3_name` whenever the `NetUserGetInfo` function is called ([Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo)). This function is related to the `net user USERNAME` command, found on Windows systems since XP.

The `--dll-hooks-list` option must supplied with a file should look exactly like this:
```log
samcli.dll,NetUserGetInfo,log,lpcwstr,lpcwstr,dword,lpbyte
```

To run Drakvuf with the apimon plugin, type (a few extra options have been added to limit output):
```bash
sudo ./drakvuf -a apimon -d win10-dev -r /root/windows10-pro-21h1.json \
 --dll-hooks-list /home/tester/guests/dll-hooks-test.txt \
 --memdump-disable-free-vm --memdump-disable-protect-vm \
 --memdump-disable-write-vm --memdump-disable-terminate-proc \
 --memdump-disable-create-thread --memdump-disable-set-thread \
 --disable-sysret -o json
```

-------

More information can be found on the project website: https://drakvuf.com

[![ci](https://github.com/tklengyel/drakvuf/actions/workflows/ci.yml/badge.svg)](https://github.com/tklengyel/drakvuf/actions/workflows/ci.yml)
<a href="https://scan.coverity.com/projects/tklengyel-drakvuf"><img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/3238/badge.svg"/></a>
