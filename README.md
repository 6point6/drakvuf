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
This plugin has been modified to manipulate the behaviour of Windows systems by hooking into specific user mode calls.

* Modify the response of `net user USERNAME` command.
* Modify the reponse of `whoami` command.
* Pause guest VM when a `ping` request is sent.
* Modify the response of `Invoke-WebRequest` when a HTTPS request sent.

The `--dll-hooks-list` option must supplied: (**NOTE: DLL names are case-sensitive!**). Use the following links to help with identifying the right symbols and DLLs, [WinDBG](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) and [winpdb](https://lise.pnfsoftware.com/winpdb/).

To run Drakvuf with modified apimon plugin, type:
```bash
sudo ./drakvuf -a apimon -d win10-dev -r /root/windows10-pro-21h1.json \
 --dll-hooks-list /home/tester/guests/dll-hooks-test.txt \
 -o json
```

### Hooking NetUserGetInfo
The `NetUserGetInfo` function uses the `samcli.dll` module. The hook modifies a struct named `usri3_name` whenever the `NetUserGetInfo` function is called ([Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo)). This function is related to the `net user USERNAME` command, found on most Windows systems since XP.

Use the following DLL signature:
```log
samcli.dll,NetUserGetInfo,log,lpcwstr,lpcwstr,dword,lpbyte
```

### Hooking LookupAccountSidW
The `LookupAccountSidW` function uses the `advapi32.dll` module. This is used whenever the `whoami.exe` command is executed. This hook simply modifies the **second entry argument**, resulting in NT System user SID returned.

Use the following DLL signature:
```log
advapi32.dll,LookupAccountSidW,log,lpcwstr,psid,lpwstr,lpdword,lpwstr,lpdword,psid_name_use
```

### Hooking IcmpSendEcho2Ex
The `IcmpSendEcho2Ex` function uses the `IPHLPAPI.DLL` module. It is used by many applications such as `ping.exe`. All code does is pauses the VM for 3 seconds and resumes.

Use the following DLL signature:
```log
IPHLPAPI.DLL,IcmpSendEcho2Ex,log,handle,handle,pio_apc_routine,pvoid,srcipaddr,dstipaddr,lpvoid,word,pip_option_information,lpvoid,dword,dword
```

### Hooking TlsDecryptPacket
The `TlsDecryptPacket` function uses the `ncrypt.dll` module. The hook works by obtaining the memory address of the decrypted buffer (5th argument) of `TlsDecryptPacket` and replaces 10 bytes and returns. To activate the request simply use Powershell and the cmdlet `Invoke-WebRequest` with a **HTTPS** URI. For example:
```bash
Invoke-WebRequest -Uri "https://example.com/file.txt" -OutFile "C:\path\file.txt"
```

Use the following DLL signature:
```log
ncrypt.dll,SslDecryptPacket,log,NCRYPT_PROV_HANDLE,NCRYPT_KEY_HANDLE,PBYTE,DWORD,PBYTE,DWORD,DWORD,ULONGLONG,DWORD
```

-------

More information can be found on the project website: https://drakvuf.com

[![ci](https://github.com/tklengyel/drakvuf/actions/workflows/ci.yml/badge.svg)](https://github.com/tklengyel/drakvuf/actions/workflows/ci.yml)
<a href="https://scan.coverity.com/projects/tklengyel-drakvuf"><img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/3238/badge.svg"/></a>
