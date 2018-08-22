# Bochspwn Reloaded

Bochspwn Reloaded is an instrumentation module for the [Bochs IA-32 emulator](http://bochs.sourceforge.net/), similar to the original [Bochspwn](https://github.com/google/bochspwn) project from 2013. It performs taint tracking of the kernel address space of the guest operating systems, to detect the disclosure of uninitialized kernel stack/heap memory to user-mode and other data sinks. It helped us identify over [70](https://bugs.chromium.org/p/project-zero/issues/list?can=1&q=finder:mjurczyk%20product:kernel%20opened%3E2017-02-23%20opened%3C2018-1-23%20%22uninitialized%20%22memory%20disclosure%22&colspec=ID%20Status%20Restrict%20Reported%20Vendor%20Product%20Finder%20Summary&cells=ids) bugs in the Windows kernel, and more than [10](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/?qt=author&q=mjurczyk@google.com) lesser bugs in Linux in 2017 and early 2018.

The tool was discussed at the [REcon Montreal](https://j00ru.vexillium.org/talks/recon-bochspwn-reloaded-detecting-kernel-memory-disclosure/), [Black Hat USA](https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/), and [INFILTRATE](https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions-further-advancements-in-detecting-kernel-infoleaks/) conferences, as well as in the [  
Detecting Kernel Memory Disclosure with x86 Emulation and Taint Tracking](http://j00ru.vexillium.org/papers/2018/bochspwn_reloaded.pdf) white paper. The paper includes a comprehensive description of the general kernel infoleak bug class, as well as an in-depth study of Bochspwn Reloaded and its inner workings. We highly recommend the read before diving right into the source code, as it may answer many potential questions that may arise while experimenting with the tool. Specifically, Chapter 3 covers the fundamental ideas behind it and the implementation details of the software.

## Instrumentation types

The repository contains four directories, each comprising a separate Bochs instrumentation module:

- `linux-x86` - kernel infoleak detection for 32-bit Linux.
- `windows-x86` - kernel infoleak detection for 32-bit Windows.
- `windows-x64` - kernel infoleak detection for 64-bit WIndows.
- `windows-x86-markers` - an instrumentation for 32-bit Windows, which facilitates the detection of kernel memory disclosure to other sinks (such as file systems or network), by poisoning all kernel stack and pool allocations with the addresses of the allocation origins. For details, refer to Section 6.1 in the white paper.

Depending on the specific system being tested inside of Bochs, it is necessary to recompile the emulator with the suitable instrumentation.

## Building

The steps required to cross-compile Bochspwn Reloaded on Linux to run on Windows are enumerated below. For additional reference, you may find the [Bochspwn documentation](https://github.com/google/bochspwn/blob/master/DOCUMENTATION.old.md) useful.

1. Install the `x86_64-w64-mingw32` compiler via the `mingw-w64` package.
2. Download [Protocol Buffers 3.4.1](https://github.com/google/protobuf/releases/tag/v3.4.1), unpack it, compile and install, both for your local toolchain (to get access to the `protoc` command-line utility), and for the `x86_64-w64-mingw32` cross-compilation toolchain (to install the essential headers and libraries).
3. Download the latest version of Bochs (currently 2.6.9), unpack it, and copy the desired instrumentation directory (e.g. `windows-x64`), together with the corresponding third-party subdirectory (e.g. `third_party/instrumentation/windows-x64`) into `bochs-2.6.9/instrument`.
4. In case of Windows-specific instrumentations, copy the DbgHelp library file (`dbghelp.lib` or `dbghelp.dll`) from a Microsoft SDK or your local Windows installation to the `bochs-2.6.9/instrument/<instrumentation>` directory.
5. Configure Bochs and compile it:
```bash
$ CFLAGS="-O2 -Wno-narrowing -Wno-format" \
> CXXFLAGS="-O2 -std=c++11 -Wno-narrowing -Wno-format" \
> LIBS="-lprotobuf instrument/<instrumentation>/dbghelp.dll" \
> ./configure \
>  --host=x86_64-w64-mingw32 \
>  --enable-x86-64 \
>  --enable-e1000 \
>  --with-win32 \
>  --without-x \
>  --without-x11 \
>  --enable-cpu-level=6 \
>  --enable-pci \
>  --enable-pnic \
>  --enable-fast-function-calls \
>  --enable-fpu \
>  --enable-avx \
>  --enable-cdrom \
>  --disable-all-optimizations \
>  --disable-memtype \
>  --enable-instrumentation="instrument/<instrumentation>"
$ make
```

This should result in the creation of a 64-bit PE file named `bochs`, which can be then copied to a Windows host and run from there:

```bash
$ file bochs
bochs: PE32+ executable (console) x86-64, for MS Windows
$
```

## Usage

In order to use the newly compiled Bochs emulator on your Windows host, perform the following steps:

1. Download and install Bochs for Windows, which will supply parts of the executive environment such as ROM code not being built into the main executable.
2. Create a `bochsrc.txt` Bochs configuration file, or modify an existing one.
3. Create a raw disk image with the tested guest operating system, preferably by first installing the OS in a normal virtual machine such as VirtualBox, and then converting a `.vdi` or other file into the raw format.
4. Extract all kernel drivers from the guest system, and save them on the host machine. In case of Windows, download the corresponding `.pdb` files for each of them from the [Microsoft Symbol Server](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols). This is needed to symbolize stack traces in the output log, and to correctly traverse call stacks on 64-bit builds of Windows.
5. Create a Bochspwn configuration INI file, or adjust an existing one to your needs. For each of the four instrumentation modules, an example configuration file is provided in this repository.
6. If you are testing Windows and intend to attach a kernel debugger to the emulated system, install [WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) on your host, configure the guest to boot in debug mode, and redirect a serial port (COM) to a Windows named pipe in the `bochsrc.txt` configuration file.
7. Create a Bochs start up batch script (e.g. `start.bat`), for example:

```batch
set BXSHARE=C:\Program Files (x86)\Bochs-2.6.9
set BOCHSPWN_CONF=C:\bochspwn\config.txt
bochs.exe -f C:\bochspwn\bochsrc.txt
```

If all of the above steps were successfully completed, congratulations! You should now be able to run the target system inside of Bochs, attach a kernel debugger, and potentially start observing reports of kernel memory disclosure bugs once the system boots up. It is now up to you to trigger a vast kernel code coverage (e.g. by running system call fuzzers), and thus enable Bochspwn Reloaded to identify new, previously unpatched memory disclosure vulnerabilities.

## Example reports

_Report of the [CVE-2017-8473](https://bugs.chromium.org/p/project-zero/issues/detail?id=1181) bug detected on Windows 7 32-bit:_
```
------------------------------ found uninit-access of address 94447d04
[pid/tid: 000006f0/00000740] {    explorer.exe}
       READ of 94447d04 (4 bytes, kernel--->user), pc = 902df30f
       [ rep movsd dword ptr es:[edi], dword ptr ds:[esi] ]

[Pool allocation not recognized]
Allocation origin: 0x90334988 (win32k.sys!__SEH_prolog4+00000018)

Destination address: 1b9d380
Shadow bytes: 00 ff ff ff Guest bytes: 00 bb bb bb 

Stack trace:
 #0  0x902df30f (win32k.sys!NtGdiGetRealizationInfo+0000005e)
 #1  0x8288cdb6 (ntoskrnl.exe!KiSystemServicePostCall+00000000)
```

_Report of the [CVE-2018-0894](https://bugs.chromium.org/p/project-zero/issues/detail?id=1458) bug detected on Windows 7 64-bit:_
```
------------------------------ found uninit-copy of address fffff8a000a63010

[pid/tid: 000001a0/000001a4] {     wininit.exe}
       COPY of fffff8a000a63010 ---> 1afab8 (64 bytes), pc = fffff80002698600
       [                             mov r11, rcx ]
Allocation origin: 0xfffff80002a11101
                   (ntoskrnl.exe!IopQueryNameInternal+00000071)
--- Shadow memory:
00000000: 00 00 00 00 ff ff ff ff 00 00 00 00 00 00 00 00 ................
00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
--- Actual memory:
00000000: 2e 00 30 00 aa aa aa aa 20 30 a6 00 a0 f8 ff ff ..0..... 0......
00000010: 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 \.D.e.v.i.c.e.\.
00000020: 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 H.a.r.d.d.i.s.k.
00000030: 56 00 6f 00 6c 00 75 00 6d 00 65 00 32 00 00 00 V.o.l.u.m.e.2...
--- Stack trace:
 #0  0xfffff80002698600 (ntoskrnl.exe!memmove+00000000)
 #1  0xfffff80002a11319 (ntoskrnl.exe!IopQueryNameInternal+00000289)
 #2  0xfffff800028d4426 (ntoskrnl.exe!IopQueryName+00000026)
 #3  0xfffff800028e8fa8 (ntoskrnl.exe!ObpQueryNameString+000000b0)
 #4  0xfffff8000291313b (ntoskrnl.exe!NtQueryVirtualMemory+000005fb)
 #5  0xfffff800026b9283 (ntoskrnl.exe!KiSystemServiceCopyEnd+00000013)
```

_Report of [a bug](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=608c4adfcabab220142ee335a2a003ccd1c0b25b) in `llcp_sock_connect` on Ubuntu 16.10 32-bit:_
```
------------------------------ found uninit-access of address f5733f38
========== READ of f5733f38 (4 bytes, kernel--->kernel), pc = f8aaf5c5
                            [           mov edi, dword ptr ds:[ebx+84] ]
[Heap allocation not recognized]
Allocation origin: 0xc16b40bc: SYSC_connect at net/socket.c:1524
Shadow bytes: ff ff ff ff Guest bytes: bb bb bb bb
Stack trace:
#0  0xf8aaf5c5: llcp_sock_connect at net/nfc/llcp_sock.c:668
#1  0xc16b4141: SYSC_connect at net/socket.c:1536
#2  0xc16b4b26: SyS_connect at net/socket.c:1517
#3  0xc100375d: do_syscall_32_irqs_on at arch/x86/entry/common.c:330
  (inlined by) do_fast_syscall_32 at arch/x86/entry/common.c:392
```

## Disclaimer

This is not an official Google product.
