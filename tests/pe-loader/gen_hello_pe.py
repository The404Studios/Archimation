#!/usr/bin/env python3
"""
gen_hello_pe.py - Generate a minimal 64-bit PE executable

Creates hello.exe: a tiny Windows console application that writes
"Hello from PE!\n" to stdout using kernel32!WriteFile and then exits
via kernel32!ExitProcess.

This is a hand-crafted PE binary that can be loaded by the PE loader
without needing MinGW. It uses only two kernel32 imports:
  - GetStdHandle
  - WriteFile
  - ExitProcess

Usage: python3 gen_hello_pe.py [output.exe]
"""

import struct
import sys

# PE constants
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

# Sections: .text (code), .rdata (imports), .data (message string)
IMAGE_BASE = 0x00400000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200

# Layout:
# 0x000: DOS header + PE signature
# 0x100: COFF + Optional header
# 0x200: Section headers
# 0x400: .text section (code)
# 0x600: .rdata section (import table)
# 0xa00: .data section (message string)

# Virtual addresses
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
DATA_RVA = 0x3000

MSG = b"Hello from PE!\n"
MSG_OFFSET_IN_DATA = 0  # offset within .data


def align(val, alignment):
    return (val + alignment - 1) & ~(alignment - 1)


def build_import_directory(rdata_base):
    """Build Import Directory Table + Import Lookup/Address Tables for kernel32.dll"""
    # We need:
    # 1. Import Directory Table (one entry for kernel32 + null terminator)
    # 2. Import Lookup Table (ILT) - array of hint/name RVAs
    # 3. Import Address Table (IAT) - initially same as ILT, patched by loader
    # 4. Hint/Name entries
    # 5. DLL name string

    # Layout within .rdata:
    # 0x000: Import Directory Entry for kernel32 (20 bytes)
    # 0x014: Null terminator entry (20 bytes)
    # 0x028: ILT (3 entries + null = 32 bytes)
    # 0x048: IAT (3 entries + null = 32 bytes)
    # 0x068: Hint/Name: GetStdHandle
    # 0x080: Hint/Name: WriteFile
    # 0x094: Hint/Name: ExitProcess
    # 0x0A8: DLL name "kernel32.dll"

    ilt_rva = rdata_base + 0x28
    iat_rva = rdata_base + 0x48
    hint_getstdhandle_rva = rdata_base + 0x68
    hint_writefile_rva = rdata_base + 0x80
    hint_exitprocess_rva = rdata_base + 0x94
    dllname_rva = rdata_base + 0xA8

    # Import Directory Entry (20 bytes each)
    # OriginalFirstThunk (ILT), TimeDateStamp, ForwarderChain, Name, FirstThunk (IAT)
    idt = struct.pack("<IIIII", ilt_rva, 0, 0, dllname_rva, iat_rva)
    idt += b'\x00' * 20  # null terminator entry

    # ILT entries (8 bytes each for PE32+)
    ilt = struct.pack("<QQQ Q",
                      hint_getstdhandle_rva,
                      hint_writefile_rva,
                      hint_exitprocess_rva,
                      0)  # null terminator

    # IAT entries (same as ILT initially - loader patches these)
    iat = struct.pack("<QQQ Q",
                      hint_getstdhandle_rva,
                      hint_writefile_rva,
                      hint_exitprocess_rva,
                      0)  # null terminator

    # Hint/Name entries: 2-byte hint + name + padding
    def hint_name(hint, name):
        data = struct.pack("<H", hint) + name.encode('ascii') + b'\x00'
        if len(data) % 2:
            data += b'\x00'
        return data

    hn_getstdhandle = hint_name(0, "GetStdHandle")    # 16 bytes padded
    hn_writefile = hint_name(0, "WriteFile")           # 12 bytes padded
    hn_exitprocess = hint_name(0, "ExitProcess")       # 14 bytes padded

    dllname = b"kernel32.dll\x00"

    # Assemble .rdata: pad each piece to expected offset
    rdata = bytearray(0x200)  # pre-allocate
    rdata[0x00:0x00+len(idt)] = idt
    rdata[0x28:0x28+len(ilt)] = ilt
    rdata[0x48:0x48+len(iat)] = iat
    rdata[0x68:0x68+len(hn_getstdhandle)] = hn_getstdhandle
    rdata[0x80:0x80+len(hn_writefile)] = hn_writefile
    rdata[0x94:0x94+len(hn_exitprocess)] = hn_exitprocess
    rdata[0xA8:0xA8+len(dllname)] = dllname

    return bytes(rdata), iat_rva


def build_code(iat_rva, msg_rva, msg_len):
    """Build x86-64 code that calls GetStdHandle, WriteFile, ExitProcess."""
    # IAT layout: [0]=GetStdHandle, [8]=WriteFile, [16]=ExitProcess
    getstdhandle_iat = iat_rva
    writefile_iat = iat_rva + 8
    exitprocess_iat = iat_rva + 16

    code = bytearray()

    # Windows x64 ABI: first 4 args in rcx, rdx, r8, r9
    # Stack must be 16-byte aligned, with 32-byte shadow space

    # sub rsp, 0x48 (align stack + shadow + local space)
    code += b'\x48\x83\xEC\x48'

    # --- GetStdHandle(-11) = STD_OUTPUT_HANDLE ---
    # mov ecx, -11 (0xFFFFFFF5)
    code += b'\xB9\xF5\xFF\xFF\xFF'
    # mov rax, [getstdhandle_iat]
    code += b'\x48\xA1' + struct.pack('<Q', getstdhandle_iat)
    # call rax
    code += b'\xFF\xD0'
    # mov rbx, rax  (save handle)
    code += b'\x48\x89\xC3'

    # --- WriteFile(handle, msg, len, &written, NULL) ---
    # mov rcx, rbx (handle)
    code += b'\x48\x89\xD9'
    # lea rdx, [msg_rva] -- mov rdx, imm64
    code += b'\x48\xBA' + struct.pack('<Q', msg_rva)
    # mov r8d, msg_len
    code += b'\x41\xB8' + struct.pack('<I', msg_len)
    # lea r9, [rsp+0x30] (&written - local variable on stack)
    code += b'\x4C\x8D\x4C\x24\x30'
    # mov qword [rsp+0x20], 0 (lpOverlapped = NULL, in shadow space for 5th arg)
    code += b'\x48\xC7\x44\x24\x20\x00\x00\x00\x00'
    # mov rax, [writefile_iat]
    code += b'\x48\xA1' + struct.pack('<Q', writefile_iat)
    # call rax
    code += b'\xFF\xD0'

    # --- ExitProcess(0) ---
    # xor ecx, ecx
    code += b'\x31\xC9'
    # mov rax, [exitprocess_iat]
    code += b'\x48\xA1' + struct.pack('<Q', exitprocess_iat)
    # call rax
    code += b'\xFF\xD0'

    # (Should never reach here, but just in case)
    # add rsp, 0x48
    code += b'\x48\x83\xC4\x48'
    # ret
    code += b'\xC3'

    return bytes(code)


def build_pe():
    """Build the complete PE file."""
    # Build .rdata (imports)
    rdata, iat_rva = build_import_directory(RDATA_RVA)

    # Build .data (message)
    data = bytearray(0x200)
    data[MSG_OFFSET_IN_DATA:MSG_OFFSET_IN_DATA+len(MSG)] = MSG

    msg_rva = IMAGE_BASE + DATA_RVA + MSG_OFFSET_IN_DATA

    # Build .text (code)
    code = build_code(IMAGE_BASE + iat_rva, msg_rva, len(MSG))
    text = bytearray(0x200)
    text[0:len(code)] = code

    # Entry point RVA
    entry_rva = TEXT_RVA

    # --- DOS Header ---
    dos_header = bytearray(0x100)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 0x80)  # e_lfanew -> PE sig at 0x80

    # PE Signature at 0x80
    dos_header[0x80:0x84] = b'PE\x00\x00'

    # --- COFF Header (20 bytes at 0x84) ---
    # Machine=0x8664 (AMD64), NumberOfSections=3
    coff = struct.pack("<HH III HH",
        0x8664,    # Machine
        3,         # NumberOfSections
        0,         # TimeDateStamp
        0,         # PointerToSymbolTable
        0,         # NumberOfSymbols
        0xF0,      # SizeOfOptionalHeader (PE32+ = 240 bytes)
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
    )
    dos_header[0x84:0x84+len(coff)] = coff

    # --- Optional Header PE32+ (starts at 0x98) ---
    opt = bytearray(0xF0)

    # Magic (PE32+ = 0x020B)
    struct.pack_into('<H', opt, 0, 0x020B)
    # MajorLinkerVersion, MinorLinkerVersion
    opt[2] = 1; opt[3] = 0
    # SizeOfCode
    struct.pack_into('<I', opt, 4, 0x200)
    # SizeOfInitializedData
    struct.pack_into('<I', opt, 8, 0x400)
    # SizeOfUninitializedData
    struct.pack_into('<I', opt, 12, 0)
    # AddressOfEntryPoint
    struct.pack_into('<I', opt, 16, entry_rva)
    # BaseOfCode
    struct.pack_into('<I', opt, 20, TEXT_RVA)

    # --- PE32+ specific (64-bit) ---
    # ImageBase (8 bytes at offset 24)
    struct.pack_into('<Q', opt, 24, IMAGE_BASE)
    # SectionAlignment
    struct.pack_into('<I', opt, 32, SECTION_ALIGNMENT)
    # FileAlignment
    struct.pack_into('<I', opt, 36, FILE_ALIGNMENT)
    # OS Version 6.0
    struct.pack_into('<HH', opt, 40, 6, 0)
    # Image Version
    struct.pack_into('<HH', opt, 44, 0, 0)
    # Subsystem Version 6.0
    struct.pack_into('<HH', opt, 48, 6, 0)
    # Win32VersionValue
    struct.pack_into('<I', opt, 52, 0)
    # SizeOfImage (must be aligned to SectionAlignment)
    struct.pack_into('<I', opt, 56, 0x4000)
    # SizeOfHeaders
    struct.pack_into('<I', opt, 60, 0x400)
    # CheckSum
    struct.pack_into('<I', opt, 64, 0)
    # Subsystem (CUI = console)
    struct.pack_into('<H', opt, 68, IMAGE_SUBSYSTEM_WINDOWS_CUI)
    # DllCharacteristics
    struct.pack_into('<H', opt, 70, 0)
    # SizeOfStackReserve (8 bytes at 72)
    struct.pack_into('<Q', opt, 72, 0x100000)
    # SizeOfStackCommit
    struct.pack_into('<Q', opt, 80, 0x1000)
    # SizeOfHeapReserve
    struct.pack_into('<Q', opt, 88, 0x100000)
    # SizeOfHeapCommit
    struct.pack_into('<Q', opt, 96, 0x1000)
    # LoaderFlags
    struct.pack_into('<I', opt, 104, 0)
    # NumberOfRvaAndSizes
    struct.pack_into('<I', opt, 108, 16)

    # Data directories (8 bytes each, starting at offset 112)
    # Index 1: Import Directory
    struct.pack_into('<II', opt, 112 + 1*8, RDATA_RVA, 0x28)  # RVA, Size

    dos_header[0x98:0x98+len(opt)] = opt

    # --- Section Headers (start at 0x188, 40 bytes each) ---
    # After COFF (20 bytes at 0x84) + Optional (0xF0 bytes at 0x98) = ends at 0x188
    section_start = 0x188

    def section_header(name, vsize, vrva, rawsize, rawptr, flags):
        hdr = bytearray(40)
        hdr[0:len(name)] = name[:8]
        struct.pack_into('<I', hdr, 8, vsize)    # VirtualSize
        struct.pack_into('<I', hdr, 12, vrva)     # VirtualAddress
        struct.pack_into('<I', hdr, 16, rawsize)  # SizeOfRawData
        struct.pack_into('<I', hdr, 20, rawptr)   # PointerToRawData
        struct.pack_into('<I', hdr, 36, flags)    # Characteristics
        return bytes(hdr)

    # .text: CODE | EXECUTE | READ
    sh_text = section_header(b'.text\x00\x00\x00', 0x200, TEXT_RVA, 0x200, 0x400,
                             0x60000020)
    # .rdata: INITIALIZED_DATA | READ
    sh_rdata = section_header(b'.rdata\x00\x00', 0x200, RDATA_RVA, 0x200, 0x600,
                              0x40000040)
    # .data: INITIALIZED_DATA | READ | WRITE
    sh_data = section_header(b'.data\x00\x00\x00', 0x200, DATA_RVA, 0x200, 0x800,
                             0xC0000040)

    dos_header[section_start:section_start+40] = sh_text
    dos_header[section_start+40:section_start+80] = sh_rdata
    dos_header[section_start+80:section_start+120] = sh_data

    # --- Assemble final PE ---
    pe = bytearray(0xA00)  # headers(0x400) + .text(0x200) + .rdata(0x200) + .data(0x200)

    # Headers
    pe[0:len(dos_header)] = dos_header

    # .text at file offset 0x400
    pe[0x400:0x400+len(text)] = text

    # .rdata at file offset 0x600
    pe[0x600:0x600+len(rdata)] = rdata

    # .data at file offset 0x800
    pe[0x800:0x800+len(data)] = data

    return bytes(pe)


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "hello.exe"
    pe = build_pe()

    with open(output, 'wb') as f:
        f.write(pe)

    print(f"Generated {output} ({len(pe)} bytes)")
    print(f"  Entry point RVA: 0x{TEXT_RVA:04X}")
    print(f"  Image base: 0x{IMAGE_BASE:08X}")
    print(f"  Imports: kernel32.dll (GetStdHandle, WriteFile, ExitProcess)")
    print(f"  Message: {MSG.decode().strip()!r}")


if __name__ == "__main__":
    main()
