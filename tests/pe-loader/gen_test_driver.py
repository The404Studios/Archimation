#!/usr/bin/env python3
"""
gen_test_driver.py - Generate a minimal 64-bit PE kernel driver (.sys)

Creates test_driver.sys: a tiny Windows kernel driver that:
  1. Calls DbgPrint("Hello from Windows driver!")
  2. Creates a device \\Device\\TestDrv
  3. Creates a symlink \\DosDevices\\TestDrv
  4. Sets up IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_DEVICE_CONTROL
  5. IOCTL handler returns "Hello from driver IOCTL!"

Imports from ntoskrnl.exe:
  - DbgPrint
  - RtlInitUnicodeString
  - IoCreateDevice
  - IoCreateSymbolicLink
  - IoDeleteDevice
  - IoDeleteSymbolicLink
  - IoCompleteRequest
  - IofCompleteRequest

Usage: python3 gen_test_driver.py [output.sys]
"""

import struct
import sys

# PE constants
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_SYSTEM = 0x1000  # System file (driver)
IMAGE_SUBSYSTEM_NATIVE = 1

# Layout
IMAGE_BASE = 0x00400000  # Use standard exe base to avoid preloader DOS area conflict
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200

# Virtual addresses
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
DATA_RVA = 0x3000


def align(val, alignment):
    return (val + alignment - 1) & ~(alignment - 1)


def build_import_directory(rdata_base):
    """Build Import Directory for ntoskrnl.exe"""
    # Imports:
    #  0: DbgPrint
    #  1: RtlInitUnicodeString
    #  2: IoCreateDevice
    #  3: IoCreateSymbolicLink
    #  4: IoCompleteRequest
    #  5: IofCompleteRequest

    num_imports = 6

    # Layout within .rdata:
    # 0x000: Import Directory Entry for ntoskrnl.exe (20 bytes)
    # 0x014: Null terminator entry (20 bytes)
    # 0x028: ILT (num_imports entries + null = (num_imports+1)*8 bytes)
    # ILT_END: IAT (same size)
    # IAT_END: Hint/Name entries
    # After hints: DLL name

    ilt_offset = 0x28
    ilt_size = (num_imports + 1) * 8
    iat_offset = ilt_offset + ilt_size
    iat_size = ilt_size
    hints_offset = iat_offset + iat_size

    ilt_rva = rdata_base + ilt_offset
    iat_rva = rdata_base + iat_offset

    # Build hint/name entries
    imports = [
        (0, "DbgPrint"),
        (0, "RtlInitUnicodeString"),
        (0, "IoCreateDevice"),
        (0, "IoCreateSymbolicLink"),
        (0, "IoCompleteRequest"),
        (0, "IofCompleteRequest"),
    ]

    hint_entries = []
    hint_rvas = []
    current_offset = hints_offset

    for hint, name in imports:
        entry = struct.pack("<H", hint) + name.encode('ascii') + b'\x00'
        if len(entry) % 2:
            entry += b'\x00'
        hint_rvas.append(rdata_base + current_offset)
        hint_entries.append((current_offset, entry))
        current_offset += len(entry)

    # DLL name
    dllname = b"ntoskrnl.exe\x00"
    dllname_offset = current_offset
    dllname_rva = rdata_base + dllname_offset

    total_size = dllname_offset + len(dllname)
    rdata = bytearray(align(total_size, FILE_ALIGNMENT))

    # Import Directory Entry
    idt = struct.pack("<IIIII", ilt_rva, 0, 0, dllname_rva, iat_rva)
    rdata[0x00:0x00+len(idt)] = idt
    # Null terminator
    rdata[0x14:0x14+20] = b'\x00' * 20

    # ILT entries
    for i, rva in enumerate(hint_rvas):
        struct.pack_into("<Q", rdata, ilt_offset + i * 8, rva)
    # Null terminator
    struct.pack_into("<Q", rdata, ilt_offset + num_imports * 8, 0)

    # IAT entries (same as ILT)
    for i, rva in enumerate(hint_rvas):
        struct.pack_into("<Q", rdata, iat_offset + i * 8, rva)
    struct.pack_into("<Q", rdata, iat_offset + num_imports * 8, 0)

    # Hint/Name entries
    for offset, entry in hint_entries:
        rdata[offset:offset+len(entry)] = entry

    # DLL name
    rdata[dllname_offset:dllname_offset+len(dllname)] = dllname

    return bytes(rdata), iat_rva


def build_data():
    """Build .data section with strings."""
    data = bytearray(0x200)

    # String table for the driver
    strings = {}
    pos = 0

    # DbgPrint message (ASCII, null-terminated)
    msg = b"Hello from Windows driver!\n\x00"
    strings['dbg_msg'] = pos
    data[pos:pos+len(msg)] = msg
    pos += len(msg)
    pos = align(pos, 2)

    # Device name: \Device\TestDrv (UTF-16LE)
    dev_name = "\\Device\\TestDrv"
    dev_name_utf16 = dev_name.encode('utf-16-le') + b'\x00\x00'
    strings['dev_name'] = pos
    strings['dev_name_len'] = len(dev_name) * 2  # byte length without null
    data[pos:pos+len(dev_name_utf16)] = dev_name_utf16
    pos += len(dev_name_utf16)
    pos = align(pos, 2)

    # Symlink name: \DosDevices\TestDrv (UTF-16LE)
    sym_name = "\\DosDevices\\TestDrv"
    sym_name_utf16 = sym_name.encode('utf-16-le') + b'\x00\x00'
    strings['sym_name'] = pos
    strings['sym_name_len'] = len(sym_name) * 2
    data[pos:pos+len(sym_name_utf16)] = sym_name_utf16
    pos += len(sym_name_utf16)
    pos = align(pos, 2)

    # IOCTL response: "Hello from driver IOCTL!\n" (ASCII)
    ioctl_msg = b"Hello from driver IOCTL!\n\x00"
    strings['ioctl_msg'] = pos
    strings['ioctl_msg_len'] = len(ioctl_msg) - 1  # exclude null
    data[pos:pos+len(ioctl_msg)] = ioctl_msg
    pos += len(ioctl_msg)

    return bytes(data), strings


def build_code(iat_rva, data_rva, strings):
    """Build x86-64 code for DriverEntry + dispatch routines."""
    # IAT layout (each 8 bytes):
    #  [0] = DbgPrint
    #  [8] = RtlInitUnicodeString
    #  [16] = IoCreateDevice
    #  [24] = IoCreateSymbolicLink
    #  [32] = IoCompleteRequest
    #  [40] = IofCompleteRequest

    abs_iat = IMAGE_BASE + iat_rva
    abs_data = IMAGE_BASE + data_rva

    dbgprint_iat = abs_iat + 0
    rtlinitunicode_iat = abs_iat + 8
    iocreatedevice_iat = abs_iat + 16
    iocreatesymlink_iat = abs_iat + 24
    iocomplete_iat = abs_iat + 32

    # Data addresses
    dbg_msg_addr = abs_data + strings['dbg_msg']
    dev_name_addr = abs_data + strings['dev_name']
    sym_name_addr = abs_data + strings['sym_name']
    ioctl_msg_addr = abs_data + strings['ioctl_msg']
    ioctl_msg_len = strings['ioctl_msg_len']

    code = bytearray()

    # ===================================================================
    # IRP dispatch stub (simple handler that returns STATUS_SUCCESS)
    # This is placed first so we know its RVA for the dispatch table setup.
    #
    # NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DevObj, PIRP Irp)
    # {
    #     Irp->IoStatus.Status = 0;  // STATUS_SUCCESS
    #     Irp->IoStatus.Information = 0;
    #     IofCompleteRequest(Irp, IO_NO_INCREMENT);
    #     return 0;
    # }
    # ===================================================================
    dispatch_create_close_offset = len(code)

    # Windows x64 ABI: rcx=DevObj, rdx=Irp
    # sub rsp, 0x28 (shadow space + alignment)
    code += b'\x48\x83\xEC\x28'

    # Irp->IoStatus.Status = 0 (offset 0x18 in our IRP struct)
    # mov dword [rdx+0x18], 0
    code += b'\xC7\x42\x18\x00\x00\x00\x00'

    # Irp->IoStatus.Information = 0 (offset 0x20 in our IRP struct)
    # mov qword [rdx+0x20], 0
    code += b'\x48\xC7\x42\x20\x00\x00\x00\x00'

    # IofCompleteRequest(Irp, IO_NO_INCREMENT=0)
    # mov rcx, rdx (Irp)
    code += b'\x48\x89\xD1'
    # xor edx, edx (IO_NO_INCREMENT)
    code += b'\x31\xD2'
    # mov rax, [iocomplete_iat]
    code += b'\x48\xA1' + struct.pack('<Q', iocomplete_iat)
    # call rax
    code += b'\xFF\xD0'

    # xor eax, eax (return STATUS_SUCCESS)
    code += b'\x31\xC0'
    # add rsp, 0x28
    code += b'\x48\x83\xC4\x28'
    # ret
    code += b'\xC3'

    # ===================================================================
    # IRP dispatch for DEVICE_CONTROL
    #
    # NTSTATUS DispatchIoctl(PDEVICE_OBJECT DevObj, PIRP Irp)
    # {
    #     // Copy "Hello from driver IOCTL!" into SystemBuffer
    #     // Set IoStatus.Information = length
    #     // Complete IRP
    #     return STATUS_SUCCESS;
    # }
    # MS x64 ABI: rbx, rsi, rdi are callee-saved. All three used here.
    # ===================================================================
    dispatch_ioctl_offset = len(code)

    # Save callee-saved registers FIRST (before sub rsp)
    code += b'\x53'               # push rbx
    code += b'\x56'               # push rsi
    code += b'\x57'               # push rdi
    # Shadow space: ret(8) + 3 pushes(24) + 0x20(32) = 64, 16-byte aligned
    code += b'\x48\x83\xEC\x20'  # sub rsp, 0x20

    # Save Irp in rbx
    code += b'\x48\x89\xD3'       # mov rbx, rdx

    # Get SystemBuffer: Irp->AssociatedIrp_SystemBuffer (offset 0x38)
    code += b'\x48\x8B\x7B\x38'   # mov rdi, [rbx+0x38]

    # Load source address: ioctl_msg_addr
    code += b'\x48\xBE' + struct.pack('<Q', ioctl_msg_addr)  # mov rsi, imm64

    # Copy ioctl_msg_len bytes (using rep movsb)
    code += b'\xB9' + struct.pack('<I', ioctl_msg_len)  # mov ecx, imm32
    code += b'\xF3\xA4'           # rep movsb

    # Irp->IoStatus.Status = 0 (offset 0x18)
    code += b'\xC7\x43\x18\x00\x00\x00\x00'

    # Irp->IoStatus.Information = ioctl_msg_len (offset 0x20)
    code += b'\x48\xC7\x43\x20' + struct.pack('<i', ioctl_msg_len)

    # IofCompleteRequest(Irp, 0)
    code += b'\x48\x89\xD9'       # mov rcx, rbx
    code += b'\x31\xD2'           # xor edx, edx
    code += b'\x48\xA1' + struct.pack('<Q', iocomplete_iat)
    code += b'\xFF\xD0'           # call rax

    # return STATUS_SUCCESS
    code += b'\x31\xC0'           # xor eax, eax
    # Epilogue: undo sub rsp, then pop in reverse push order
    code += b'\x48\x83\xC4\x20'  # add rsp, 0x20
    code += b'\x5F'               # pop rdi
    code += b'\x5E'               # pop rsi
    code += b'\x5B'               # pop rbx
    code += b'\xC3'               # ret

    # ===================================================================
    # DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
    #
    # Prologue: push callee-saved regs FIRST, then allocate local space.
    # This ensures saved regs are above local space and safe from shadow
    # space writes during function calls.
    # Stack layout after prologue (from rsp, growing up):
    #   [rsp+0x00..0x1F] = shadow space (32 bytes)
    #   [rsp+0x20..0x37] = args 5-7 for IoCreateDevice
    #   [rsp+0x38..0x3F] = padding
    #   [rsp+0x40..0x4F] = devNameU UNICODE_STRING (16 bytes)
    #   [rsp+0x50..0x57] = pDevObj output (8 bytes)
    #   [rsp+0x58..0x67] = symlinkU UNICODE_STRING (16 bytes)
    #   [rsp+0x68..0x6F] = unused
    #   [rsp+0x70]       = saved r13
    #   [rsp+0x78]       = saved r12
    #   [rsp+0x80]       = saved rbx
    #   [rsp+0x88]       = return address
    # ===================================================================
    driver_entry_offset = len(code)

    # Push callee-saved regs BEFORE sub rsp
    code += b'\x53'               # push rbx
    code += b'\x41\x54'           # push r12
    code += b'\x41\x55'           # push r13
    # ret(8) + 3 pushes(24) + 0x70(112) = 144 = 0x90, 16-byte aligned
    code += b'\x48\x83\xEC\x70'  # sub rsp, 0x70

    # Save args in callee-saved regs
    code += b'\x49\x89\xCC'       # mov r12, rcx (DriverObject)
    code += b'\x49\x89\xD5'       # mov r13, rdx (RegistryPath)

    # --- DbgPrint("Hello from Windows driver!\n") ---
    # For ms_abi varargs, caller MUST spill register args to shadow space
    code += b'\x48\xB9' + struct.pack('<Q', dbg_msg_addr)  # mov rcx, imm64
    code += b'\x48\x89\x0C\x24'  # mov [rsp], rcx (spill 1st arg)
    code += b'\x48\xA1' + struct.pack('<Q', dbgprint_iat)
    code += b'\xFF\xD0'           # call rax

    # --- Set up dispatch routines ---
    # MajorFunction is at offset 0x70 in DRIVER_OBJECT
    # [0]=CREATE(0x70), [2]=CLOSE(0x80), [14]=DEVICE_CONTROL(0xE0)
    dispatch_cc_abs = IMAGE_BASE + TEXT_RVA + dispatch_create_close_offset
    dispatch_ioctl_abs = IMAGE_BASE + TEXT_RVA + dispatch_ioctl_offset

    code += b'\x48\xB8' + struct.pack('<Q', dispatch_cc_abs)   # mov rax, dispatch_cc
    code += b'\x49\x89\x44\x24\x70'                            # mov [r12+0x70], rax
    code += b'\x49\x89\x84\x24\x80\x00\x00\x00'               # mov [r12+0x80], rax

    code += b'\x48\xB8' + struct.pack('<Q', dispatch_ioctl_abs)  # mov rax, dispatch_ioctl
    code += b'\x49\x89\x84\x24\xE0\x00\x00\x00'               # mov [r12+0xE0], rax

    # --- RtlInitUnicodeString(&devNameU, dev_name_addr) ---
    code += b'\x48\x8D\x4C\x24\x40'                            # lea rcx, [rsp+0x40]
    code += b'\x48\xBA' + struct.pack('<Q', dev_name_addr)      # mov rdx, imm64
    code += b'\x48\xA1' + struct.pack('<Q', rtlinitunicode_iat)
    code += b'\xFF\xD0'                                          # call rax

    # --- IoCreateDevice(DriverObj, 0, &devNameU, 0x22, 0, FALSE, &pDevObj) ---
    code += b'\x4C\x89\xE1'                                     # mov rcx, r12
    code += b'\x31\xD2'                                          # xor edx, edx
    code += b'\x4C\x8D\x44\x24\x40'                            # lea r8, [rsp+0x40]
    code += b'\x41\xB9\x22\x00\x00\x00'                        # mov r9d, 0x22
    code += b'\x48\xC7\x44\x24\x20\x00\x00\x00\x00'           # [rsp+0x20] = 0
    code += b'\x48\xC7\x44\x24\x28\x00\x00\x00\x00'           # [rsp+0x28] = 0
    code += b'\x48\x8D\x44\x24\x50'                            # lea rax, [rsp+0x50]
    code += b'\x48\x89\x44\x24\x30'                            # mov [rsp+0x30], rax
    code += b'\x48\xA1' + struct.pack('<Q', iocreatedevice_iat)
    code += b'\xFF\xD0'                                          # call rax

    # Check result
    code += b'\x85\xC0'           # test eax, eax
    # jnz .fail - placeholder, backpatched after we know the offset
    jnz_pos = len(code)
    code += b'\x75\x00'           # jnz rel8 (placeholder)

    # --- RtlInitUnicodeString(&symlinkU, sym_name_addr) ---
    code += b'\x48\x8D\x4C\x24\x58'                            # lea rcx, [rsp+0x58]
    code += b'\x48\xBA' + struct.pack('<Q', sym_name_addr)
    code += b'\x48\xA1' + struct.pack('<Q', rtlinitunicode_iat)
    code += b'\xFF\xD0'                                          # call rax

    # --- IoCreateSymbolicLink(&symlinkU, &devNameU) ---
    code += b'\x48\x8D\x4C\x24\x58'                            # lea rcx, [rsp+0x58]
    code += b'\x48\x8D\x54\x24\x40'                            # lea rdx, [rsp+0x40]
    code += b'\x48\xA1' + struct.pack('<Q', iocreatesymlink_iat)
    code += b'\xFF\xD0'                                          # call rax

    # Return STATUS_SUCCESS
    code += b'\x31\xC0'           # xor eax, eax

    # Epilogue (success): undo sub rsp, then pop in reverse push order
    code += b'\x48\x83\xC4\x70'  # add rsp, 0x70
    code += b'\x41\x5D'           # pop r13
    code += b'\x41\x5C'           # pop r12
    code += b'\x5B'               # pop rbx
    code += b'\xC3'               # ret

    # .fail: error code already in eax from IoCreateDevice
    fail_pos = len(code)
    code += b'\x48\x83\xC4\x70'  # add rsp, 0x70
    code += b'\x41\x5D'           # pop r13
    code += b'\x41\x5C'           # pop r12
    code += b'\x5B'               # pop rbx
    code += b'\xC3'               # ret

    # Backpatch jnz .fail offset
    jnz_disp = fail_pos - (jnz_pos + 2)  # +2 for size of jnz instruction
    assert 0 < jnz_disp < 128, f"jnz displacement {jnz_disp} out of rel8 range"
    code[jnz_pos + 1] = jnz_disp

    return bytes(code), driver_entry_offset


def build_pe():
    """Build the complete PE file."""
    # Build .rdata (imports)
    rdata, iat_rva = build_import_directory(RDATA_RVA)

    # Build .data (strings)
    data, strings = build_data()

    # Build .text (code)
    code_bytes, entry_offset = build_code(iat_rva, DATA_RVA, strings)
    text = bytearray(align(len(code_bytes), FILE_ALIGNMENT))
    text[0:len(code_bytes)] = code_bytes

    # Entry point RVA
    entry_rva = TEXT_RVA + entry_offset

    # --- DOS Header ---
    dos_header = bytearray(0x100)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 0x80)

    # PE Signature
    dos_header[0x80:0x84] = b'PE\x00\x00'

    # --- COFF Header ---
    coff = struct.pack("<HH III HH",
        0x8664,    # Machine (AMD64)
        3,         # NumberOfSections
        0,         # TimeDateStamp
        0,         # PointerToSymbolTable
        0,         # NumberOfSymbols
        0xF0,      # SizeOfOptionalHeader
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_SYSTEM,
    )
    dos_header[0x84:0x84+len(coff)] = coff

    # --- Optional Header PE32+ ---
    opt = bytearray(0xF0)

    struct.pack_into('<H', opt, 0, 0x020B)  # Magic (PE32+)
    opt[2] = 1; opt[3] = 0  # Linker version
    struct.pack_into('<I', opt, 4, len(text))  # SizeOfCode
    struct.pack_into('<I', opt, 8, 0x400)  # SizeOfInitializedData
    struct.pack_into('<I', opt, 12, 0)  # SizeOfUninitializedData
    struct.pack_into('<I', opt, 16, entry_rva)  # AddressOfEntryPoint
    struct.pack_into('<I', opt, 20, TEXT_RVA)  # BaseOfCode

    struct.pack_into('<Q', opt, 24, IMAGE_BASE)  # ImageBase
    struct.pack_into('<I', opt, 32, SECTION_ALIGNMENT)
    struct.pack_into('<I', opt, 36, FILE_ALIGNMENT)
    struct.pack_into('<HH', opt, 40, 6, 0)  # OS Version
    struct.pack_into('<HH', opt, 44, 0, 0)  # Image Version
    struct.pack_into('<HH', opt, 48, 6, 0)  # Subsystem Version
    struct.pack_into('<I', opt, 52, 0)  # Win32VersionValue
    struct.pack_into('<I', opt, 56, 0x4000)  # SizeOfImage
    struct.pack_into('<I', opt, 60, 0x400)  # SizeOfHeaders
    struct.pack_into('<I', opt, 64, 0)  # CheckSum
    struct.pack_into('<H', opt, 68, IMAGE_SUBSYSTEM_NATIVE)  # Subsystem = NATIVE
    struct.pack_into('<H', opt, 70, 0)  # DllCharacteristics
    struct.pack_into('<Q', opt, 72, 0x40000)  # SizeOfStackReserve (smaller for driver)
    struct.pack_into('<Q', opt, 80, 0x1000)  # SizeOfStackCommit
    struct.pack_into('<Q', opt, 88, 0x40000)  # SizeOfHeapReserve
    struct.pack_into('<Q', opt, 96, 0x1000)  # SizeOfHeapCommit
    struct.pack_into('<I', opt, 104, 0)  # LoaderFlags
    struct.pack_into('<I', opt, 108, 16)  # NumberOfRvaAndSizes

    # Data directories - Index 1: Import Directory
    struct.pack_into('<II', opt, 112 + 1*8, RDATA_RVA, 0x28)

    dos_header[0x98:0x98+len(opt)] = opt

    # --- Section Headers ---
    section_start = 0x188

    def section_header(name, vsize, vrva, rawsize, rawptr, flags):
        hdr = bytearray(40)
        hdr[0:len(name)] = name[:8]
        struct.pack_into('<I', hdr, 8, vsize)
        struct.pack_into('<I', hdr, 12, vrva)
        struct.pack_into('<I', hdr, 16, rawsize)
        struct.pack_into('<I', hdr, 20, rawptr)
        struct.pack_into('<I', hdr, 36, flags)
        return bytes(hdr)

    text_raw_size = len(text)
    rdata_raw_size = len(rdata)
    data_raw_size = len(data)

    # File offsets
    text_foff = 0x400
    rdata_foff = text_foff + text_raw_size
    data_foff = rdata_foff + rdata_raw_size

    sh_text = section_header(b'.text\x00\x00\x00',
                             len(code_bytes), TEXT_RVA, text_raw_size, text_foff,
                             0x60000020)  # CODE|EXECUTE|READ
    sh_rdata = section_header(b'.rdata\x00\x00',
                              len(rdata), RDATA_RVA, rdata_raw_size, rdata_foff,
                              0x40000040)  # INITIALIZED_DATA|READ
    sh_data = section_header(b'.data\x00\x00\x00',
                             0x200, DATA_RVA, data_raw_size, data_foff,
                             0xC0000040)  # INITIALIZED_DATA|READ|WRITE

    dos_header[section_start:section_start+40] = sh_text
    dos_header[section_start+40:section_start+80] = sh_rdata
    dos_header[section_start+80:section_start+120] = sh_data

    # --- Assemble final PE ---
    total_size = data_foff + data_raw_size
    pe = bytearray(total_size)

    pe[0:len(dos_header)] = dos_header
    pe[text_foff:text_foff+text_raw_size] = text
    pe[rdata_foff:rdata_foff+rdata_raw_size] = rdata
    pe[data_foff:data_foff+data_raw_size] = data

    return bytes(pe), entry_rva


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "test_driver.sys"
    pe, entry_rva = build_pe()

    with open(output, 'wb') as f:
        f.write(pe)

    print(f"Generated {output} ({len(pe)} bytes)")
    print(f"  Entry point RVA: 0x{entry_rva:04X}")
    print(f"  Image base: 0x{IMAGE_BASE:08X}")
    print(f"  Subsystem: NATIVE (kernel driver)")
    print(f"  Imports: ntoskrnl.exe (DbgPrint, RtlInitUnicodeString, IoCreateDevice,")
    print(f"           IoCreateSymbolicLink, IoCompleteRequest, IofCompleteRequest)")
    print(f"  Creates: \\Device\\TestDrv, \\DosDevices\\TestDrv")


if __name__ == "__main__":
    main()
