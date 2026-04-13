#!/usr/bin/env node
/**
 * gen_hello_pe.js - Generate a minimal 64-bit PE executable (Node.js port)
 *
 * Creates hello.exe: a tiny Windows console application that writes
 * "Hello from PE!\n" to stdout using kernel32!WriteFile and then exits
 * via kernel32!ExitProcess.
 */

const fs = require('fs');
const path = require('path');

// PE constants
const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
const IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;

const IMAGE_BASE = 0x00400000;
const SECTION_ALIGNMENT = 0x1000;
const FILE_ALIGNMENT = 0x200;

// Virtual addresses
const TEXT_RVA  = 0x1000;
const RDATA_RVA = 0x2000;
const DATA_RVA  = 0x3000;

const MSG = Buffer.from("Hello from PE!\n", "ascii");
const MSG_OFFSET_IN_DATA = 0;

// Helper: write a little-endian unsigned 16-bit value
function writeU16(buf, offset, val) {
    buf[offset]     = val & 0xFF;
    buf[offset + 1] = (val >>> 8) & 0xFF;
}

// Helper: write a little-endian unsigned 32-bit value
function writeU32(buf, offset, val) {
    buf[offset]     = val & 0xFF;
    buf[offset + 1] = (val >>> 8) & 0xFF;
    buf[offset + 2] = (val >>> 16) & 0xFF;
    buf[offset + 3] = (val >>> 24) & 0xFF;
}

// Helper: write a little-endian unsigned 64-bit value (as two 32-bit writes)
function writeU64(buf, offset, val) {
    // val is a JS number; for values <= 2^53 this is fine
    const lo = val & 0xFFFFFFFF;
    const hi = Math.floor(val / 0x100000000) & 0xFFFFFFFF;
    writeU32(buf, offset, lo);
    writeU32(buf, offset + 4, hi);
}

// Helper: copy bytes from src into dst at offset
function copyInto(dst, offset, src) {
    for (let i = 0; i < src.length; i++) {
        dst[offset + i] = src[i];
    }
}

function buildHintName(hint, name) {
    // 2-byte hint + ASCII name + null terminator, padded to even length
    const nameBuf = Buffer.from(name, "ascii");
    let data = Buffer.alloc(2 + nameBuf.length + 1);
    writeU16(data, 0, hint);
    nameBuf.copy(data, 2);
    data[2 + nameBuf.length] = 0;
    if (data.length % 2 !== 0) {
        data = Buffer.concat([data, Buffer.alloc(1)]);
    }
    return data;
}

function buildImportDirectory(rdataBase) {
    // Layout within .rdata:
    // 0x000: Import Directory Entry for kernel32 (20 bytes)
    // 0x014: Null terminator entry (20 bytes)
    // 0x028: ILT (3 entries + null = 32 bytes)
    // 0x048: IAT (3 entries + null = 32 bytes)
    // 0x068: Hint/Name: GetStdHandle
    // 0x080: Hint/Name: WriteFile
    // 0x094: Hint/Name: ExitProcess
    // 0x0A8: DLL name "kernel32.dll"

    const iltRva = rdataBase + 0x28;
    const iatRva = rdataBase + 0x48;
    const hintGetStdHandleRva = rdataBase + 0x68;
    const hintWriteFileRva    = rdataBase + 0x80;
    const hintExitProcessRva  = rdataBase + 0x94;
    const dllnameRva          = rdataBase + 0xA8;

    const rdata = Buffer.alloc(0x200);

    // Import Directory Entry (20 bytes): ILT, TimeDateStamp, ForwarderChain, Name, IAT
    writeU32(rdata, 0x00, iltRva);
    writeU32(rdata, 0x04, 0);
    writeU32(rdata, 0x08, 0);
    writeU32(rdata, 0x0C, dllnameRva);
    writeU32(rdata, 0x10, iatRva);
    // 0x14..0x27: null terminator entry (already zeroed)

    // ILT entries (8 bytes each, PE32+)
    writeU64(rdata, 0x28, hintGetStdHandleRva);
    writeU64(rdata, 0x30, hintWriteFileRva);
    writeU64(rdata, 0x38, hintExitProcessRva);
    writeU64(rdata, 0x40, 0); // null terminator

    // IAT entries (same as ILT initially)
    writeU64(rdata, 0x48, hintGetStdHandleRva);
    writeU64(rdata, 0x50, hintWriteFileRva);
    writeU64(rdata, 0x58, hintExitProcessRva);
    writeU64(rdata, 0x60, 0); // null terminator

    // Hint/Name entries
    const hnGetStdHandle = buildHintName(0, "GetStdHandle");
    const hnWriteFile    = buildHintName(0, "WriteFile");
    const hnExitProcess  = buildHintName(0, "ExitProcess");

    copyInto(rdata, 0x68, hnGetStdHandle);
    copyInto(rdata, 0x80, hnWriteFile);
    copyInto(rdata, 0x94, hnExitProcess);

    // DLL name
    const dllname = Buffer.from("kernel32.dll\0", "ascii");
    copyInto(rdata, 0xA8, dllname);

    return { rdata, iatRva };
}

function buildCode(iatRva, msgRva, msgLen) {
    // IAT layout: [0]=GetStdHandle, [8]=WriteFile, [16]=ExitProcess
    const getstdhandleIat = iatRva;
    const writefileIat    = iatRva + 8;
    const exitprocessIat  = iatRva + 16;

    const parts = [];

    function pushBytes(/*...bytes*/) {
        parts.push(Buffer.from(Array.prototype.slice.call(arguments)));
    }

    function pushU32LE(val) {
        const b = Buffer.alloc(4);
        writeU32(b, 0, val);
        parts.push(b);
    }

    function pushU64LE(val) {
        const b = Buffer.alloc(8);
        writeU64(b, 0, val);
        parts.push(b);
    }

    // sub rsp, 0x48
    pushBytes(0x48, 0x83, 0xEC, 0x48);

    // --- GetStdHandle(-11) ---
    // mov ecx, 0xFFFFFFF5
    pushBytes(0xB9, 0xF5, 0xFF, 0xFF, 0xFF);
    // mov rax, [getstdhandle_iat]  (48 A1 + imm64)
    pushBytes(0x48, 0xA1);
    pushU64LE(getstdhandleIat);
    // call rax
    pushBytes(0xFF, 0xD0);
    // mov rbx, rax
    pushBytes(0x48, 0x89, 0xC3);

    // --- WriteFile(handle, msg, len, &written, NULL) ---
    // mov rcx, rbx
    pushBytes(0x48, 0x89, 0xD9);
    // mov rdx, imm64 (msg_rva)
    pushBytes(0x48, 0xBA);
    pushU64LE(msgRva);
    // mov r8d, msg_len
    pushBytes(0x41, 0xB8);
    pushU32LE(msgLen);
    // lea r9, [rsp+0x30]
    pushBytes(0x4C, 0x8D, 0x4C, 0x24, 0x30);
    // mov qword [rsp+0x20], 0
    pushBytes(0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00);
    // mov rax, [writefile_iat]
    pushBytes(0x48, 0xA1);
    pushU64LE(writefileIat);
    // call rax
    pushBytes(0xFF, 0xD0);

    // --- ExitProcess(0) ---
    // xor ecx, ecx
    pushBytes(0x31, 0xC9);
    // mov rax, [exitprocess_iat]
    pushBytes(0x48, 0xA1);
    pushU64LE(exitprocessIat);
    // call rax
    pushBytes(0xFF, 0xD0);

    // (unreachable)
    // add rsp, 0x48
    pushBytes(0x48, 0x83, 0xC4, 0x48);
    // ret
    pushBytes(0xC3);

    return Buffer.concat(parts);
}

function buildSectionHeader(name, vsize, vrva, rawsize, rawptr, flags) {
    const hdr = Buffer.alloc(40);
    const nameBuf = Buffer.from(name, "ascii");
    nameBuf.copy(hdr, 0, 0, Math.min(nameBuf.length, 8));
    writeU32(hdr, 8,  vsize);
    writeU32(hdr, 12, vrva);
    writeU32(hdr, 16, rawsize);
    writeU32(hdr, 20, rawptr);
    writeU32(hdr, 36, flags);
    return hdr;
}

function buildPE() {
    // Build .rdata (imports)
    const { rdata, iatRva } = buildImportDirectory(RDATA_RVA);

    // Build .data (message)
    const data = Buffer.alloc(0x200);
    MSG.copy(data, MSG_OFFSET_IN_DATA);

    const msgRva = IMAGE_BASE + DATA_RVA + MSG_OFFSET_IN_DATA;

    // Build .text (code)
    const code = buildCode(IMAGE_BASE + iatRva, msgRva, MSG.length);
    const text = Buffer.alloc(0x200);
    code.copy(text, 0);

    const entryRva = TEXT_RVA;

    // --- DOS Header + COFF + Optional + Section Headers ---
    // The full header area spans from 0x000 to 0x200 (section headers end at 0x200)
    const dosHeader = Buffer.alloc(0x400);
    dosHeader[0] = 0x4D; // 'M'
    dosHeader[1] = 0x5A; // 'Z'
    writeU32(dosHeader, 0x3C, 0x80); // e_lfanew

    // PE Signature at 0x80
    dosHeader[0x80] = 0x50; // 'P'
    dosHeader[0x81] = 0x45; // 'E'
    dosHeader[0x82] = 0x00;
    dosHeader[0x83] = 0x00;

    // --- COFF Header (20 bytes at 0x84) ---
    writeU16(dosHeader, 0x84, 0x8664);  // Machine: AMD64
    writeU16(dosHeader, 0x86, 3);       // NumberOfSections
    writeU32(dosHeader, 0x88, 0);       // TimeDateStamp
    writeU32(dosHeader, 0x8C, 0);       // PointerToSymbolTable
    writeU32(dosHeader, 0x90, 0);       // NumberOfSymbols
    writeU16(dosHeader, 0x94, 0xF0);    // SizeOfOptionalHeader
    writeU16(dosHeader, 0x96, IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE);

    // --- Optional Header PE32+ (starts at 0x98, 0xF0 bytes) ---
    const optOff = 0x98;

    writeU16(dosHeader, optOff + 0, 0x020B);  // Magic: PE32+
    dosHeader[optOff + 2] = 1;                 // MajorLinkerVersion
    dosHeader[optOff + 3] = 0;                 // MinorLinkerVersion
    writeU32(dosHeader, optOff + 4, 0x200);    // SizeOfCode
    writeU32(dosHeader, optOff + 8, 0x400);    // SizeOfInitializedData
    writeU32(dosHeader, optOff + 12, 0);       // SizeOfUninitializedData
    writeU32(dosHeader, optOff + 16, entryRva);// AddressOfEntryPoint
    writeU32(dosHeader, optOff + 20, TEXT_RVA); // BaseOfCode

    // PE32+ specific (64-bit)
    writeU64(dosHeader, optOff + 24, IMAGE_BASE);       // ImageBase
    writeU32(dosHeader, optOff + 32, SECTION_ALIGNMENT); // SectionAlignment
    writeU32(dosHeader, optOff + 36, FILE_ALIGNMENT);    // FileAlignment
    writeU16(dosHeader, optOff + 40, 6);                 // MajorOperatingSystemVersion
    writeU16(dosHeader, optOff + 42, 0);                 // MinorOperatingSystemVersion
    writeU16(dosHeader, optOff + 44, 0);                 // MajorImageVersion
    writeU16(dosHeader, optOff + 46, 0);                 // MinorImageVersion
    writeU16(dosHeader, optOff + 48, 6);                 // MajorSubsystemVersion
    writeU16(dosHeader, optOff + 50, 0);                 // MinorSubsystemVersion
    writeU32(dosHeader, optOff + 52, 0);                 // Win32VersionValue
    writeU32(dosHeader, optOff + 56, 0x4000);            // SizeOfImage
    writeU32(dosHeader, optOff + 60, 0x400);             // SizeOfHeaders
    writeU32(dosHeader, optOff + 64, 0);                 // CheckSum
    writeU16(dosHeader, optOff + 68, IMAGE_SUBSYSTEM_WINDOWS_CUI); // Subsystem
    writeU16(dosHeader, optOff + 70, 0);                 // DllCharacteristics
    writeU64(dosHeader, optOff + 72, 0x100000);          // SizeOfStackReserve
    writeU64(dosHeader, optOff + 80, 0x1000);            // SizeOfStackCommit
    writeU64(dosHeader, optOff + 88, 0x100000);          // SizeOfHeapReserve
    writeU64(dosHeader, optOff + 96, 0x1000);            // SizeOfHeapCommit
    writeU32(dosHeader, optOff + 104, 0);                // LoaderFlags
    writeU32(dosHeader, optOff + 108, 16);               // NumberOfRvaAndSizes

    // Data directories (8 bytes each, starting at offset 112 within opt header)
    // Index 1: Import Directory
    writeU32(dosHeader, optOff + 112 + 1 * 8, RDATA_RVA); // Import Dir RVA
    writeU32(dosHeader, optOff + 112 + 1 * 8 + 4, 0x28);  // Import Dir Size

    // --- Section Headers (start at 0x188, 40 bytes each) ---
    const sectionStart = 0x188;

    // .text: CODE | EXECUTE | READ = 0x60000020
    const shText = buildSectionHeader(".text\0\0\0", 0x200, TEXT_RVA, 0x200, 0x400, 0x60000020);
    // .rdata: INITIALIZED_DATA | READ = 0x40000040
    const shRdata = buildSectionHeader(".rdata\0\0", 0x200, RDATA_RVA, 0x200, 0x600, 0x40000040);
    // .data: INITIALIZED_DATA | READ | WRITE = 0xC0000040
    const shData = buildSectionHeader(".data\0\0\0", 0x200, DATA_RVA, 0x200, 0x800, 0xC0000040);

    shText.copy(dosHeader, sectionStart);
    shRdata.copy(dosHeader, sectionStart + 40);
    shData.copy(dosHeader, sectionStart + 80);

    // --- Assemble final PE ---
    // Total: headers(0x400) + .text(0x200) + .rdata(0x200) + .data(0x200) = 0xA00
    const pe = Buffer.alloc(0xA00);

    // Headers (dosHeader is 0x100 bytes, but we wrote into it up to ~0x1F8)
    dosHeader.copy(pe, 0);

    // .text at file offset 0x400
    text.copy(pe, 0x400);

    // .rdata at file offset 0x600
    rdata.copy(pe, 0x600);

    // .data at file offset 0x800
    data.copy(pe, 0x800);

    return pe;
}

// Main
const outputArg = process.argv[2] || path.join(__dirname, "hello.exe");
const pe = buildPE();

fs.writeFileSync(outputArg, pe);

console.log(`Generated ${outputArg} (${pe.length} bytes)`);
console.log(`  Entry point RVA: 0x${TEXT_RVA.toString(16).padStart(4, '0').toUpperCase()}`);
console.log(`  Image base: 0x${IMAGE_BASE.toString(16).padStart(8, '0').toUpperCase()}`);
console.log(`  Imports: kernel32.dll (GetStdHandle, WriteFile, ExitProcess)`);
console.log(`  Message: 'Hello from PE!'`);
