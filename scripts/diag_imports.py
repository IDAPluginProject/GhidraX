"""Parse PE .idata section to find import names."""
import struct

with open('bin/cp.exe', 'rb') as f:
    raw = f.read()

pe_off = struct.unpack_from('<I', raw, 0x3c)[0]
coff_off = pe_off + 4
nsec = struct.unpack_from('<H', raw, coff_off + 2)[0]
ohsz = struct.unpack_from('<H', raw, coff_off + 16)[0]
opt_off = coff_off + 20
ibase = struct.unpack_from('<I', raw, opt_off + 28)[0]

# Find .idata section
sec_off = opt_off + ohsz
idata_rva = idata_raw = idata_sz = 0
for i in range(nsec):
    s = sec_off + i * 40
    name = raw[s:s+8].rstrip(b'\x00')
    if name == b'.idata':
        idata_rva = struct.unpack_from('<I', raw, s + 12)[0]
        idata_sz = struct.unpack_from('<I', raw, s + 8)[0]
        idata_raw = struct.unpack_from('<I', raw, s + 20)[0]
        break

def rva_to_file(rva):
    """Convert RVA to file offset using .idata section mapping."""
    if idata_rva <= rva < idata_rva + idata_sz:
        return idata_raw + (rva - idata_rva)
    return None

# Parse Import Directory Table (at start of .idata)
# Each entry: 20 bytes (ILT_RVA, timestamp, forwarder, name_RVA, IAT_RVA)
imp_off = idata_raw
print(f"ImageBase=0x{ibase:x}, .idata RVA=0x{idata_rva:x}, raw=0x{idata_raw:x}")

# Known non-returning functions
NORETURN_NAMES = {
    'exit', '_exit', 'abort', '_abort', '_Exit',
    'ExitProcess', 'TerminateProcess', 'FatalExit',
    '__assert_fail', '__stack_chk_fail',
    '_assert', '__cxa_throw', 'longjmp', '_longjmp',
}

noreturn_iat_addrs = set()

while True:
    ilt_rva = struct.unpack_from('<I', raw, imp_off)[0]
    name_rva = struct.unpack_from('<I', raw, imp_off + 12)[0]
    iat_rva = struct.unpack_from('<I', raw, imp_off + 16)[0]
    if ilt_rva == 0 and name_rva == 0:
        break

    # DLL name
    name_fo = rva_to_file(name_rva)
    dll_name = ""
    if name_fo:
        end = raw.index(b'\x00', name_fo)
        dll_name = raw[name_fo:end].decode('ascii', errors='replace')

    # Parse ILT/IAT entries
    ilt_fo = rva_to_file(ilt_rva)
    iat_va = ibase + iat_rva
    idx = 0
    if ilt_fo:
        while True:
            entry = struct.unpack_from('<I', raw, ilt_fo + idx * 4)[0]
            if entry == 0:
                break
            if entry & 0x80000000:
                func_name = f"ordinal_{entry & 0xFFFF}"
            else:
                hint_fo = rva_to_file(entry)
                if hint_fo:
                    func_name = raw[hint_fo+2:raw.index(b'\x00', hint_fo+2)].decode('ascii', errors='replace')
                else:
                    func_name = f"unknown_{entry:x}"

            entry_iat_va = iat_va + idx * 4
            is_noreturn = func_name in NORETURN_NAMES
            if is_noreturn:
                noreturn_iat_addrs.add(entry_iat_va)
                print(f"  ** NORETURN: {dll_name}!{func_name} IAT=0x{entry_iat_va:x}")

            # Check if this is one of our target IAT addresses
            if entry_iat_va in (0x421514, 0x4214c4):
                print(f"  >>> TARGET: {dll_name}!{func_name} IAT=0x{entry_iat_va:x} noreturn={is_noreturn}")

            idx += 1

    imp_off += 20

print(f"\nAll noreturn IAT addresses: {[f'0x{a:x}' for a in sorted(noreturn_iat_addrs)]}")

# Find thunks that JMP to noreturn IAT entries
# Thunks are typically: FF 25 <IAT_addr32> (JMP [addr32])
print("\nSearching for thunks to noreturn functions...")
# Scan .text section for JMP [addr] pattern
for i in range(nsec):
    s = sec_off + i * 40
    name = raw[s:s+8].rstrip(b'\x00')
    if name == b'.text':
        text_rva = struct.unpack_from('<I', raw, s + 12)[0]
        text_sz = struct.unpack_from('<I', raw, s + 8)[0]
        text_raw = struct.unpack_from('<I', raw, s + 20)[0]
        text_data = raw[text_raw:text_raw + text_sz]
        for j in range(len(text_data) - 6):
            if text_data[j] == 0xFF and text_data[j+1] == 0x25:
                target = struct.unpack_from('<I', text_data, j + 2)[0]
                if target in noreturn_iat_addrs:
                    thunk_va = ibase + text_rva + j
                    print(f"  Thunk at 0x{thunk_va:x}: JMP [0x{target:x}]")
