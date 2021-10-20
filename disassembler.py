from sys import argv

inpf = argv[1]
outf = ""
if len(argv) == 3:
    outf = argv[2]

with open(inpf, "rb") as f:
    b = f.read()
pos = 0


class ELFHeader:
    entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx = [0] * 8


class SectionHeader:
    name, stype, flags, addr, offset, size, link, info, addralign, entsize = [0] * 10
    str_name = ""


class SymtabEntry:
    name, value, stype = [0]*3
    str_name = ""


def next_bytes(n):
    global pos
    bts = b[pos:pos + n]
    pos += n
    return bts


def next_bytes_as_int(n):
    global pos
    bts = b[pos:pos + n]
    pos += n
    return int.from_bytes(bts, "little")


def skip_bytes(n):
    global pos
    pos += n


def offset_from_start(offset):
    global pos
    pos = offset


def check_file():
    ei_mag = next_bytes(4)
    assert ei_mag == b'\x7fELF', "Not elf"

    ei_class = next_bytes_as_int(1)
    assert ei_class == 1, "Not 32-bit"

    ei_data = next_bytes_as_int(1)
    assert ei_data == 1, "Not little-endian => not RISC-V"

    skip_bytes(12)  # skip version, ABI, pad, type

    ei_machine = next_bytes_as_int(2)
    assert ei_machine == 0xf3, "Not RISC-V"

    skip_bytes(4)  # skip version


def parse_elf_header():
    eh = ELFHeader()
    eh.entry = next_bytes_as_int(4)
    eh.phoff = next_bytes_as_int(4)
    eh.shoff = next_bytes_as_int(4)

    skip_bytes(6)  # skip flags, ehsize

    eh.phentsize = next_bytes_as_int(2)
    eh.phnum = next_bytes_as_int(2)
    eh.shentsize = next_bytes_as_int(2)
    eh.shnum = next_bytes_as_int(2)
    eh.shstrndx = next_bytes_as_int(2)
    return eh


def get_str_name(name, strtb):
    global pos
    offset_from_start(strtb.offset + name)
    str_name = ""
    while b[pos] != 0:
        str_name += chr(b[pos])
        pos += 1
    return str_name


def parse_section_header():
    sec = SectionHeader()
    sec.name = next_bytes_as_int(4)
    sec.stype = next_bytes_as_int(4)
    sec.flags = next_bytes_as_int(4)
    sec.addr = next_bytes_as_int(4)
    sec.offset = next_bytes_as_int(4)
    sec.size = next_bytes_as_int(4)
    sec.link = next_bytes_as_int(4)
    sec.info = next_bytes_as_int(4)
    sec.addralign = next_bytes_as_int(4)
    sec.entsize = next_bytes_as_int(4)
    return sec


def parse_section_header_table():
    headers = []
    offset_from_start(eh.shoff)
    for _ in range(eh.shnum):
        headers.append(parse_section_header())
    return headers


def get_str_names(lst, strtab):
    for s in lst:
        s.str_name = get_str_name(s.name, strtab)


def find_header(name):
    for s in section_headers:
        if s.str_name == name:
            return s

    return False


def get_text_section_content():
    offset_from_start(text_header.offset)
    return next_bytes(text_header.size)


def parse_entry():
    e = SymtabEntry()
    e.name = next_bytes_as_int(4)
    e.value = next_bytes_as_int(4)
    skip_bytes(4)
    e.stype = next_bytes_as_int(1) & 0xf
    skip_bytes(3)
    return e


def parse_symtab():
    labels = []
    offset_from_start(symtab.offset)
    skip_bytes(16)
    for i in range(1, symtab.size // 16):
        e = parse_entry()
        if e.stype != 4:
            labels.append(e)

    return labels


def addr_name():
    d = {}
    for l in labels:
        if l.str_name:
            d[l.value] = f"<{l.str_name}>"
        else:
            d[l.value] = f"<LOC_{hex8(l.value)}>"
    return d


def to_signed(s):
    if s[0] == "1":
        return int(s, 2) - (1 << len(s))
    return int(s, 2)


def hex8(n):
    return hex(n)[2:].zfill(8)


def parse_command(cmd):
    cmd = bin(int.from_bytes(cmd, "little"))[2:].zfill(32)[::-1]
    _6_0 = cmd[0:7][::-1]
    _11_7 = cmd[7:12][::-1]
    _14_12 = cmd[12:15][::-1]
    _19_15 = cmd[15:20][::-1]
    _24_20 = cmd[20:25][::-1]
    _31_25 = cmd[25:32][::-1]
    _31_12 = cmd[12:32][::-1]
    _30_21 = cmd[21:31][::-1]
    _19_12 = cmd[12:20][::-1]
    _27_24 = cmd[24:28][::-1]
    if _6_0 in utype:
        opcode = utype[_6_0]
        rd = regname[int(_11_7, 2)]
        imm = to_signed(_31_12 + "0"*20)
        res = [opcode, rd, imm]
    elif _6_0 in jtype:
        opcode = jtype[_6_0]
        rd = regname[int(_11_7, 2)]
        imm = to_signed(cmd[31]*12 + _19_12 + cmd[20] + _30_21 + "0")
        res = [opcode, rd, imm]
    elif _14_12 + _6_0 in itype:
        opcode = itype[_14_12 + _6_0]
        rd = regname[int(_11_7, 2)]
        rs1 = regname[int(_19_15, 2)]
        imm = to_signed(cmd[31]*20 + _31_25 + _24_20)
        res = [opcode, rd, rs1, imm]
    elif cmd[::-1] in full_len:
        opcode = full_len[cmd[::-1]]
        res = [opcode, ""]
    elif _6_0 == "0001111":
        opcode = "fence"
        pred = _27_24
        succ = _24_20[1:]
        res = [opcode, pred, succ]
    elif _14_12 + _6_0 in stype:
        opcode = stype[_14_12 + _6_0]
        rs1 = regname[int(_19_15, 2)]
        rs2 = regname[int(_24_20, 2)]
        imm = to_signed(cmd[31]*20 + _31_25 + _11_7)
        res = [opcode, rs1, rs2, imm]
    elif _14_12 + _6_0 in btype:
        opcode = btype[_14_12 + _6_0]
        rs1 = regname[int(_19_15, 2)]
        rs2 = regname[int(_24_20, 2)]
        imm = to_signed(cmd[31]*20 + cmd[7] + _31_25 + _11_7[:-1] + "0")
        res = [opcode, rs1, rs2, imm]
    elif _31_25 + _14_12 + _6_0 in rtype:
        opcode = rtype[_31_25 + _14_12 + _6_0]
        rd = regname[int(_11_7, 2)]
        rs1 = regname[int(_19_15, 2)]
        rs2 = regname[int(_24_20, 2)]
        res = [opcode, rd, rs1, rs2]
    else:
        res = ["Unknown command", ""]

    return res


def disassemble():
    res = []
    for i in range(0, text_header.size, 4):
        command = text[i:i + 4]
        res.append(parse_command(command))
    return res


utype = {"0110111": "lui",
         "0010111": "auipc"}
jtype = {"1101111": "jal"}
itype = {"000" + "1100111": "jalr",
         "000" + "0000011": "lb",
         "001" + "0000011": "lh",
         "010" + "0000011": "lw",
         "100" + "0000011": "lbu",
         "101" + "0000011": "lhu",
         "000" + "0010011": "addi",
         "010" + "0010011": "slti",
         "011" + "0010011": "sltiu",
         "100" + "0010011": "xori",
         "110" + "0010011": "ori",
         "111" + "0010011": "andi",
         "001" + "1110011": "csrrw",
         "010" + "1110011": "csrrs",
         "011" + "1110011": "csrrc",
         "101" + "1110011": "csrrwi",
         "110" + "1110011": "csrrsi",
         "111" + "1110011": "csrrci",}
full_len = {"0" * 25 + "1110011": "ecall",
            "0"*24 + "1" + "1110011": "ebreak",
            "00000000000000000001000000001111": "fence.i"}
stype = {"000" + "0100011": "sb",
         "001" + "0100011": "sh",
         "010" + "0100011": "sw"}
btype = {"000" + "1100011": "beq",
         "001" + "1100011": "bne",
         "100" + "1100011": "blt",
         "101" + "1100011": "bge",
         "110" + "1100011": "bltu",
         "111" + "1100011": "bgeu"}
rtype = {"0000000" + "001" + "0010011": "slli",
         "0000000" + "101" + "0010011": "srli",
         "0100000" + "101" + "0010011": "srai",
         "0000000" + "000" + "0110011": "add",
         "0100000" + "000" + "0110011": "sub",
         "0000000" + "001" + "0110011": "sll",
         "0000000" + "010" + "0110011": "slt",
         "0000000" + "011" + "0110011": "sltu",
         "0000000" + "100" + "0110011": "xor",
         "0000000" + "101" + "0110011": "srl",
         "0100000" + "101" + "0110011": "sra",
         "0000000" + "110" + "0110011": "or",
         "0000000" + "111" + "0110011": "and",
         "0000001" + "000" + "0110011": "mul",
         "0000001" + "001" + "0110011": "mulh",
         "0000001" + "010" + "0110011": "mulhsu",
         "0000001" + "011" + "0110011": "mulhu",
         "0000001" + "100" + "0110011": "div",
         "0000001" + "101" + "0110011": "divu",
         "0000001" + "110" + "0110011": "rem",
         "0000001" + "111" + "0110011": "remu"}
regname = ["zero", "ra", "sp", "gp", "tp"] +  ["t0", "t1", "t2", "s0", "s1"] + [f"a{i}" for i in range(8)] +\
          [f"s{i}" for i in range(2, 12)] + [f"t{i}" for i in range(3, 7)]

check_file()
eh = parse_elf_header()

assert eh.shnum != 0, "No sections"

section_headers = parse_section_header_table()
get_str_names(section_headers, section_headers[eh.shstrndx])

text_header = find_header(".text")
assert text_header, "No section .text"

strtab = find_header(".strtab")
symtab = find_header(".symtab")
labels = []
if symtab:
    labels = parse_symtab()
    if strtab:
        get_str_names(labels, strtab)
an = addr_name()

text = get_text_section_content()
res = disassemble()


if outf: f = open(outf, "w")
else: f = None
addr = text_header.addr
for c in res:
    if addr in an:
        print(hex8(addr), an[addr], sep=":\t", end="\t", file=f)
    else:
        print(hex8(addr), end=":\t", file=f)
    print(c[0], end="\t", file=f)
    for e in c[1:-1]:
        print(e, end=", ", file=f)
    print(c[-1], file=f)
    addr += 4

if outf:
    f.close()