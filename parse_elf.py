import struct
import sys
import re

hex_regex = '0x[0-9A-F]*'

EI_OSABI = {i:x for i,x in enumerate([j.replace(re.findall(hex_regex, j)[0], '').strip() for j in '''0x00 System V
0x01	HP-UX
0x02	NetBSD
0x03	Linux
0x04	GNU Hurd
0x06	Solaris
0x07	AIX (Monterey)
0x08	IRIX
0x09	FreeBSD
0x0A	Tru64
0x0B	Novell Modesto
0x0C	OpenBSD
0x0D	OpenVMS
0x0E	NonStop Kernel
0x0F	AROS
0x10	FenixOS
0x11	Nuxi CloudABI
0x12\tStratus Technologies OpenVOS'''.split('\n')])}

EI_TYPE = {i:x for i,x in enumerate([j.replace(re.findall(hex_regex, j)[0], '').strip() for j in '''0x00	ET_NONE	Unknown.
0x01	ET_REL
0x02	ET_EXEC
0x03	ET_DYN	
0x04	ET_CORE	
0xFE00  ET_LOOS	
0xFEFF  ET_HIOS
0xFF00  ET_LOPROC	
0xFFFF  ET_HIPROC'''.split('\n')])}

EI_MACHINE = {i:x for i,x in enumerate([j.replace(re.findall(hex_regex, j)[0], '').strip() for j in '''0x00	No specific instruction set
0x01	AT&T WE 32100
0x02	SPARC
0x03	x86
0x04	Motorola 68000 (M68k)
0x05	Motorola 88000 (M88k)
0x06	Intel MCU
0x07	Intel 80860
0x08	MIPS
0x09	IBM System/370
0x0A	MIPS RS3000 Little-endian
0x0B    Reserved for future use
0x0C    Reserved for future use
0x0D    Reserved for future use
0x0E	Hewlett-Packard PA-RISC
0x0F	Reserved for future use
0x13	Intel 80960
0x14	PowerPC
0x15	PowerPC (64-bit)
0x16	S390, including S390x
0x17	IBM SPU/SPC
0x18    Reserved for future use
0x19    Reserved for future use
0x1a    Reserved for future use
0x1b    Reserved for future use
0x1c    Reserved for future use
0x1d    Reserved for future use
0x1e    Reserved for future use
0x1f    Reserved for future use
0x20    Reserved for future use
0x21    Reserved for future use
0x22    Reserved for future use
0x23    Reserved for future use
0x24	NEC V800
0x25	Fujitsu FR20
0x26	TRW RH-32
0x27	Motorola RCE
0x28	Arm (up to Armv7/AArch32)
0x29	Digital Alpha
0x2A	SuperH
0x2B	SPARC Version 9
0x2C	Siemens TriCore embedded processor
0x2D	Argonaut RISC Core
0x2E	Hitachi H8/300
0x2F	Hitachi H8/300H
0x30	Hitachi H8S
0x31	Hitachi H8/500
0x32	IA-64
0x33	Stanford MIPS-X
0x34	Motorola ColdFire
0x35	Motorola M68HC12
0x36	Fujitsu MMA Multimedia Accelerator
0x37	Siemens PCP
0x38	Sony nCPU embedded RISC processor
0x39	Denso NDR1 microprocessor
0x3A	Motorola Star*Core processor
0x3B	Toyota ME16 processor
0x3C	STMicroelectronics ST100 processor
0x3D	Advanced Logic Corp. TinyJ embedded processor family
0x3E	AMD x86-64
0x3F	Sony DSP Processor
0x40	Digital Equipment Corp. PDP-10
0x41	Digital Equipment Corp. PDP-11
0x42	Siemens FX66 microcontroller
0x43	STMicroelectronics ST9+ 8/16 bit microcontroller
0x44	STMicroelectronics ST7 8-bit microcontroller
0x45	Motorola MC68HC16 Microcontroller
0x46	Motorola MC68HC11 Microcontroller
0x47	Motorola MC68HC08 Microcontroller
0x48	Motorola MC68HC05 Microcontroller
0x49	Silicon Graphics SVx
0x4A	STMicroelectronics ST19 8-bit microcontroller
0x4B	Digital VAX
0x4C	Axis Communications 32-bit embedded processor
0x4D	Infineon Technologies 32-bit embedded processor
0x4E	Element 14 64-bit DSP Processor
0x4F	LSI Logic 16-bit DSP Processor
0x8C	TMS320C6000 Family
0xAF	MCST Elbrus e2k
0xB7	Arm 64-bits (Armv8/AArch64)
0xDC	Zilog Z80
0xF3	RISC-V
0xF7	Berkeley Packet Filter
0x101   WDC 65C816'''.split('\n')])}

PGH_TYPE = {x[0]:x[1] for i,x in enumerate([(int(re.findall(hex_regex, j)[0], 16), j.replace(re.findall(hex_regex, j)[0], '').strip()) for j in f'''0x00000000	PT_NULL	Program header table entry unused.
0x00000001	PT_LOAD	Loadable segment.
0x00000002	PT_DYNAMIC	Dynamic linking information.
0x00000003	PT_INTERP	Interpreter information.
0x00000004	PT_NOTE	Auxiliary information.
0x00000005	PT_SHLIB	Reserved.
0x00000006	PT_PHDR	Segment containing program header table itself.
0x00000007	PT_TLS	Thread-Local Storage template.
0x60000000	PT_LOOS	Reserved inclusive range. Operating system specific.
0x6FFFFFFF	PT_HIOS
0x70000000	PT_LOPROC	Reserved inclusive range. Processor specific.
0x7FFFFFFF	PT_HIPROC
0x{0x60000000 + 0x474e550:X} PT_GNU_EH_FRAME
0x{0x60000000 + 0x474e551:X} PT_GNU_STACK
0x{0x60000000 + 0x474e552:X} PT_GNU_RELRO
0x{0x60000000 + 0x474e553:X} PT_GNU_PROPERTY'''.split('\n')])}

SH_TYPE = {x[0]:x[1] for i,x in enumerate([(int(re.findall('0x[0-9a-f]*', j)[0], 16), j.replace(re.findall('0x[0-9a-f]*', j)[0], '').strip()) for j in f'''SHT_NULL 0x0
SHT_PROGBITS 0x1
SHT_SYMTAB 0x2
SHT_STRTAB 0x3
SHT_RELA 0x4
SHT_HASH 0x5
SHT_DYNAMIC 0x6
SHT_NOTE 0x7
SHT_NOBITS 0x8
SHT_REL 0x9
SHT_SHLIB 0x10
SHT_DYNSYM 0x11
SHT_SUNW_move 0x6ffffffa
SHT_SUNW_COMDAT 0x6ffffffb
SHT_SUNW_syminfo 0x6ffffffc
SHT_SUNW_verdef 0x6ffffffd
SHT_SUNW_verneed 0x6ffffffe
SHT_SUNW_versym 0x6fffffff
SHT_LOPROC 0x70000000
SHT_HIPROC 0x7fffffff
SHT_LOUSER 0x80000000
SHT_HIUSER 0xffffffff'''.split('\n')])}

SH_FLAGS = {x[0]:x[1] for i,x in enumerate([(int(re.findall(hex_regex, j)[0], 16), j.replace(re.findall(hex_regex, j)[0], '').strip()) for j in f'''0x1	SHF_WRITE	Writable
0x2	SHF_ALLOC	Occupies memory during execution
0x4	SHF_EXECINSTR	Executable
0x10	SHF_MERGE	Might be merged
0x20	SHF_STRINGS	Contains null-terminated strings
0x40	SHF_INFO_LINK	'sh_info' contains SHT index
0x80	SHF_LINK_ORDER	Preserve order after combining
0x100	SHF_OS_NONCONFORMING	Non-standard OS specific handling required
0x200	SHF_GROUP	Section is member of a group
0x400	SHF_TLS	Section hold thread-local data
0x0FF00000	SHF_MASKOS	OS-specific
0xF0000000	SHF_MASKPROC	Processor-specific
0x4000000	SHF_ORDERED	Special ordering requirement (Solaris)
0x8000000	SHF_EXCLUDE	Section is excluded unless referenced or allocated (Solaris)'''.split('\n')])}

def RetShFlags(value : int):
    result = ''
    for i in list(SH_FLAGS.keys()):
        if value & i != 0:
            result += SH_FLAGS[i] + ' | '
    if len(result) == 0:
        return 'None'
    return result[:-3]

ELF_HEADER_SIZE = 0x40

ELF_HEADER_FORMAT = "<4s4BQHHIQQQIHHHHHH"
ELF_PROGRAM_HEADER_FORMAT = "<IIQQQQQQ"
ELF_SECTION_HEADER_FORMAT = "<IIQQQQIIQQ"

def parse_elf_header(py_flags, file_path):
    f = open(file_path, "rb")
    elf_header = f.read(ELF_HEADER_SIZE)

    (
        magic,
        ident_class,
        ident_data,
        ident_version,
        ident_osabi,
        ident_abiversion_and_pad,
        type_,
        machine,
        version,
        entry,
        ph_offset,
        sh_offset,
        flags,
        eh_size,
        ph_entry_size,
        ph_entry_count,
        sh_entry_size,
        sh_entry_count,
        sh_str_index,
    ) = struct.unpack(ELF_HEADER_FORMAT, elf_header)
    
    if ident_class == 1:
        print('this program only supports ELF64, sorry :(')
        f.close()
        sys.exit()

    if len(py_flags) == 0 or '-e' in py_flags:
        print("ELF Header:")
        print(f'  Magic:              {magic}')
        print(f"  Class:              {ident_class} (ELF64)")
        print(f"  Data:               {ident_data}")
        print(f"  Version:            {ident_version}")
        print(f"  OS/ABI:             {ident_osabi} ({EI_OSABI[ident_osabi] if ident_osabi in EI_OSABI.keys() else 'UNKNOWN'})")
        print(f"  ABI Version:        {ident_abiversion_and_pad & 0xff}")
        print(f"  Padding:            {ident_abiversion_and_pad >> 8}")
        print(f"  Type:               {type_} ({EI_TYPE[type_] if type_ in EI_TYPE.keys() else 'UNKNOWN'})")
        print(f"  Machine:            {machine} ({EI_MACHINE[machine] if machine in EI_MACHINE.keys() else 'UNKNOWN'})")
        print(f"  Version:            {version}")
        print(f"  Entry point:        0x{entry:X}")
        print(f'  ELF Header size:    {eh_size}')
        print(f"  Program headers:    offset: {ph_offset}, entry size: {ph_entry_size}, count: {ph_entry_count}")
        print(f"  Section headers:    offset: {sh_offset}, entry size: {sh_entry_size}, count: {sh_entry_count}")
        print(f"  String table index: {sh_str_index}")
    
    if len(py_flags) == 0 or '-p' in py_flags:
        program_headers = []
        f.seek(ph_offset)
        for _ in range(ph_entry_count):
            program_header = f.read(ph_entry_size)
            (
                type_,
                flags,
                offset,
                vaddr,
                paddr,
                filesz,
                memsz,
                align,
            ) = struct.unpack(ELF_PROGRAM_HEADER_FORMAT, program_header)
            program_headers.append(
                {
                    "type": type_,
                    "flags": flags,
                    "offset": offset,
                    "virtual_address": vaddr,
                    "physical_address": paddr,
                    "file_size": filesz,
                    "memory_size": memsz,
                    "alignment": align,
                }
            )
            
        print("\nProgram Headers:")
        for i, program_header in enumerate(program_headers):
            print(f"Program Header {i + 1}:")
            print(f"  Type:              {PGH_TYPE[program_header['type']] if program_header['type'] in PGH_TYPE.keys() else 'UNKNOWN'}")
            print(f"  Flags:             {program_header['flags']}")
            print(f"  Offset:            {program_header['offset']}")
            print(f"  Virtual Address:    0x{program_header['virtual_address']:X}")
            print(f"  Physical Address:   0x{program_header['physical_address']:X}")
            print(f"  File Size:         {program_header['file_size']}")
            print(f"  Memory Size:       {program_header['memory_size']}")
            print(f"  Alignment:         {program_header['alignment']}\n")
    
    if len(py_flags) == 0 or '-s' in py_flags:
        section_headers = []
        f.seek(sh_offset)
        counter = 0
        for _ in range(sh_entry_count):
            section_header = f.read(sh_entry_size)        
            (
                name,
                type_,
                flags,
                addr,
                offset,
                size,
                link,
                info,
                addr_align,
                entry_size,
            ) = struct.unpack(ELF_SECTION_HEADER_FORMAT, section_header)
            if counter == sh_str_index:
                shstrtab_offset = offset
                shstrtab_size = size
                counter += 1
                continue
            section_headers.append(
                {
                    "name": name,
                    "type": type_,
                    "flags": flags,
                    "address": addr,
                    "offset": offset,
                    "size": size,
                    "link": link,
                    "info": info,
                    "address_align": addr_align,
                    "entry_size": entry_size,
                }
            )
            counter += 1
            
        f.seek(shstrtab_offset)
        shstrtab = f.read(shstrtab_size).decode()

        print("\nSection Headers:")
        for i, section_header in enumerate(section_headers):
            print(f"Section {i + 1}:")
            print(f"  Name:            {shstrtab[section_header['name']:][:shstrtab[section_header['name']:].find(chr(0))]}")
            print(f"  Type:            {SH_TYPE[section_header['type']] if section_header['type'] in SH_TYPE.keys() else 'UNKNOWN'}")
            print(f"  Flags:           {RetShFlags(section_header['flags'])}")
            print(f"  Address:         0x{section_header['address']:X}")
            print(f"  Offset:          {section_header['offset']}")
            print(f"  Size:            {section_header['size']}")
            print(f"  Link:            {section_header['link']}")
            print(f"  Info:            {section_header['info']}")
            print(f"  Address Align:   {section_header['address_align']}")
            print(f"  Entry Size:      {section_header['entry_size']}\n")
    f.close()

if len(sys.argv) < 2:
    print('Usage: parse_elf.py [flags: -h, -e, -p, -s] <elf_file_path>')
    sys.exit()
    
if '-h' in sys.argv:
    print('None : print everything')
    print('-e : print only ELF Header')
    print('-p : print only Program Header')
    print('-s : print only Section Header')
    sys.exit()

flags = [i for i in sys.argv if i in ['-e', '-p', '-s']]
file_path = [i for i in sys.argv if i not in ['-e', '-p', '-s']]
file_path.remove('parse_elf.py')
if len(flags) > 3:
    print('Error: too many flag params')
    sys.exit()
if len(file_path) > 1:
    print('Error: unknown params')
    sys.exit()
file_path = file_path[0]
parse_elf_header(flags, file_path)