import pefile
import os 
import mmap
import sys


def align(val_to_align, alignment):
    return ((val_to_align+alignment-1)/alignment)*alignment

def IncreaseFileSize(binary, original_size):
    fil = open(binary, 'a+b')
    map = mmap.mmap(fil.fileno(), 0, access = mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    fil.close()

def insertCaves(malware, target_section, cave_size=0):
    original_size = os.path.getsize(malware)
    print("Original Size", original_size)
    pe = pefile.PE(malware, fast_load=True)
    pe.write("new_malware.exe")
    IncreaseFileSize("new_malware.exe", original_size)
    malware = "new_malware.exe"
    Increased_size = os.path.getsize(malware)
    print("Increased Size", Increased_size)

    pe = pefile.PE(malware, fast_load=True)

    if not pe.is_exe():
        pe.close()
        raise NotPE()
    elif pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 or pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size != 0:
        pe.close()
        raise NotPE()
    raw_addition = int(align(0x1000, pe.OPTIONAL_HEADER.FileAlignment))
    virtual_addition = int(align(0x1000, pe.OPTIONAL_HEADER.SectionAlignment))

    for section in pe.sections:
        if section.Name.decode().rstrip('\x00') == '.text':
            section.Characteristics=0xC0000020

    print("Raw Addition ", raw_addition)
    print("Virtual Addition ", virtual_addition)
    #AEP_Point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    #pe.OPTIONAL_HEADER.SizeOfRawData += raw_addition
    pe.OPTIONAL_HEADER.SizeOfImage += virtual_addition
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x289A


    pe.__data__[28672 : 32768] = pe.__data__[6144:10240] #7000+1000 = 1800+1000

    pe.__data__[6144:10240] = b'\x00' * 4096

    #pe.__data__[int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)+4096)] = b'\x00' * 4096
    # pe.__data__[8192:8216] = b'\x00' * 24

    pe.__data__[10394:10418] = b'\xBE\x00\x70\x40\x00\xBF\x00\x18\x40\x00\xB9\x00\x10\x00\x00\xF3\xA4\xB8\x74\x26\x40\x00\xFF\xE0'

    #pe.__data__[10394:10429] = b'\x66\xBB\x9A\x28\x8E\xDB\xBE\x00\x00\x00\x00\x66\xBB\x00\x20\x8E\xC3\xBF\x00\x00\x00\x00\xB9\x18\x00\x00\xF3\xA4\xEA\x00\x00\x00\x00\x74\x26'

    #pe.__data__[10394:10401] = b'\xB8\x74\x26\x40\x00\xFF\xE0'

    #pe.__data__[int(pe.OPTIONAL_HEADER.AddressOfEntryPoint) : (int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)+32)] = b'\x66\xBB\x00\xF0\x8E\xDB\xBE\x00\x00\x00\x00\x66\xBB\x00\x15\xBF\x00\x00\x00\x00\xB9\x00\x10\x00\x00\xF3\xA4\xE9\x70\x26\x00\x00'

    # for section in pe.sections:
    #     if section.Name.decode().rstrip('\x00') == '.rsrc':
    #         print("Inside resource section") 

    pe.write("final_malware.exe")


#direct = "/home/user/Desktop/Code_caves/0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC.exe"
#direct = "putty.exe"

inp = int(input("Select one of the sections to input code cave: \n 1 for .text \n 2 for .rdata \n 3 for .data \n 4 for .rsrc \n"))


if inp == 1: 
    target_section = '.text'
elif inp == 2: 
    target_section = '.rdata'
elif inp == 3: 
    target_section = '.data'
elif inp == 4: 
    target_section = '.rsrc'
else:
    print("Invalid section value entered")
    sys.exit()
insertCaves(direct, target_section)
