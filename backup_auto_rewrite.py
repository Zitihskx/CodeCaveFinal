from ctypes import sizeof
from functools import total_ordering
from shellgen import *
import pefile
import os 
import mmap
import sys
import re
import csv
import time

#Align values to either File alignment or Section Alignment
def align(val_to_align, alignment):
    return ((val_to_align+alignment-1)/alignment)*alignment

#Increases the size of file by required amount
def IncreaseFileSize(binary, original_size):
    fil = open(binary, 'a+b')
    map = mmap.mmap(fil.fileno(), 0, access = mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    fil.close()


def insertCaves(malware, target_section, cave_size=0):
    original_size = os.path.getsize(malware)
    # if original_size>2000000:
    #     return 0

    IncreaseFileSize(malware, original_size) #Work on original file

    pattern = r"valid/(.*)"
    match= re.search(pattern, malware)
    if match:
        output_str = match.group(1) #name of a file separated using regex

    Increased_size = os.path.getsize(malware) 
    print("Increased Size", Increased_size)

    try:
        pe = pefile.PE(malware, fast_load=True)
        #time.sleep(1)
    except:
        return 0
    status = "Failure"

    try:
        if not pe.is_exe():
            pe.close()
            print("Not executable \n")
            return 0
        elif pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 or pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size != 0:
            pe.close()
            print("Data directory incompatible \n")
            return 0
    except:
        print("Issues with PE files \n")
        return 0
    flag =False
    
    #raw_addition = int(align(0x1000, pe.OPTIONAL_HEADER.FileAlignment))
    virtual_addition = int(align(0x1000, pe.OPTIONAL_HEADER.SectionAlignment))


    #Disabling the base relocation for a file
    if hex(pe.FILE_HEADER.Characteristics)[-1:].upper() in ['2', '4', '6', '8', 'A','C','E']:
         pe.FILE_HEADER.Characteristics += 0x1

    #Writing assembly instructions at the end of text section
    for section in pe.sections:
        try:
            section_name = section.Name.decode().rstrip('\x00')
        except:
            print("Failure to decode section\n")
            return 0
        if section_name == '.text':
            assembly_start = section.PointerToRawData + section.SizeOfRawData - 30
            #print(hex(assembly_start))

    #Changing characteristics flag of target section where code cave is injected
    maxim_size = 10
    start_location = 10
    assembly_start = 10
    for section in pe.sections:
        last_va = section.VirtualAddress
        last_vs = section.Misc_VirtualSize
        last_ra = section.PointerToRawData
        last_rs = section.SizeOfRawData
        if section.Name.decode().rstrip('\x00') == target_section:
            if target_section == '.text':
                section.Characteristics=0xC0000020
            elif target_section in {'.rdata', '.data', '.rsrc'}:
                section.Characteristics=0xC0000040
            elif target_section ==".reloc":
                section.Characteristics=0xC2000040
            else:
                print("Unknown section encountered")
            maxim_size = int(section.SizeOfRawData) #last 30 bytes reserved 
            start_location = int(section.PointerToRawData)
    

    print("Cave Size "+ str(0.15*Increased_size))
    print("Maximu available size "+ str(maxim_size))

    if maxim_size < (0.15*Increased_size):
        print("Given section size is insufficient for code cave \n")
        status = "Insufficient"
        flag = True
        return 0
    


    cave_size = int(0.15*Increased_size)
    
    #print("maximum size available "+ str(maxim_size))
    #print("STart address of given section  "+str(start_location))
    #cave_size = int(input("Enter size of the cave   "))  #Size of cave that we are about to insert needs to automate
    cave_location = int(start_location) #Starting location for cave needs to automate, this has been changed

    copy_to = last_ra + last_rs - cave_size  #where the cave chunk is being saved initially

    cave_size_hex = hex(cave_size)[2:]
    cave_location_hex = hex(cave_location+pe.OPTIONAL_HEADER.ImageBase)[2:]
    #cave_source_hex = hex(original_size+pe.OPTIONAL_HEADER.ImageBase)[2:]
    cave_source_hex = hex(copy_to + pe.OPTIONAL_HEADER.ImageBase)[2:]

    temp_AEP = str(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint+pe.OPTIONAL_HEADER.ImageBase))[2:]
    #print(temp_AEP)

    pe.OPTIONAL_HEADER.SizeOfImage += virtual_addition

    pe.OPTIONAL_HEADER.AddressOfEntryPoint = assembly_start

    try:
        pe.__data__[copy_to : copy_to + cave_size] = pe.__data__[cave_location:cave_location+cave_size]

        #pe.__data__[cave_location:cave_location+cave_size] = b'\x00' * cave_size
    except:
        print("Slice assignment incorrect \n")
        return 0
    

    print("Cave source "+ cave_source_hex)
    shell_data = gen_shellcode(cave_location_hex, cave_source_hex, cave_size_hex, temp_AEP)
    
   
    pe.__data__[assembly_start:assembly_start+24] = shell_data.encode().decode('unicode-escape').encode('ISO-8859-1')

    malware_name = "/home/user/Desktop/Code_caves/Malware_15_New/" + output_str
    pe.write(malware_name)
    time.sleep(1)
    status = "success"

    row = [output_str, cave_location, cave_size, status,flag]
    with open("Cave15_Non_empty_caves.csv",'a', newline='') as csvfile:
        my_writer = csv.writer(csvfile, delimiter=',')
        my_writer.writerow(row)
        
    return 1



#direct = "/home/user/Desktop/Code_caves/0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC.exe"

direct = "/home/user/Desktop/Code_caves/FCD83326561CC455A8336C83A472F0211863B5BC7E846E6E95CA570D698A1A2A.exe"
valid_count = 0
directory = "/home/user/Desktop/valid"
for root, dirs, files in os.walk(directory):
    for filename in files:
        full_name = os.path.join(root,filename)
        valid_count += insertCaves(full_name, '.data')
        #time.sleep(1)
print(valid_count)





#insertCaves(direct, '.text')


