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
from concurrent.futures import ProcessPoolExecutor, as_completed

#Align values to either File alignment or Section Alignment
def align(val_to_align, alignment):
    return ((val_to_align+alignment-1)/alignment)*alignment

#Increases the size of file by required amount
def increase_file_size(binary, additional_size):
    with open(binary, 'a+b') as fil:
        with mmap.mmap(fil.fileno(), 0, access=mmap.ACCESS_WRITE) as map:
            map.resize(os.path.getsize(binary) + additional_size)


def insertCaves(malware, target_section, cave_size=0):

    original_size = os.path.getsize(malware)
    # print(f"original size: {original_size}")
    if original_size>2000000:
        return 0

    #Work on original file

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

    virtual_addition = int(align(0x5000, pe.OPTIONAL_HEADER.SectionAlignment))


    #Disabling the base relocation for a file
    if hex(pe.FILE_HEADER.Characteristics)[-1:].upper() in ['2', '4', '6', '8', 'A','C','E']:
         pe.FILE_HEADER.Characteristics += 0x1cd

    maxim_size = -1
    start_location = -1
    assembly_start = -1 

    try:
        required_sections = {"UPX1", ".rsrc"}
        present_sections = (section.Name.decode().rstrip('\x00') for section in pe.sections)

        if required_sections.issubset(present_sections):
            pass
        else:
            return 0
    except:
        return 0

    #Writing assembly instructions at the end of .text section
    for section in pe.sections:
        try:
            section_name = section.Name.decode().rstrip('\x00')
        except:
            print("Failure to decode section\n")
            return 0
        if section_name == 'UPX1':
            assembly_start = section.PointerToRawData + section.SizeOfRawData - 30
            # print(f"assembly start {hex(assembly_start)}")
            maxim_size = int(section.SizeOfRawData)-30
            start_location = int(section.PointerToRawData)
            start_location_hex = section.PointerToRawData
        elif section_name =='.rsrc':
            section.Misc_VirtualSize = int(align(section.Misc_VirtualSize+0x5000, pe.OPTIONAL_HEADER.SectionAlignment))
            section.SizeOfRawData = int(align(section.SizeOfRawData+0x5000, pe.OPTIONAL_HEADER.FileAlignment))

            # last_va = section.VirtualAddress
            # last_vs = section.Misc_VirtualSize
            last_ra = int(section.PointerToRawData)
            last_rs = int(section.SizeOfRawData)

    cave_size = int(0x5000)
    # print("Cave Size "+ str(cave_size))
    # print("Maximu available size " + str(maxim_size))

    if maxim_size < cave_size:
        print("Given section size is insufficient for code cave \n")
        status = "Insufficient"
        flag = True
        return 0
    
    cave_location = int(start_location) #Starting location for cave needs to automate, this has been changed

    copy_to = last_ra + last_rs - cave_size  #where the cave chunk is being saved initially

    if (copy_to+cave_size)>original_size:
        copy_to = original_size-cave_size-1

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
    

    # print("Cave source "+ cave_source_hex)
    
    
    try:
        shell_data = gen_shellcode(cave_location_hex, cave_source_hex, cave_size_hex, temp_AEP)
        pe.__data__[assembly_start:assembly_start+24] = shell_data.encode().decode('unicode-escape').encode('ISO-8859-1')
    except:
        return 0

    output_str = re.search(r"UPX9_Size_20480/(.*)", malware).group(1)
    output_dir = "Cave20480_UPX1"
    malware_name = os.path.join(output_dir, output_str)
    
    try:
        pe.write(malware_name)
    except Exception as e:
        print(f"Error writing to {malware_name}: {e}")
        return 0
    
    time.sleep(1)
    status = "success"

    row = [output_str, cave_location, cave_size, status,flag]
    with open("Cave20480_UPX1_caves.csv",'a', newline='') as csvfile:
        my_writer = csv.writer(csvfile, delimiter=',')
        my_writer.writerow(row) 
    return 1


def process_files(directory):
    valid_count = 0
    with ProcessPoolExecutor() as executor:
        futures = []
        for root, dirs, files in os.walk(directory):
            for filename in files:
                full_name = os.path.join(root, filename)
                futures.append(executor.submit(insertCaves, full_name, 'UPX1'))

        for future in as_completed(futures):
            valid_count += future.result()

    print(f"Total valid processed files: {valid_count}")

if __name__ == "__main__":
    directory = "/home/user/Desktop/CodeCaveFinal-main/UPX9_Size_20480/"
    process_files(directory)
# full_name = '/home/user/Desktop/ObfusTestMalware_CanDeleteLater/0a1f0111f4516001a002dba72405a30fc230a41b273b7cbaf1ccf5267eb7c804'
# insertCaves(full_name, 'UPX1')




