import pefile
import sys
import numpy as np
import pandas as pd


pe = pefile.PE("0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC", fast_load=True)

# Check if it is a 32-bit or 64-bit binary
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print("This is a 32-bit binary")
else:
    print("This is a 64-bit binary")

print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))

print ("Optional Header Content:")
print("Magic : " + hex(pe.OPTIONAL_HEADER.Magic))
print("ImageBase : " + hex(pe.OPTIONAL_HEADER.ImageBase))
print("SectionAlignment : " + hex(pe.OPTIONAL_HEADER.SectionAlignment))
print("FileAlignment : " + hex(pe.OPTIONAL_HEADER.FileAlignment))
print("SizeOfImage : " + hex(pe.OPTIONAL_HEADER.SizeOfImage))
print("DllCharacteristics flags : " + hex(pe.OPTIONAL_HEADER.DllCharacteristics))

Cave_df = pd.DataFrame(columns=['Section', 'Starting_Addr', 'Ending_Addr', 'Size'])
t = 0

print("\n Section Header contents \n")
print("Sections Info: \n")
print("*" * 50)
for section in pe.sections:
    print(section.Name.decode().rstrip('\x00') + "\n|\n|---- Vitual Size : " + hex(section.Misc_VirtualSize) +
     "\n|\n|---- VirutalAddress : " + hex(section.VirtualAddress) + "\n|\n|---- SizeOfRawData : " +
      hex(section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " + hex(section.PointerToRawData) +
       "\n|\n|---- Characterisitcs : " + hex(section.Characteristics)+'\n')   
    va = section.VirtualAddress
    vs = section.Misc_VirtualSize
    ea = section.VirtualAddress + section.Misc_VirtualSize -1

    print("Starting location: {}".format(va))
    print("Size of section in bytes: {}".format(vs))
    print("Location of last bute of the section: {}".format(ea))

    min_size= 200
    count = 0
    i = 0

    for byte in pe.__data__[va:ea]:
        if byte == 0:
            if count ==0:
                Starting_Addr = va+i
            count +=1
        else:
            if count > min_size:
                data = {'Section':section.Name.decode().rstrip('\x00'), 'Starting_Addr': Starting_Addr, 'Ending_Addr' : (va+i), 'Size' : count}
                datadf = pd.DataFrame(data, index=[0])
                Cave_df = pd.concat([Cave_df, datadf],  ignore_index=True, sort = False)
            count =0
        i += 1

    mismatch = section.SizeOfRawData - section.Misc_VirtualSize
    data = {'Section': section.Name.decode().rstrip('\x00'), 'Starting_Addr': (va+vs), 'Ending_Addr' : (va+vs+mismatch), 'Size' : mismatch}
    datadf = pd.DataFrame(data, index=[0])
    Cave_df = pd.concat([Cave_df, datadf],  ignore_index=True, sort = False)

print("*" * 50)

print(Cave_df)