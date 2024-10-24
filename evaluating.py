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
import pandas as pd

count =0
columns =['File_name', 'Size', '.text', '.rdata', '.data', '.rsrc', '.reloc']
df = pd.DataFrame(columns=columns)

def insertCaves(malware):
    original_size = os.path.getsize(malware)
    pattern = r"train_malware/(.*)"
    match= re.search(pattern, malware)
    if match:
        output_str = match.group(1) #name of a file separated using regex

    try:
        pe = pefile.PE(malware, fast_load=True)
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

    #Writing assembly instructions at the end of text section
    columns =['File_name', 'Size', '.text', '.rdata', '.data', '.rsrc', '.reloc']
    df1 = pd.DataFrame(columns = columns)
    df1.at[0,'File_name'] = output_str
    df1.at[0,'Size'] = original_size

    for section in pe.sections:
        try:
            section_name = section.Name.decode().rstrip('\x00')
        except:
            print("Failure to decode section\n")
            return 0
        if section_name == ".text":
            try:
                df1.at[0,'.text'] = section.SizeOfRawData
            except:
                df1.at[0,'.text'] = "NA"
        elif section_name == ".rdata":
            try:
                df1.at[0,'.rdata'] = section.SizeOfRawData
            except:
                df1.at[0,'.rdata'] = "NA"
        elif section_name == ".data":
            try:
                df1.at[0,'.data'] = section.SizeOfRawData
            except:
                df1.at[0,'.data'] = "NA"
        elif section_name == ".rsrc":
            try:
                df1.at[0,'.rsrc'] = section.SizeOfRawData
            except:
                df1.at[0,'.rsrc'] = "NA"
        elif section_name == ".reloc":
            try:
                df1.at[0,'.reloc'] = section.SizeOfRawData
            except:
                df1.at[0,'.reloc'] = "NA"
    print(df1)
    global df
    df = pd.concat([df,df1], ignore_index=True, sort = False, join ='outer')
    global count
    count += 1
    print(count)

    return 0

directory = "/home/user/Desktop/train_malware"
valid_count=0
invalid_count=0
for root, dirs, files in os.walk(directory):
    for filename in files:
        full_name = os.path.join(root,filename)
        valid_count = insertCaves(full_name)
df.to_csv("Results_section_sizes_df.csv", index=False)
print("Done")


