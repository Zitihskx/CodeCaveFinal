from base64 import decode
import os
import pefile

reloc_count=0
total = 0
decode_error = 0
notpe = 0
path = "/home/user/Desktop/Gradient Attack/data/valid/"
dir_list = os.listdir(path)
for directory in dir_list:
    indiv_pe = path+directory
    try:
        pe = pefile.PE(indiv_pe, fast_load=True)
    except:
        notpe += 1
        continue
    total +=1
    for section in pe.sections:
        try:
            name = section.Name.decode().rstrip('\x00')
        except:
            decode_error += 1

        if name == '.reloc':
            reloc_count +=1

print(f"total   {total}")
print(f"reloc counr     {reloc_count}")
print(f"decode error    {decode_error}")
print(f"not pe error    {notpe}")