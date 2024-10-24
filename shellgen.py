#from asyncio.windows_events import NULL
import codecs


def gen_shellcode(destination, source, cavesize, entry_point):
    shellcode = r"\xBE"


    if len(source)>8:
        source=source[-8:]
    while len(source)<8:
        source = '0' + source
    

    while len(source)!=0:
        shellcode += r"\x" + source[-2:]
        source = source[0:-2]

    shellcode += r"\xBF"

    if len(destination)>8:
        destination=destination[-8:]
    while len(destination)<8:
        destination= '0' + destination

    while len(destination)!=0:
        shellcode += r"\x" + destination[-2:]
        destination = destination[0:-2]

    shellcode += r"\xB9"

    if len(cavesize)>6:
        cavesize=cavesize[-6:]
    while len(cavesize)<6:
        cavesize = '0'+ cavesize

    while len(cavesize)!=0:
        shellcode += r"\x" + cavesize[-2:]
        cavesize = cavesize[0:-2]
    
    shellcode += r"\x00\xF3\xA4\xB8"

    if len(entry_point)>8:
        entry_point=entry_point[-8:]

    while len(entry_point)<8:
        entry_point = '0' + entry_point

    while len(entry_point)!=0:
        shellcode += r"\x" + entry_point[-2:]
        entry_point = entry_point[0:-2]

    shellcode += r"\xFF\xE0"
    
    return (shellcode)


def main():
    destination = hex(0x401770)[2:]
    source = hex(0x40d65a)[2:]
    cavesize = hex(0x138)[2:]
    entry_point = hex(0x4fd004)[2:]
    result = gen_shellcode(destination, source, cavesize, entry_point)
    print(result)
    print(result.encode().decode('unicode-escape').encode('ISO-8859-1'))
    temp_datat = b'\xBE\x00\x70\x40\x00\xBF\x00\x18\x40\x00\xB9\x00\x10\x00\x00\xF3\xA4\xB8\x74\x26\x40\x00\xFF\xE0'
    print(temp_datat)

if __name__=="__main__":
    main()

def gen_shellcode_copy(destination, source, cavesize, entry_point):
    shellcode = r"\xBE"
    while len(destination)!=0:
        shellcode += r"\x" + destination[-2:]
        destination = destination[0:-2]
    shellcode += r"\x00\xBF"

    while len(source)!=0:
        shellcode += r"\x" + source[-2:]
        source = source[0:-2]

    shellcode += r"\x00\xB9"

    while len(cavesize)!=0:
        shellcode += r"\x" + cavesize[-2:]
        cavesize = cavesize[0:-2]
    
    shellcode += r"\x00\x00\xF3\xA4\xB8"

    while len(entry_point)!=0:
        shellcode += r"\x" + entry_point[-2:]
        entry_point = entry_point[0:-2]

    shellcode += r"\x00\xFF\xE0"
    
    
    return (shellcode)