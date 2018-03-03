import idaapi
import idc
import binascii
import struct
from string import ascii_lowercase

add = 0x13c4fd6 # loc_13C4FD6
table = [0x1, 0x1A, 0x2A4, 0x44A8, 0x6F910, 0xB54BA0]
result_table = {}

def magniber_table(extension):
    result = 0
    length = len(extension)-1

    for_loop = list(extension)

    for i in for_loop:
        result += table[length] * (ord(i) - 0x60)
        length -= 1

    result = binascii.hexlify(struct.pack("<L",result))
    return result

if __name__ == "__main__":
    for a in ascii_lowercase:
        result_table[magniber_table(a)] = a

    for a in ascii_lowercase:
        for b in ascii_lowercase:
            result_table[magniber_table(a+b)] = a+b

    for a in ascii_lowercase:
        for b in ascii_lowercase:
            for c in ascii_lowercase:
                result_table[magniber_table(a+b+c)] = a+b+c

    for a in ascii_lowercase:
        for b in ascii_lowercase:
            for c in ascii_lowercase:
                for d in ascii_lowercase:
                    result_table[magniber_table(a+b+c+d)] = a+b+c+d

    while True:
        add = idc.NextHead(add)

        if GetMnem(add) == "call" and GetOpnd(add,0) == "edi":
            break

        if GetMnem(add) == "mov" and "esp+0BE" in GetOpnd(add, 0):
            value = GetOpnd(add, 1)
            if "h" in value:
                value = value.replace("h","")
                
            value = int("0x"+value,16)
            try:
                value = result_table[binascii.hexlify(struct.pack("<L",value))]
                print(value)
            except:
                pass
