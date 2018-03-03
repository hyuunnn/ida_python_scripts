import struct
import binascii
from string import ascii_lowercase

table = [0x1, 0x1A, 0x2A4, 0x44A8, 0x6F910, 0xB54BA0]

def magniber_table(extension):
    result = 0
    length = len(extension)-1

    for_loop = list(extension)

    for i in for_loop:
        result += table[length] * (ord(i) - 0x60)
        length -= 1

    result = binascii.hexlify(struct.pack("<L",result)).decode("utf-8")
    return result

if __name__ == "__main__":
    f = open("magiber_table.txt","w")

    for a in ascii_lowercase:
        f.write(a + " : " + magniber_table(a)+"\n")

    for a in ascii_lowercase:
        for b in ascii_lowercase:
            f.write(a+b + " : " + magniber_table(a+b)+"\n")

    for a in ascii_lowercase:
        for b in ascii_lowercase:
            for c in ascii_lowercase:
                f.write(a+b+c + " : " + magniber_table(a+b+c)+"\n")

    for a in ascii_lowercase:
        for b in ascii_lowercase:
            for c in ascii_lowercase:
                for d in ascii_lowercase:
                    f.write(a+b+c+d + " : " + magniber_table(a+b+c+d)+"\n")

    #for a in ascii_lowercase:
    #    for b in ascii_lowercase:
    #        for c in ascii_lowercase:
    #            for d in ascii_lowercase:
    #                for e in ascii_lowercase:
    #                    f.write(a+b+c+d+e + " : " + magniber_table(a+b+c+d+e)+"\n")
                        
    f.close()