# ama

string = [0x10,0xDA,0xE6,0x28,0xCF,0x9B,0x39,0xA5,0x41,0xE9,0xC3,0xEB,0x46,0x2F,0x7,0x6B,0x4A]

def Manuscrypt(string):
    result = 0
    num = 0
    v7 = 0x7DEC1FDE
    v8 = 0x311AA827
    v9 = 0xE3EAE9B8
    v10 = 0xBECAD862
    v4 = 0
    table = list(range(256))
    key = [0xDE,0x1F,0xEC,0x7D,0x27,0xA8,0x1A,0x31,0xB8,0xE9,0xEA,0xE3,0x62,0xD8,0xCA,0xBE]
    while result < 256:
        #v4 += table[result] + table[result % 16 + key[num]]
        v4 = table[result] + key[result % 16]
        print("@@"+str(key[result % 16]))
        v5 = table[result]
        result +=1
        table[result] = table[v4]
        table[v4] = v5
        if num == 16:
            num = 0
        else:
            num += 1

    return result

print(Manuscrypt(string))
