# md5 : 7CAA500B60A536D7501E7A6C02408538
# md5 : EA38BDC05F3D357623A78E4A90613AE2

def subs(string):
    sub_table = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3E,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3F,0x00,0x34,0x00,0x35,0x00,0x36,0x00,0x37,0x00,0x38,0x00,0x39,0x00,0x3A,0x00,0x3B,0x00,0x3C,0x00,0x3D,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,0x00,0x09,0x00,0x0A,0x00,0x0B,0x00,0x0C,0x00,0x0D,0x00,0x0E,0x00,0x0F,0x00,0x10,0x00,0x11,0x00,0x12,0x00,0x13,0x00,0x14,0x00,0x15,0x00,0x16,0x00,0x17,0x00,0x18,0x00,0x19,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x1A,0x00,0x1B,0x00,0x1C,0x00,0x1D,0x00,0x1E,0x00,0x1F,0x00,0x20,0x00,0x21,0x00,0x22,0x00,0x23,0x00,0x24,0x00,0x25,0x00,0x26,0x00,0x27,0x00,0x28,0x00,0x29,0x00,0x2A,0x00,0x2B,0x00,0x2C,0x00,0x2D,0x00,0x2E,0x00,0x2F,0x00,0x30,0x00,0x31,0x00,0x32,0x00,0x33,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]
    v5 = 0
    result_index = 0
    result = [0]*len(string)
    for i in range(0,len(string)):
        if string[i] == "=":
            break
        if string[i] == " ":
            string[i] = "+"

        value = sub_table[ord(string[i])*2] # i don't know *2
        switch = v5 % 4
        if switch == 0 :
            result[result_index] = 4 * value
        elif switch == 1:
            result[result_index] = result[result_index] | (value >> 4)
            result_index +=1
            result[result_index] = 16 * value
        elif switch == 2:
            result[result_index] = result[result_index] | (value >> 2)
            result_index +=1
            result[result_index] = (value << 6)
        elif switch == 3:
            result[result_index] = result[result_index] | value
            result_index +=1
        v5 +=1

    for i in range(0,len(result)):
        while(1):
            if result[i] > 0xff:
                result[i] -= 0xff+1
            else:
                break

    return [hex(a) for a in result]

def XOR_transform(string):
    result = []
    sub_decode_string = subs(string)
    v5 = 0x82
    v6 = 0x5
    v11 = 0x556F9482
    v7 = 0xAFC12058
    for i in range(0,len(sub_decode_string)):
        if sub_decode_string[i] == "0x0":
            break

        v7 = int("0x" + hex(v7)[-9:-1], base=16)
        a = hex(v6 ^ v7 ^ v5 ^ int(sub_decode_string[i],base=16))
        result.append(a[-3:-1])
        v6 = v6 & v7 ^ v5 & (v6 ^ v7)
        v5 = (((v11 ^ (8 * v11)) & 0x7F8) << 20) | (v11 >> 8)
        v7 = (((v7 << 7) ^ (v7 ^ 16 * (v7 ^ 2 * v7)) & 0xFFFFFF80) << 17) | (v7 >> 8)
        v11 = (((v11 ^ (8 * v11)) & 0x7F8) << 20) | (v11 >> 8)
    return [chr(int(b,base=16)) for b in result]
    
print(''.join(XOR_transform(list("lNHc1SyUQ/B9235n")))) # Kernel32.dll