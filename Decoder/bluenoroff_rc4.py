string = [0x10, 0xDA, 0xE6, 0x28, 0xCF, 0x9B, 0x39, 0xA5, 0x41, 0xE9, 0xC3, 0xEB, 0x46, 0x2F, 0x7, 0x6B, 0x4A, 0x0, 0x0, 0x0]
# GetProcessTimes

v7 = 0x7DEC1FDE ## a1
v8 = 0x311AA827
v9 = 0xE3EAE9B8
v10 = 0xBECAD862

table = [i for i in range(256)]
key = [0xDE,0x1F,0xEC,0x7D,0x27,0xA8,0x1A,0x31,0xB8,0xE9,0xEA,0xE3,0x62,0xD8,0xCA,0xBE]

v4 = 0
count = 0
while count < 256:
    v4 += table[count] + key[count % 16]
    v5 = table[count]
    while v4 > 0xff:
        v4 = v4 % 256
    table[count] = table[v4] # change calculate data
    count += 1
    table[v4] = v5 # shuffing

index = 1
length = string[0]

print([hex(i) for i in table])

i = 0
j = 0
while(index < length):
    i = i + table[table[index]]
    while i > 0xff:
        i = i % 256
    print(hex(i))
    j = j + table[index]
    while j > 0xff:
        j = j % 256
    table[i], table[j] = table[j], table[i]
    x = table[(i+j) % 256]
    print(hex(x), hex(string[index]))

    string[index] = x ^ string[index]
    index += 1


#print([hex(i) for i in string])
#print([chr(i) for i in string])