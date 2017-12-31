string = list("SwuPlwnLwcX")
#string = [ord(c) for c in string]

for i in range(0,len(string)):
    v10 = ord(string[i]) - 1
    print(v10)
    if ord(string[i]) - 99 < 0: # check uppercase
        string[i] = v10
        continue
    if v10 >= 0x62 and v10 <= 0x79:
        string[i] = 0xDB - v10

for i in string:
    try:
        print(chr(i))
    except:
        print(i)
