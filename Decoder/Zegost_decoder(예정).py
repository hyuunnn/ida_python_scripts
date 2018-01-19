#MD5 : AEB40B58C5380ECB31C96F1400344F5B
#MD5 : F5B75F2DC24CBA9FEC540E2C62D36332
#MD5 : 8B69A3EE4AB5A45E39D3F100084B1953
#MD5 : F5B75F2DC24CBA9FEC540E2C62D36332


subkey = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
string = list("PjdCLUE+RS0+PkQtN0JP")
v3 = []
v20 = 0
v5 = 0
v7 = 0
v9 = 0
v17 = 0
#for i in range(len(string)):
i = 0


def Decode(v3,v20,v5,v7,v9,v17,i):
    while(1):
        v4 = ord(string[i+2])
        if v20:
            return v3 
        #for j in range(1,len(subkey)):
        #    if string[i] == subkey[j]:
        v5 = ord(string[i]) - ord("A")
        if v5 < 0:
            return v3 
        v6 = v5 << 6
        #for j in range(1,len(subkey)):                # - ord 이 부분에 문제가 있음
        #    if string[i] == subkey[j]:
        v7 = ord(string[i+2]) - ord("A")
        if v7 < 0:
            return v3 # return -1
        v8 = (v7 + v6) << 6
        if v4 == 61:
            v20 = 1
        else:
            #for j in range(1,len(subkey)):
            #    if string[i] == subkey[j]:
            v9 = ord(string[i+8]) - ord("A")
            if v9 < 0:
                return v3
            print(hex(v9))
            return -1
            v8 += v9
        v10 = ord(string[i+3])
        v11 = v8 << 6
        v12 = v11
        #if v10 != 61:
        #    break
        #v13 = v20 + 1
        #v15 = 
        #v14 = v20+=1 -2 < 0
        for j in subkey:
            if string[i] == j:
                v17 == ord(string[i])
        if v17 < 0:
            return v3 # return -1
        v12 = v17 + v11
        v13 = 0
        v3.append(hex(v12))
        i += 1
        if v13 < 2:
            v3.append(hex(v12))
        if v13 < 1:
            v3.append(hex(v12))
        try:
            v16 = ord(string[i+4])
        except:
            return v3
        v4 += 4

print(Decode(v3,v20,v5,v7,v9,v17,i))