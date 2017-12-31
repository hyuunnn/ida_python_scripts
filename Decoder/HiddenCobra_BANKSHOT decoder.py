string = list("RpiEgdcphhItxph")
for i in range(0, len(string)):
    string[i] = ord(string[i])

def Label_15(v14):
    if v14 < 66 or v14 > 89:
        return
    if v14 < 68 or v14 > 77:
        if v14 < 79 or v14 > 88:
            return
        v15 = v14 - 11
    else:
        v15 = v14 + 11
    string[i] = v15


for i in range(0,len(string)):
    v12 = string[i]
    if v12 >= 98 and v12 <= 121:
        if v12 >= 100 and v12 <= 109:
            v13 = v12 + 11
            string[i] = v13
            v14 = string[i]
            Label_15(v14)
            
        if v12 >= 111 and v12 <= 120:
            v13 = v12 - 11
            string[i] = v13
            v14 = string[i]
            Label_15(v14)

    v14 = string[i]
    Label_15(v14)

string = [chr(x) for x in string]
print(''.join(string))
    
