#MD5 : 7FE80CEE04003FED91C02E3A372F4B01
#MD5 : FD59AF723B7A4044AB41F1B2A33350D6

from idaapi import *
import idc

def get_string(addr):
  out = ""
  while True:
    if Byte(addr) != 0:
      out += chr(Byte(addr))
    else:
      break
    addr += 1
  return out

def string_decode(string):
    string = list(string)
    v21 = list("1A2z3B4y5C6x7D8w9E0v$F_uGtHsIrJqKpLoMnNmOlPkQjRiShTgUfVeWdXcYbZa")
    v22 = list("9025jhdho39ehe2")
    Source = list("iamsorry!@1234567")
    v23 = [0x0,0x1,0x3,0x7,0xF,0x1F,0x3F]
    Source = [hex(ord(x)) for x in Source]
    v9 = [0]*len(string)
    v36 = 0

    v2 = Source
    if not Source:
        v2 = v22
    v32 = len(v2)

    for i in range(1, len(Source)):
        Source[i] = hex(int(str(Source[i]),16) + int(str(Source[i-1]),16))
        while int(str(Source[i]),16) > 0xFF:
            Source[i] = hex(int(str(Source[i]),16) - 0x100)

    for j in range(len(Source)-1,0,-1):
        Source[j-1] = hex(int(str(Source[j-1]),16) + int(str(Source[j]),16))
        while int(str(Source[j-1]),16) > 0xFF:
            Source[j-1] = hex(int(str(Source[j-1]),16) - 0x100)

    v35 = 8
    for i in range(1,len(string)):
        for j in range(len(v21)):
            if string[i] == v21[j]:
                Source_3 = j
        v11 = 6
        while v11 > 0:
            v12 = v35
            if v11 < v35:
                v12 = v11
            v11 = v11 - v12
            v31 = v9[v36]
            #print(v12,hex(Source_3),v9[v36])
            v9[v36] = hex(int(str(v9[v36]),16) << v12 | (v23[v12]) & (Source_3 >> (6 - v12)))
            while int(v9[v36],16) > 0xFF:
                v9[v36] = hex(int(str(v9[v36]),16) - 0x100) # ex) 0xdc0 -> 0xc0
            Source_3 = Source_3 << v12
            v35 = v35 - v12
            if not v35:
                v36 += 1
                v35 = 8
                v9[v36] = 0

    k = 0
    for i in range(v36-1):
        v9[i] = hex(int(str(v9[i]),16) - int(str(v9[i+1]),16))
        while int(str(v9[i]),16) < 0:
            v9[i] = hex(int(str(v9[i]),16) + 0x100)
        k = i
    while k >= 1:
        v9[k] = hex(int(str(v9[k]),16) - int(str(v9[k - 1]),16))
        #print(Source[k % 32])
        try:
            v9[k] = hex(int(str(v9[k]),16) - (int(Source[k % 32],16)))
        except:
            return ""
        while int(str(v9[k]),16) < 0:
            v9[k] = hex(int(str(v9[k]),16) + 0x100)
        k = k - 1

    v15 = v9[1]
    first_alphabet = v9[0]
    #print (first_alphabet)

    Str_3 = 0

    for i in range(len(v15)):
        v9[i] = v9[i+3]
    v9[int(v15,16)+2] = first_alphabet
    return v9[3:]

decode_func = 0x401757
total_decode = 0
for addr in XrefsTo(decode_func, flags=0):
    next_address = idc.PrevHead(addr.frm)
    for i in range(0,3):
        next_address = idc.PrevHead(next_address)
        if GetMnem(next_address) == "push" and GetOpnd(next_address, 0).find("offset") != -1:
            String = GetOpnd(next_address,0).split(" ")[1]
            add = get_name_ea(next_address,String)
            String = get_string(add)
            decode_str = string_decode(String)
            #print decode_str
            decode_str = ''.join(chr(int(str(i),16)) for i in decode_str)
            print_info = str(hex(next_address))[:-1] + " -> " + decode_str
            print(print_info)
            MakeComm(next_address, print_info)
            #String_addr = GetOperandValue(next_address, 0)
            #print String_addr
            #print hex(String_addr)
            #print GetOpnd(String_addr, 0)
            total_decode+=1
print "total : " + str(total_decode)
