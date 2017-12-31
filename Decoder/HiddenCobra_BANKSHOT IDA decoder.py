# md5 : 9394078671922DE6B5CD194E3581EC46
# md5 : BBEE2A74C766CC5DBCD827CCA2CCA269
# md5 : C6F8C416E67424C213DFD8265802B221

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
    string = [ord(c) for c in string]
    
    for i in range(0,len(string)):
        v12 = string[i]
        if v12 >= 98 and v12 <= 121:
            if v12 >= 100 and v12 <= 109:
                v13 = v12 + 11
                string[i] = v13
                v14 = string[i]
                if v14 < 66 or v14 > 89:
                    continue
                if v14 < 68 or v14 > 77:
                    if v14 < 79 or v14 > 88:
                        continue
                    v15 = v14 - 11
                else:
                    v15 = v14 + 11
                string[i] = v15
                
            if v12 >= 111 and v12 <= 120:
                v13 = v12 - 11
                string[i] = v13
                v14 = string[i]
                if v14 < 66 or v14 > 89:
                    continue
                if v14 < 68 or v14 > 77:
                    if v14 < 79 or v14 > 88:
                        continue
                    v15 = v14 - 11
                else:
                    v15 = v14 + 11
                string[i] = v15
    
        v14 = string[i]
        if v14 < 66 or v14 > 89:
            continue
        if v14 < 68 or v14 > 77:
            if v14 < 79 or v14 > 88:
                continue
            v15 = v14 - 11
        else:
            v15 = v14 + 11
        string[i] = v15
    
    return string

decode_func = 0x408660
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
            decode_str = ''.join(chr(i) for i in decode_str)
            print_info = str(hex(next_address))[:-1] + " -> " + decode_str
            print(print_info)
            MakeComm(next_address, print_info)
            #String_addr = GetOperandValue(next_address, 0)
            #print String_addr
            #print hex(String_addr)
            #print GetOpnd(String_addr, 0)
            total_decode+=1
print "total : " + str(total_decode)
