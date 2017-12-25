# ama

from idaapi import *
import idautils

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
    for i in range (0,len(string)):
        if string[i] < 105 or string[i] > 112:
            if string[i] >= 114 and string[i] <= 121:
                string[i] = string[i] - 9
            if string[i] < 73 or string[i] > 80:
                if string[i] < 82 or string[i] > 89:
                    continue
                string[i] = string[i] - 9
            string[i] = string[i] + 9
        else:
            string[i] = string[i] + 9
    return string
            
decode_string_add = 0x10002BD0
total_decode = 0
for addr in XrefsTo(decode_string_add, flags=0):
    #print hex(addr.frm)
    next_address = idc.PrevHead(addr.frm)
    #print idc.PrevHead(addr.frm)
    for i in range(0,3):
        next_address = idc.PrevHead(next_address)
        #print hex(next_address)
        if GetMnem(next_address) == "push" and GetOpnd(next_address, 0).find("offset") != -1:
            String = GetOpnd(next_address, 0).split(" ")[1]
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
