# md5 : 9394078671922DE6B5CD194E3581EC46

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
    num = 0
    while len(string) > num:
        v3 = string[num]
        if string[num] >= 98 and v3 <= 121:
            string[num] = 219 - v3
        num+=1
    return string

decode_func = 0x40A34D
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
