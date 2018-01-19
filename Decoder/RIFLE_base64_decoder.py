# md5 : 18E4A570BE3FE301776F81E39DF6974B

from idaapi import *
import idc
import base64

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
    string = base64.b64decode(string)
    return string

decode_func = 0x401000
total_decode = 0
for addr in XrefsTo(decode_func, flags=0):
    next_address = addr.frm
    for i in range(0,2):
        next_address = idc.PrevHead(next_address)
        if GetMnem(next_address) == "mov" and GetOpnd(next_address, 1).find("offset") != -1:
            String = GetOpnd(next_address,1).split(" ")[1]
            add = get_name_ea(next_address,String)
            String = get_string(add)
            decode_str = string_decode(String)
            print_info = str(hex(next_address))[:-1] + " -> " + decode_str
            print(print_info)
            MakeComm(next_address, print_info)
            MakeComm(addr.frm, print_info)
            total_decode+=1
print "total : " + str(total_decode)
