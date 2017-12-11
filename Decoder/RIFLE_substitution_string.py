## md5 : 8BD8C367DFE5C418A771CA8BDCE6AC88

from idaapi import *
import idautils

key = list("zcgXlSWkj314CwaYLvyh0U_odZH8OReKiNIr-JM2G7QAxpnmEVbqP5TuB9Ds6fFt")

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
    result = ""
    arr = list(string)
    for i in range(0, len(arr)):
        cnt = 0
        for j in range(0, len(key)):
            if arr[i] != key[j]:
                cnt +=1
            if arr[i] == key[j]:
                result += (key[((cnt - 0x16) & 0x3F)])
                break
    return result

decode_string_add = [0x403ca0, 0xb3bc0]
total_decode = 0
for addr in XrefsTo(decode_string_add[0], flags=0):
    next_address = idc.PrevHead(addr.frm)
    for i in range(0,6):
        next_address = idc.PrevHead(next_address)
        if GetMnem(next_address) == "mov" and GetOpnd(next_address, 1).find("offset") != -1:
            String = GetOpnd(next_address, 1).split(" ")[1]
            add = get_name_ea(next_address,String)
            String = get_string(add)
            decode_str = string_decode(String)
            print_info = str(hex(next_address))[:-1] + " -> " + decode_str
            print(print_info)
            MakeComm(next_address, print_info)
            total_decode+=1
print "total : " + str(total_decode)
