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
    return string[2:]
            
decode_string_add = 0x403de0
total_decode = 0
for addr in XrefsTo(decode_string_add, flags=0): # decode 함수를 사용하는 함수들에 들어간다(IDA Xrefs)
    next_address = idc.PrevHead(addr.frm) # 사용된 함수의 주소 값을 가져온다.
    for i in range(0,3):
        next_address = idc.PrevHead(next_address) # 대부분 mov offset string 후에 call decode 함수 형식으로 되어있어 
                                                  # 최대 3번까지 mov와 offset string이 있는지 체크
        if GetMnem(next_address) == "mov" and GetOpnd(next_address, 1).find("offset") != -1:
            String = GetOpnd(next_address, 1).split(" ")[1] # offset aCloststrgxctha에서 aCloststrgxctha을 가져옴 해당 스트링은 변수
            add = get_name_ea(next_address,String) # 해당 string이 있는 data 영역의 주소를 가져옴
            String = get_string(add) # 거기에 있는 최종 string 값을 뽑아 온다. aCloststrgxctha 이 변수 값은 최종 string의 일부
            decode_str = string_decode(String)
            print_info = str(hex(next_address))[:-1] + " -> " + decode_str
            print(print_info)
            MakeComm(next_address, print_info)
            total_decode+=1
print "total : " + str(total_decode)