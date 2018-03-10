import idaapi
import idc

decode_func = 0x10001000
total_decode = 0
add_list = []

def get_string(addr, last_addr, flag=0):
    out = []
    if flag == 0:
        while addr < last_addr:
            out.append(hex(Byte(addr)))
            addr += 1
    else:
        while True:
            if Byte(addr) != 0:
                out.append(hex(Byte(addr)))
            else:
                break
            addr += 1
            
    return out

for addr in XrefsTo(decode_func, flags=0):
    next_address = idc.PrevHead(addr.frm)
    for i in range(0,3):
        next_address = idc.PrevHead(next_address)
        if GetMnem(next_address) == "push" and GetOpnd(next_address, 0).find("offset") != -1:
            String = GetOpnd(next_address,0).split(" ")[1]
            add_list.append(get_name_ea(next_address, String))

add_list = sorted(add_list)
count = 0
result = []

for i in range(len(add_list)):
    next_address = add_list[i]
    count = i
    try:
        result.append(get_string(next_address, add_list[count+1]))
    except:
        result.append(get_string(next_address, add_list[count],1))
    next_address = idc.NextHead(next_address)
    
print(result)