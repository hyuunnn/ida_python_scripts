from idautils import *
from idaapi import *
from idc import *

# https://reverseengineering.stackexchange.com/questions/14725/using-ida-python-iterate-through-all-functions-and-their-instructions

blacklist = ["operator", "dword"]
result = {}

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        functionName = GetFunctionName(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                result[functionName] = []

            for head in Heads(startea, endea):
                assem = GetDisasm(head)
                if "call" in assem and "ds:" in assem:
                    #print functionName, ":", "0x%08x"%(head), ":", assem.split("    ")[1]
                    API_name = assem.split("    ")[1].replace("ds:","").strip()
                    result[functionName].append(API_name)

                elif "call" in assem and not "ds:" in assem:
                    name = assem.split("    ")[1]
                    call_addr = get_name_ea(head, name)
                    assem = GetDisasm(call_addr)
                    if "ds:" in assem:
                        #print functionName, ":", "0x%08x"%(head), ":", name
                        API_name = assem.split("    ")[1].replace("ds:__imp_","").replace("ds:","").strip()
                        result[functionName].append(API_name)

for name in result.keys():
    if result[name] == []:
        del result[name]
    else:
        list(set(result[name]))


