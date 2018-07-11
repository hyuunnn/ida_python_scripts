from idaapi import *
from idautils import *
from idc import *
import time

def imp_cb(ea, name, ord):
    global result, bpt_module_name
    if name in bpt_module_name:
        #print "%08x: %s (ord#%d)" % (ea, name, ord)
        result.append(ea)
    # True -> Continue enumeration
    # False -> Stop enumeration
    return True

class VariableFinder():
    def __init__(self):
        pass

    def find_module(self):
        import_module = get_import_module_qty()
        for i in range(import_module):
            name = idaapi.get_import_module_name(i)
            idaapi.enum_import_names(i, imp_cb)
    
    def register_view(self):
        self.EAX = GetRegValue('EAX')
        self.EBX = GetRegValue('EBX')
        self.ECX = GetRegValue('ECX')
        self.EDX = GetRegValue('EDX')
        self.EBP = GetRegValue('EBP')
        self.ESP = GetRegValue('ESP')

if __name__ == '__main__':
    bpt_module_name = askstr(0, "", "bpt module name")
    result = []
    a = VariableFinder()
    a.find_module()
    for addr in result:
        for i in XrefsTo(addr, flags=0):
            print i.frm
            add_bpt(i.frm, 0, BPT_SOFT)

    idaapi.info(bpt_module_name + " breakpoint success")
    StartDebugger("","","")
    GetDebuggerEvent(WFNE_SUSP, -1)
    a.register_view()
    print a.
    #result = GetManyBytes(self.EAX, 1)
    #while GetManyBytes(self.EAX, 1) != "00":
    #    self.EAX += 1
    #    GetManyBytes(self.EAX, 1)
    #
    #print result