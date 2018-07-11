from idaapi import *
from idc import *
from idautils import *

API_List = {
    'Execute':["ShellExecuteExW", "ShellExecuteW"],
    'Message':["MessageBoxW"],
    'Change':["GetModuleFileNameA"]
}

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        functionName = GetFunctionName(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                assem = GetDisasm(head)
                for tag in API_List.items():
                    for i in tag[1]:
                        if i in assem:
                            MakeName(startea, tag[0] + "_" + functionName)

class function_rename(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

    def OnClose(self, form):
        pass
        
class Func_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IDA Function Rename"
    help = "help"
    wanted_name = "IDA Function Rename"
    wanted_hotkey = "Ctrl+Shift+F"

    def init(self):
        idaapi.msg("YaraGenerator\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = function_rename()
        plg.Show("function_rename")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return Func_Plugin()


