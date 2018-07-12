from idaapi import *
from idc import *
from idautils import *
from PyQt5.QtWidgets import QCheckBox, QTableWidgetItem, QFileDialog, QTableWidget, QLineEdit, QPlainTextEdit, QPushButton, QLabel, QVBoxLayout, QGridLayout
from PyQt5.QtGui import QColor, QTextCharFormat, QFont, QSyntaxHighlighter, QPixmap
from PyQt5.QtCore import QRegExp, Qt

result = {} # [Function Name] = [Start Address, End Address, Execute Count, Message Count, Change Count]

API_List = {
            'Execute':["ShellExecute"],
            'Message':["MessageBox"],
            'Change':["GetModuleFileName"],
            'Create':["GetTempPath", "CreateDirectory"]
        }

class function_rename(PluginForm):
    def jump_code(self, row, column):
        jumpto(int(self.tableWidget.item(row,1).text().replace("L",""), 16))

    def OnCreate(self, form):
        # https://reverseengineering.stackexchange.com/questions/14725/using-ida-python-iterate-through-all-functions-and-their-instructions
        for segea in Segments():
            for funcea in Functions(segea, SegEnd(segea)):
                functionName = GetFunctionName(funcea)
                a = [(startea, endea) for startea, endea in Chunks(funcea)]
                result[functionName] = [hex(a[0][0]), hex(a[0][1]), 0, 0, 0, 0] ### add count data
                for (startea, endea) in Chunks(funcea):
                    for head in Heads(startea, endea):
                        assem = GetDisasm(head)
                        for tag in API_List.items():
                            for i in tag[1]:
                                if i in assem:
                                    MakeName(startea, tag[0] + "_" + functionName)
                                    if tag[0] == "Execute":
                                        result[functionName][2] += 1
                                    if tag[0] == "Message":
                                        result[functionName][3] += 1
                                    if tag[0] == "Change":
                                        result[functionName][4] += 1
                                    if tag[0] == "Create":
                                        result[functionName][5] += 1
                                    ### add if count data

        for i in result.items():
            if i[1][2] == 0 and i[1][3] == 0 and i[1][4] == 0 and i[1][5] == 0: ### add if loop
                del result[i[0]]

        datalist = ["Function Name", "startEA","endEA"]
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QVBoxLayout()
        self.tableWidget = QTableWidget()
        for i in API_List.keys():
            datalist.append(i)

        self.tableWidget.setRowCount(len(result))
        self.tableWidget.setColumnCount(len(datalist))
        self.tableWidget.setHorizontalHeaderLabels(datalist)
        for idx, data in enumerate(result.items()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(data[0]))
            for count, i in enumerate(data[1]):
                count2 = count + 1
                self.tableWidget.setItem(idx, count2, QTableWidgetItem(str(i)))
        self.tableWidget.cellDoubleClicked.connect(self.jump_code)
        self.layout.addWidget(self.tableWidget)
        self.parent.setLayout(self.layout)

    def OnClose(self, form):
        pass
        
class Func_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IDA Function Rename"
    help = "help"
    wanted_name = "IDA Function Rename"
    wanted_hotkey = "Ctrl+Shift+F"

    def init(self):
        idaapi.msg("IDA Function Rename\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = function_rename()
        plg.Show("function_rename")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return Func_Plugin()


