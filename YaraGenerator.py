
from idaapi import PluginForm
from PyQt5.QtWidgets import QTableWidgetItem, QTableWidget, QLineEdit, QPlainTextEdit, QPushButton, QLabel, QVBoxLayout, QGridLayout
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt

class YaraGenerator(PluginForm):

    def YaraExport(self):
        result = ""
        result += "rule " + self.Variable_name.text() + "\n{\n"
        result += "  strings:\n"
        for idx, name in enumerate(self.ruleset_list.keys()):
            result += "      "
            result += "$"+name +" = " + self.ruleset_list[name][0]+"\n"
        result += "  condition:\n"
        result += "      all of them\n"
        result += "}"
        self.TextEdit1.clear()
        self.TextEdit1.insertPlainText(result)

    def DeleteRule(self):
        self.ruleset_list = {}
        self.tableWidget.setRowCount(len(self.ruleset_list.keys()))
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Variable_name", "Rule", "Start", "End"])
        for idx, name in enumerate(self.ruleset_list.keys()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(name))
            self.tableWidget.setItem(idx, 1, QTableWidgetItem(self.ruleset_list[name][0]))
            self.tableWidget.setItem(idx, 2, QTableWidgetItem(self.ruleset_list[name][1]))
            self.tableWidget.setItem(idx, 3, QTableWidgetItem(self.ruleset_list[name][2]))
        self.layout.addWidget(self.tableWidget)


    def MakeRule(self):
        ByteCode = []
        start = int(self.StartAddress.text(), 16)
        end = int(self.EndAddress.text(), 16)

        while(start < end):
            data = hex(Byte(start))[2:].upper()
            if len(data) == 1:
                data = "0"+data
            ByteCode.append(data)
            start += 1
        self.TextEdit1.clear()
        self.TextEdit1.insertPlainText("{" + ' '.join(ByteCode) + "}")

    def SaveRule(self):
        self.ruleset_list[self.Variable_name.text()] = [self.TextEdit1.toPlainText(), self.StartAddress.text(), self.EndAddress.text()]
        self.tableWidget.setRowCount(len(self.ruleset_list.keys()))
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Variable_name", "Rule", "Start", "End"])
        for idx, name in enumerate(self.ruleset_list.keys()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(name))
            self.tableWidget.setItem(idx, 1, QTableWidgetItem(self.ruleset_list[name][0]))
            self.tableWidget.setItem(idx, 2, QTableWidgetItem(self.ruleset_list[name][1]))
            self.tableWidget.setItem(idx, 3, QTableWidgetItem(self.ruleset_list[name][2]))
        self.layout.addWidget(self.tableWidget)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.ruleset_list = {}
        self.label1 = QLabel("Variable name : ")
        self.Variable_name = QLineEdit()
        self.label2 = QLabel("Start Address : ")
        self.StartAddress = QLineEdit()
        self.label3 = QLabel("End Address : ")
        self.EndAddress = QLineEdit()
        self.TextEdit1 = QPlainTextEdit()

        self.MakeButton = QPushButton("Make")
        self.MakeButton.clicked.connect(self.MakeRule)
        self.SaveButton = QPushButton("Save")
        self.SaveButton.clicked.connect(self.SaveRule)
        self.DeleteButton = QPushButton("Delete")
        self.DeleteButton.clicked.connect(self.DeleteRule)
        self.YaraExportButton = QPushButton("Export Yara Rule")
        self.YaraExportButton.clicked.connect(self.YaraExport)

        self.layout = QVBoxLayout()

        GL1 = QGridLayout()
        GL1.addWidget(self.label1, 0, 0)
        GL1.addWidget(self.Variable_name, 0, 1)
        self.layout.addLayout(GL1)

        GL2 = QGridLayout()
        GL2.addWidget(self.label2, 0, 1)
        GL2.addWidget(self.StartAddress, 0, 2)
        GL2.addWidget(self.label3, 0, 3)
        GL2.addWidget(self.EndAddress, 0, 4)
        self.layout.addLayout(GL2)

        self.layout.addWidget(self.TextEdit1)

        GL3 = QGridLayout()
        GL3.addWidget(self.MakeButton, 0, 0)
        GL3.addWidget(self.SaveButton, 0, 1)
        GL3.addWidget(self.DeleteButton, 0, 2)
        GL3.addWidget(self.YaraExportButton, 0, 3)
        self.layout.addLayout(GL3)

        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(len(self.ruleset_list.keys()))
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Variable_name", "Rule", "Start", "End"])
        for idx, name in enumerate(self.ruleset_list.keys()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(name))
            self.tableWidget.setItem(idx, 1, QTableWidgetItem(self.ruleset_list[name][0]))
            self.tableWidget.setItem(idx, 2, QTableWidgetItem(self.ruleset_list[name][1]))
            self.tableWidget.setItem(idx, 3, QTableWidgetItem(self.ruleset_list[name][2]))
        self.layout.addWidget(self.tableWidget)

        self.parent.setLayout(self.layout)

    def OnClose(self, form):
        pass

class YaraPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is YaraGenerator"
    help = "help"
    wanted_name = "Yara_Generator"
    wanted_hotkey = "Ctrl+Y"

    def init(self):
        idaapi.msg("YaraGenerator")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = YaraGenerator()
        plg.Show("YaraGenerator")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return YaraPlugin()