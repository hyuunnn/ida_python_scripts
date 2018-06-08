from idaapi import PluginForm
from PyQt5.QtWidgets import QCheckBox, QTableWidgetItem, QFileDialog, QTableWidget, QLineEdit, QPlainTextEdit, QPushButton, QLabel, QVBoxLayout, QGridLayout
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt
from os.path import expanduser

import os
import yara
import binascii
import time

class YaraChecker(PluginForm):
    def choose_path(self):
        path = QFileDialog.getExistingDirectory(
            self.parent,
            "Open a folder",
            expanduser("~"),
            QFileDialog.ShowDirsOnly)
        self.path.setText(path)

    def Search(self):
        rule = yara.compile(source=self.TextEdit1.toPlainText())
        result = {}
        for i in os.walk(self.path.text()):
            for j in i[2]:
                f = open(i[0] + "\\" + j, "rb")
                data = f.read()
                matches = rule.match(data=data)
                f.close()
                for match in matches:
                    strings = match.strings[0]
                    result[os.path.basename(j)] = [i[0], hex(strings[0]).replace("L",""), strings[1], strings[2]]
        self.tableWidget.setRowCount(len(result.keys()))
        
        for idx, filename in enumerate(result.keys()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(result[filename][0]))
            self.tableWidget.setItem(idx, 1, QTableWidgetItem(filename))
            self.tableWidget.setItem(idx, 2, QTableWidgetItem(result[filename][1]))
            self.tableWidget.setItem(idx, 3, QTableWidgetItem(result[filename][2]))
            self.tableWidget.setItem(idx, 4, QTableWidgetItem(result[filename][3]))
        self.layout.addWidget(self.tableWidget)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.label1 = QLabel("Search Path")
        self.path = QLineEdit()
        self.PathButton = QPushButton("path")
        self.PathButton.clicked.connect(self.choose_path)        
        self.label2 = QLabel("Yara rule")
        self.TextEdit1 = QPlainTextEdit()
        self.TextEdit1.insertPlainText(self.data)
        self.SearchButton = QPushButton("Search")
        self.SearchButton.clicked.connect(self.Search)

        self.layout = QVBoxLayout()
        GL1 = QGridLayout()
        GL1.addWidget(self.path, 0, 0)
        GL1.addWidget(self.PathButton, 0, 1)
        self.layout.addLayout(GL1)

        self.layout.addWidget(self.label2)
        self.layout.addWidget(self.TextEdit1)
        self.layout.addWidget(self.SearchButton)

        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(5)
        self.tableWidget.setHorizontalHeaderLabels(["Path", "Filename", "Address", "Variable_name", "String"])
        self.layout.addWidget(self.tableWidget)
        self.parent.setLayout(self.layout)

    def OnClose(self, form):
        pass


class YaraGenerator(PluginForm):
    def YaraExport(self):
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif info.is_32bit():
            md = Cs(CS_ARCH_X86, CS_MODE_32)

        result = ""
        result += "rule " + self.Variable_name.text() + "\n{\n"
        result += "  meta:\n"
        result += "      tool = \"https://github.com/hy00un/ida_python_scripts/blob/master/YaraGenerator.py\"\n"
        result += "      date = \"" + time.strftime("%Y-%m-%d") + "\"\n"
        result += "      MD5 = \"" + GetInputFileMD5() + "\"\n"
        result += "  strings:\n"
        for idx, name in enumerate(self.ruleset_list.keys()):
            CODE = bytearray.fromhex(self.ruleset_list[name][0][1:-1].strip().replace("\\x"," "))
            if self.CheckBox1.isChecked():
                result += "      /*\n"
                for idx, i in enumerate(md.disasm(CODE, 0x1000)):
                    result += "          {0}\t{1}\t\t\t\t\t|{2}".format(i.mnemonic.upper(), i.op_str.upper().replace("0X","0x"), self.ByteCode[idx].upper()) + "\n"
                result += "      */\n"

            # if self.CheckBox2.isChecked(): # yara wildcard isChecked()
            result += "      $"+name +" = " + self.ruleset_list[name][0]+"\n"
        result += "  condition:\n"
        result += "      all of them\n"
        result += "}"
        self.TextEdit1.clear()
        self.TextEdit1.insertPlainText(result)

    def DeleteRule(self):
        if idaapi.ask_yn(idaapi.ASKBTN_NO, "Delete Yara Rule"):
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
        self.ByteCode = []
        start = int(self.StartAddress.text(), 16)
        end = int(self.EndAddress.text(), 16)

        while start <= end:
            sub_end = NextHead(start)
            data = binascii.hexlify(GetManyBytes(start, sub_end-start))
            self.ByteCode.append(data)
            start = sub_end

        self.TextEdit1.clear()
        self.TextEdit1.insertPlainText("{" + ''.join(self.ByteCode) + "}")

    def SaveRule(self):
        #info = idaapi.get_inf_structure()
        #if info.is_64bit():
        #    md = Cs(CS_ARCH_X86, CS_MODE_64)
        #elif info.is_32bit():
        #    md = Cs(CS_ARCH_X86, CS_MODE_32)
        #CODE = bytearray.fromhex(self.TextEdit1.toPlainText()[1:-1].strip().replace("\\x"," "))
        #for i in md.disasm(CODE, 0x1000):
        #    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

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

    def YaraChecker(self):
        self.YaraChecker = YaraChecker()
        self.YaraChecker.data = self.TextEdit1.toPlainText()
        self.YaraChecker.Show("YaraChecker")

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.ruleset_list = {}
        self.label1 = QLabel("Variable name : ")
        self.label_1 = QLabel("comment option")
        self.CheckBox1 = QCheckBox()
        self.label_2 = QLabel("wildcard option")
        self.CheckBox2 = QCheckBox()
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
        self.YaraCheckerButton = QPushButton("Yara Checker")
        self.YaraCheckerButton.clicked.connect(self.YaraChecker)

        self.layout = QVBoxLayout()

        GL1 = QGridLayout()
        GL1.addWidget(self.label1, 0, 0)
        GL1.addWidget(self.Variable_name, 0, 1)
        GL1.addWidget(self.label_1 , 0, 2)
        GL1.addWidget(self.CheckBox1, 0, 3)
        GL1.addWidget(self.label_2 , 0, 4)
        GL1.addWidget(self.CheckBox2, 0, 5)
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
        GL3.addWidget(self.YaraCheckerButton, 0, 4)
        self.layout.addLayout(GL3)

        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Variable_name", "Rule", "Start", "End"])
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
        idaapi.msg("YaraGenerator\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = YaraGenerator()
        plg.Show("YaraGenerator")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return YaraPlugin()