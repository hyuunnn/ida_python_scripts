import idaapi
import idautils
import sqlite3
import os

Library_cnt = idaapi.get_import_module_qty()
Library_name_lists = []
Library_lists = {}
Xref_list = []

def imp_cb(ea, name, ord):
    global api_count, Library_count
    if not name:
        name = ''
    Library_lists[Library_name].append([ea, name])
    return ([ea, name, ord])

for i in range(0, Library_cnt):
    Library_name = idaapi.get_import_module_name(i)
    Library_name_lists.append(Library_name)
    Library_lists[Library_name] = []
    idaapi.enum_import_names(i, imp_cb)
if os.path.exists("C://api_visualization//data.db"):
    os.remove("C://api_visualization//data.db")
con = sqlite3.connect("C://api_visualization//data.db")
cursor = con.cursor()

for i in Library_name_lists:
    cursor.execute("CREATE TABLE "+i+" (Address text, API_name text, count int)")
    for address, name in Library_lists[i]:
        for Xref in XrefsTo(address, flags=0):
            Xref_list.append(Xref.frm)
        Xref_list = list(set(Xref_list))
        cursor.execute("INSERT INTO "+i+" VALUES (?, ?, ?);", (hex(address), name, len(Xref_list)))
        Xref_list = []
con.commit()
con.close()

print ("[*] DB file creation completed")