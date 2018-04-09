import idautils
import idaapi
import re
import urllib
import json
import socket
import requests

def GeoIP(IP):
    response = urllib.urlopen("http://freegeoip.net/json/"+IP).read().decode("utf-8")
    try:
        result = json.loads(response)['country_name']
    except:
        result = "Not Found"
    return result

class comment(object):
    def __init__(self):
        self.data = {}
        self.variable = ""

    def save_strings(self):
        sc = idautils.Strings()
        for s in sc:
            for Xref in XrefsTo(s.ea, flags=0):
                self.data[Xref.frm] = []
            for Xref in XrefsTo(s.ea, flags=0):
                ea = Xref.frm
                cfunc = idaapi.decompile(ea)
                tl = idaapi.treeloc_t()
                tl.ea = ea
                tl.itp = idaapi.ITP_SEMI
                if "offset" in GetOpnd(ea, 0):
                    self.variable = GetOpnd(ea, 0).split(" ")
                    self.variable = self.variable[1]
                elif "offset" in GetOpnd(ea, 1):
                    self.variable = GetOpnd(ea, 1).split(" ")
                    self.variable = self.variable[1]
                else:
                    self.variable = ""

                try:
                    self.data[Xref.frm].append(str(unicode(s)))
                    #MakeComm(Xref.frm, str(unicode(s)))
                    IP = re.search("\d+[.]\d+[.]\d+[.]\d+", str(unicode(s)))
                    URL = re.search("www[.]\w+[.]\w+", str(unicode(s)))
                except:
                    pass

                if not IP == None:
                    result = GeoIP(IP.group())
                    print ("Address : " + str(hex(ea)) + " " + IP.group() + " -> " + result)
                    MakeComm(Xref.frm, str(IP.group() + " -> " + result))
                    print("[*] Assembly Code Commented successfully")
                    try:
                        cfunc.set_user_cmt(tl, self.variable + " : " + str(IP.group() + " -> " + result))
                        cfunc.save_user_cmts()
                        print("[*] Pseudocode Commented successfully")
                    except AttributeError:
                        print("[*] Don't have pseudocode")
                        pass

                elif not URL == None:
                    try:
                        IP_data = socket.gethostbyname(URL.group().replace("http://",""))
                        IP_data = GeoIP(IP_data)
                    except:
                        IP_data = "Not found"

                    print ("Address : " + str(hex(ea)) + " " + URL.group() + " -> " + IP_data)
                    MakeComm(Xref.frm, str(URL.group() + " -> " + IP_data))
                    print("[*] Assembly Code Commented successfully")
                    try:
                        cfunc.set_user_cmt(tl, self.variable + " : " + str(URL.group() + " -> " + IP_data))
                        cfunc.save_user_cmts()
                        print("[*] Pseudocode Commented successfully")
                    except AttributeError:
                        print("[*] Don't have pseudocode")
                        pass

                else:
                    try:
                        cfunc.set_user_cmt(tl, self.variable + " : " + str(unicode(s))) 
                        cfunc.save_user_cmts()
                        print("[*] Pseudocode Commented successfully")
                    except AttributeError:
                        print("[*] Don't have pseudocode")
                        pass


if __name__ == "__main__":
    a = comment()
    a.save_strings()