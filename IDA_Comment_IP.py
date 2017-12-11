import idautils
import idaapi
import re
import urllib
import json

def GeoIP(IP):
    response = urllib.urlopen("http://freegeoip.net/json/"+IP).read().decode("utf-8")
    try:
        result = json.loads(response)
        result = result['country_name']
    except ValueError:
        result = " "
    return result

IP = ""
URL = ""
a = {}
sc = idautils.Strings()
for s in sc:
    for Xref in XrefsTo(s.ea, flags=0):
        a[Xref.frm] = []
    for Xref in XrefsTo(s.ea, flags=0):
        ea = Xref.frm
        cfunc = idaapi.decompile(ea)
        tl = idaapi.treeloc_t()
        tl.ea = ea
        tl.itp = idaapi.ITP_SEMI
        if(GetOpnd(ea,0).find("offset")!=-1):
            variable = GetOpnd(ea,0).split(" ")
            variable = variable[1]
        if(GetOpnd(ea,1).find("offset")!=-1):
            variable = GetOpnd(ea,1).split(" ")
            variable = variable[1]
        try:
            a[Xref.frm].append(str(unicode(s)))
            #MakeComm(Xref.frm, str(unicode(s)))
            IP = re.search("\d+[.]\d+[.]\d+[.]\d+", str(unicode(s)))
            URL = re.search("www[.]\w+[.]\w+", str(unicode(s)))
        except:
            pass

        if IP != None:
            print "Address : "+str(hex(ea))+" "+IP.group() + " -> " + GeoIP(IP.group())
            MakeComm(Xref.frm, str(IP.group() + " -> " + GeoIP(IP.group())))
            print("[*] Assembly Code Commented successfully")
            try:
                cfunc.set_user_cmt(tl, variable+" : "+str(IP.group() + " -> " + GeoIP(IP.group())))
                cfunc.save_user_cmts()
                print("[*] Pseudocode Commented successfully")
            except AttributeError:
                print("[*] Don't have pseudocode")
                pass
        elif URL != None:
            print "Address : "+str(hex(ea))+" "+URL.group() + " -> " + GeoIP(URL.group()[4:])
            MakeComm(Xref.frm, str(URL.group() + " -> " + GeoIP(URL.group()[4:])))
            print("[*] Assembly Code Commented successfully")
            try:
                cfunc.set_user_cmt(tl, variable+" : "+str(URL.group() + " -> " + GeoIP(URL.group()[4:])))
                cfunc.save_user_cmts()
                print("[*] Pseudocode Commented successfully")
            except AttributeError:
                print("[*] Don't have pseudocode")
                pass
        else:
            try:
                cfunc.set_user_cmt(tl, variable+" : "+str(unicode(s))) 
                cfunc.save_user_cmts()
                print("[*] Pseudocode Commented successfully")
            except AttributeError:
                print("[*] Don't have pseudocode")
                pass
            #MakeComm(Xref.frm, str(unicode(s)))

'''

 try:
    cfunc = idaapi.decompile(func)
except idaapi.DecompilationFailure:
    return False

'''