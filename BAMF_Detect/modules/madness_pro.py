from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata
from base64 import b64decode
from re import match
from string import ascii_lowercase, ascii_uppercase, digits


class madness_pro(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="madnesspro",
            bot_name="Madness Pro",
            description="Distributed Denial of Service botnet capable of various attacks",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="March 14, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("madnesspro.yara")
        return self.yara_rules

    @staticmethod
    def bdecode(key):
        key = key.replace("^", "j")
        key = key.replace("@", "H")
        key = key.replace("*", "d")
        key = b64decode(key)
        return key

    @staticmethod
    def parse_madness_pro_config(key):
        key = madness_pro.bdecode(key)
        key = key[len("apoKALiplis=uebok"):]
        if key[0] == key[1] == key[2]:
            tkey = ""
            for x in range(0, len(key)):
                if x % 3 == 0:
                    tkey += key[x]
            key = tkey
        return {"c2_uri": key[:-len("0fe9bdh")], "mk": key[-len("0fe9bdh"):][:-1]}

    def get_bot_information(self, file_data):
        results = {}
        for s in data_strings(file_data, charset=ascii_lowercase + ascii_uppercase + digits + "=+/^@*"):
            if s[:len("YXBvS0")] == "YXBvS0":
                c = madness_pro.parse_madness_pro_config(s)
                for key in c:
                    results[key] = unicode(c[key], errors='ignore')
            else:
                try:
                    ret = madness_pro.bdecode(s)
                    if match(r'^\d\.\d\d$', ret) is not None:
                        results["version"] = ret
                except:
                    pass
        return results

Modules.list.append(madness_pro())