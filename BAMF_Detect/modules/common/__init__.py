from string import printable
from yara import compile
from os.path import dirname, join, abspath
from pefile import PE
from tempfile import mkstemp
from os import write, close, remove
from subprocess import Popen, PIPE


class ModuleMetadata(object):
    def __init__(self, module_name, bot_name, description, authors, date, version, references):
        self.module_name = module_name
        self.bot_name = bot_name
        self.description = description
        self.authors = authors
        self.date = date
        self.version = version
        self.references = references

    def __str__(self):
        return "%s (%s %s) - %s" % (self.bot_name, self.module_name, self.version, self.description)


class BinParseModule(object):
    def __init__(self, metadata, data_type):
        self.data_type = data_type
        self.metadata = metadata

    def get_datatype(self):
        return self.data_type

    def get_metadata(self):
        return self.metadata

    def get_module_name(self):
        return self.metadata.module_name

    def get_bot_name(self):
        return self.metadata.bot_name

    def _generate_yara_rules(self):
        return None

    def is_bot(self, file_data):
        rules = self._generate_yara_rules()
        if rules is None:
            return None
        return len(rules.match(data=file_data)) != 0

    def get_bot_information(self, file_data):
        return None


class PEParseModule(BinParseModule):
    def __init__(self, metadata):
        BinParseModule.__init__(self, metadata, "PE")


class PHPParseModule(BinParseModule):
    def __init__(self, metadata):
        BinParseModule.__init__(self, metadata, "PHP")


class Modules:
    list = []


def data_strings_wide(data, min=4, charset=printable):
    result = ""
    needs_null = False
    for c in data:
        if needs_null and c == "\x00":
            needs_null = False
            continue
        elif c in charset and not needs_null:
            result += c
            needs_null = True
            continue
        needs_null = False
        if len(result) >= min:
            yield result
        result = ""
    if len(result) >= min:
        yield result


def data_strings(data, min=4, charset=printable):
    result = ""
    for c in data:
        if c in charset:
            result += c
            continue
        if len(result) >= min:
            yield result
        result = ""
    if len(result) >= min:
        yield result


def is_upx_compressed(data):
    pe = PE(data=data)
    for entry in pe.sections:
        if entry.Name.startswith("UPX0") or entry.Name.startswith("UPX1"):
            return True
    return False


def decompress_upx(file_data):
    file_handle, path = mkstemp()
    write(file_handle, file_data)
    close(file_handle)
    p = Popen(['upx', '-d', path], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    with open(path, "rb") as f:
        file_data = f.read()
    remove(path)
    return file_data


def load_yara_rules(name):
    return compile(join(dirname(abspath(__file__)), "..", "yara", name))