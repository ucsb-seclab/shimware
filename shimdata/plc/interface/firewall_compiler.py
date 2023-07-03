import io
import yaml
import time
import struct


def compile_firewall_from_files(filter_descs_fn, in_fn, out_fn):
    with open(filter_descs_fn, "r") as f:
        filter_descs = yaml.safe_load(f)
    with open(in_fn, "r") as f:
        parsed = yaml.safe_load(f)

    fw = Firewall(filter_descs)
    for rule in parsed:
        fw.add_rule(rule)
    res = fw.pack()
    with open(out_fn, "wb") as f:
        f.write(res)

class ArgumentDescriptor:
    def __init__(self, filter_obj, name, arg_type):
        self.filter_obj = filter_obj
        self.name = name
        self.arg_type = arg_type

    def implement(self, value):
        return Argument(self, value)

class Argument:
    TYPE_TO_STRUCT_CHAR = {"uint8_t":  "B",
                           "uint16_t": "H",
                           "uint32_t": "I",
                           "uint64_t": "Q",
                           "int8_t":   "b",
                           "int16_t":  "h",
                           "int32_t":  "i",
                           "int64_t":  "q"}

    def __init__(self, arg_desc, value):
        self.argument_descriptor = arg_desc
        self.name = arg_desc.name
        self.arg_type = arg_desc.arg_type
        self.filter_obj = arg_desc.filter_obj
        self.value = self._parse(value)

    def _parse(self, value):
        if self.arg_type in self.TYPE_TO_STRUCT_CHAR:
            if isinstance(value, int) or isinstance(value, float):
                return value
            try:
                return int(value, 0)
            except ValueError:
                pass
            return self._parse(self.filter_obj.resolve_symbol(value))
        elif self.arg_type == "string_offset":
            return value.encode("ascii")
        elif self.arg_type == "tag_v":
            if isinstance(value, int) or isinstance(value, float):
                return value
            try:
                return int(value, 0)
            except ValueError:
                pass
            try:
                return float(value)
            except ValueError:
                pass

            raise ValueError("Unable to parse expression as tag value: %r" % (value,))
        else:
            raise ValueError("Unhandled type: %r" % (self.arg_type,))

    def pack(self, extra_data):
        if self.arg_type in self.TYPE_TO_STRUCT_CHAR:
            return struct.pack("<" + self.TYPE_TO_STRUCT_CHAR[self.arg_type], self.value)
        elif self.arg_type == "string_offset":
            pos = extra_data.tell()
            extra_data.write(self.value + b"\x00")
            return struct.pack("<I", pos)
        elif self.arg_type == "tag_v":
            if isinstance(self.value, int):
                return struct.pack("<q", self.value)
            elif isinstance(self.value, float):
                return struct.pack("<f", self.value)

            raise ValueError("Unable to pack value as tag value: %r" % (self.value,))
        else:
            raise ValueError("Unhandled type: %r" % (self.arg_type,))

class Filter:
    def __init__(self, name, filter_desc):
        self.name = name
        self.index = filter_desc["index"]
        self.enums = filter_desc.get("enums", {})
        self.params = []
        for param in filter_desc.get("params", ()):
            self.params.append(ArgumentDescriptor(self, param["name"], param["type"]))

    def resolve_symbol(self, symbol):
        return self.enums[symbol]

class FirewallRule:
    ACTIONS = {
        "CONTINUE": 0,
        "DROP": 1,
        "ACCEPT": 2
    }

    RULE_FORMAT = struct.Struct("<HIBBB")
    def __init__(self, rule_desc, filter_obj):
        self.filter_obj = filter_obj
        self.on_error = self.ACTIONS[rule_desc.get("on_error", "CONTINUE")]
        self.on_nomatch = self.ACTIONS[rule_desc.get("on_nomatch", "CONTINUE")]
        self.on_match = self.ACTIONS[rule_desc.get("on_match", "CONTINUE")]
        args = rule_desc.get("args", ())
        if len(args) != len(filter_obj.params):
            raise ValueError("Incorrect number of arguments passed to %r: Expected %d, got %d" \
                             % (self.filter_obj.name,
                                len(filter_obj.params),
                                len(rule_desc["args"])))
        self.args = []
        for val, arg_desc in zip(args, filter_obj.params):
            self.args.append(arg_desc.implement(val))

    def pack(self, args_data, extra_data):
        base = args_data.tell()
        for arg in self.args:
            args_data.write(arg.pack(extra_data))
        return self.RULE_FORMAT.pack(self.filter_obj.index, base,
                                     self.on_error, self.on_nomatch, self.on_match)

class Firewall:
    HEADER_FORMAT = struct.Struct("<4sQHIII")
    MAGIC = b"FWO\n"
    def __init__(self, filter_descs):
        self.rules = []
        self.packed_rules = io.BytesIO()
        self.args_data = io.BytesIO()
        self.extra_data = io.BytesIO()
        self.filters = {}
        for filter_name, filter_desc in filter_descs["filters"].items():
            self.filters[filter_name] = Filter(filter_name, filter_desc)

    def add_rule(self, rule_desc):
        if rule_desc["filter"] not in self.filters:
            raise ValueError("Unable to find filter: %r" % (rule_desc["filter"],))
        filt = self.filters[rule_desc["filter"]]
        rule = FirewallRule(rule_desc, filt)
        self.rules.append(rule)
        self.packed_rules.write(rule.pack(self.args_data, self.extra_data))

    def pack(self):
        packed_rules_raw = self.packed_rules.getvalue()
        args_data_raw = self.args_data.getvalue()
        extra_data_raw = self.extra_data.getvalue()

        pos = 0
        pos += self.HEADER_FORMAT.size
        packed_rules_pos = pos
        pos += len(packed_rules_raw)
        args_data_pos = pos
        pos += len(args_data_raw)
        extra_data_pos = pos

        header_raw = self.HEADER_FORMAT.pack(self.MAGIC, int(time.time()),
                                             len(self.rules),
                                             packed_rules_pos,
                                             args_data_pos,
                                             extra_data_pos)
        return header_raw + packed_rules_raw + args_data_raw + extra_data_raw

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: %s <filter descriptor yaml> <input yaml> <output filename>" % (sys.argv[0],))
        sys.exit(1)

    compile_firewall_from_files(sys.argv[1], sys.argv[2], sys.argv[3])
