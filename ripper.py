from contextlib import contextmanager
from enum import IntEnum, auto

import click
import orjson
from attrs import asdict, define, field
from cpp_demangle import demangle
from elftools.elf import elffile
from elftools.elf.sections import SymbolTableSection


class NamespaceEnum(IntEnum):
    NONE = auto()
    STD = auto()
    COCOS2D = auto()
    PUGI = auto()



# I use arm arch to reverse engineer Geometry Dash so to help we assume 
# were setting arguments in order from doing r0, r1, r2, r3 and 
# then STACK[0x0] and so on and so forth...
class OffsetCounter:
    def __init__(self) -> None:
        self.i = 0
        self.stack_val = 0

    def next(self):
        if self.i < 4:
            rvalue = "r%i" % self.i
            self.i += 1
            return rvalue
        # Move to stack...
        stack_value = "STACK[%s]" % hex(self.stack_val * 4)
        self.stack_val += 1
        return stack_value



def split_cpp_args(data:str) -> list[str]:
    args = []
    # Bytearrays are perfect for buffer writing 
    b = bytearray()
    followed_by = 0
    for d in data:
        if d == "<":
            followed_by += 1
            b.append(ord(d))
        elif d == ">":
            followed_by -= 1
            b.append(ord(d))
        elif d == "," and followed_by == 0:
            args.append(b.decode().strip())
            b.clear()
        else:
            b.append(ord(d))
    if b:
        args.append(b.decode().strip())
    return args


@define
class Function:
    mangled_func:str
    demangled_func:str = field(init=False)
    args:list[str] = field(init=False, factory=list)
    namespaceEnum:NamespaceEnum = field(init=False)
    namespaceName:str = field(init=False)
    arg_offsets:dict[str, str] = field(init=False, factory=dict)

    def _find_namespace(self, func:str):
        if func.startswith("cococs2d::"):
            return NamespaceEnum.COCOS2D
        elif func.startswith("std::"):
            return NamespaceEnum.STD
        elif func.startswith("pugi::"):
            return NamespaceEnum.PUGI
        return NamespaceEnum.NONE

    def _is_this_call(self, func:str):
        """Used to try and determine if we have a thiscall, NOTE: False-Positives will happen"""
        if self.namespaceEnum != NamespaceEnum.NONE or len(func.split("::")) >= 2:
            return True
        return False

    def _demangle_arguments(self, func:str):
        if "{" in func:
            func = func.lstrip("{").rstrip("}").split(",", 1)[-1]
            data = func.split("(", 1)[-1].rsplit(")",1)[0]
            return split_cpp_args(data.rstrip(")"))
        if "(" in func:
            return split_cpp_args(func.split("(", 1)[-1].rsplit(")",1)[0])
        return []

    def _make_possible_arg_offsets(self):
        """Writes off possible ARM offsets for parameters """
        counter = OffsetCounter()

        d = dict()
        if self._is_this_call:
            # Move as if this were a thiscall...
            d[counter.next()] = "this" 
            # print(self.args)
            d.update({counter.next():a.strip() for a in self.args})
            # d.pop("")
            return d
        else:
            d = {counter.next():a.strip() for a in self.args}
            # d.pop("")
            return d
        
    def __attrs_post_init__(self):
        # print(self.mangled_func)
        try:
            self.demangled_func = demangle(self.mangled_func)
            self.args = self._demangle_arguments(self.demangled_func)
            self.namespaceEnum = self._find_namespace(self.demangled_func)
            self.namespaceName = self.namespaceEnum.name.lower()
            self.arg_offsets = self._make_possible_arg_offsets()
        except ValueError:
            self.demangled_func = "FAILED"
            self.args = []
            self.namespaceEnum = NamespaceEnum.NONE
            self.namespaceName = "none"


@define 
class ELF:
    functions:list[Function] = []
    version:str = "2.205"

    def as_json(self):
        """Converts ELF File Information into a Json File..."""
        return orjson.dumps({
            "functions": asdict(self)['functions'], 
            "total_functions": len(self.functions),
            "gd-version":self.version
            }, option=orjson.OPT_INDENT_2
        )

    def add_func(self, func:str):
        f = Function(func)
        if any([a.startswith("std::__exception_ptr") for a in f.args]) or f.demangled_func.startswith(("typeinfo name for ", "typeinfo for ", "{vtable")):
            # skip, it's not worth the effort or time to screw around with 
            return
        self.functions.append(f)
    

@contextmanager
def open_elf(filename:str):
    yield elffile.ELFFile.load_from_path(filename)



@click.command()
@click.option("--filename", "-f", default="libcocos2dcpp.so")
@click.option("--output", "-o", default="libcocos2dcpp.so", help="The default json to output to")
@click.option("--version", "-v", default="2.2074", help="the version of geometry dash being looked at")
def cli(filename:str, output:str,version:str):
    """Used to parse geometry dash ELF Files and convert them to json files to later to used to convert to broma or used with ghidra as helpful info..."""
    print("parsing andriod symbols...")
    elf = ELF([], version=version)
    with open_elf(filename) as so:
        for sec in so.iter_sections():
            if hasattr(sec, "symboltable"):
                table: SymbolTableSection = sec.symboltable
                for s in table.iter_symbols():
                    if s.name.startswith("_Z"):
                        elf.add_func(s.name)
    with open(output +"."+ version + ".json","wb") as wb:
        wb.write(elf.as_json())
    print("done!")

if __name__ == "__main__":
    cli()


