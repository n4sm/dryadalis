import gdb
import colorama
import struct

import time

def get_rip() -> int:
    s = gdb.execute("p/x $rip", to_string=True)
    return int(s[s.find(' = ')+3:len(s)-2], 16)

def get_instruction() -> str:
    s = gdb.execute("x/i $rip", to_string=True)
    return s[s.find(':\t')+2:]

class dryadalis_trace(GenericCommand):
    """trace utils to dump all instructions"""
    _cmdline_ = "dryadalis_trace"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.fd = open("gdb_trace", 'w')
        buf = []
        while get_rip():
            buf.append(get_instruction())
            print(get_instruction())

            if len(buf) == 1024:
                self.fd.write("".join(buf))
                buf.clear()

            gdb.execute("si")
            time.sleep(0.01) # mandatory 

if __name__ == "__main__":
    register_external_command(dryadalis_trace())