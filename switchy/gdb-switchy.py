#!/usr/bin/python3

import gdb

for i in range(0x080484A0, 0x080486A8 + 0x1A, 0x1A):
    gdb.Breakpoint("*0x%08x" % i)

# redirect program output to /dev/null so that it doesn't display garbage and
# mess up the terminal
gdb.execute("run > /dev/null", False, True)

flag = ""

for i in range(34):
    eax = gdb.parse_and_eval("$eax")
    flag += chr(eax)
    gdb.execute("continue", False, True)

print(flag)
