#!/usr/bin/python

import os, collections

flag = "flag{switch jump pogo pogo bounce}";

# generate header

header = open("switchy.h", "wb")

counter = collections.Counter(flag)
freq = counter.most_common()
charlist = [x[0] for x in freq]

# real chars and random junk chars alternating
for i in xrange(len(charlist)):
    char = charlist[i]
    header.write("char char%d = 0x%02x;\n" % (i, ord(char)))
    header.write("char junkchar%d = 0x%02x;\n" % (i, ord(os.urandom(1))))

# real char ordering and random numbers alternating
for i in xrange(len(flag)):
    header.write("int order%d = %d;\n" % (i, charlist.index(flag[i])))
    header.write("int junkorder%d = %d;\n" % (i, ord(os.urandom(1))))

header.close()

# generate main source file

source = open("switchy.c", "wb")

source.write("""#include <stdio.h>
#include "switchy.h"

char getnextchar(int index)
{
    switch(index)
    {
""")

for i in xrange(len(charlist)):
    source.write("""        case %d:
            return char%d ^ junkchar%d;
            break;
""" % (i, i, i))


source.write("""        default:
            return 0;
    }
}

int main()
{
""")

for i in xrange(len(flag)):
    source.write("""    printf("%%c", getnextchar(order%d));
    fflush(stdout);
""" % i)

source.write("""    printf("\\n");
    return 0;
}
""")

source.close()
