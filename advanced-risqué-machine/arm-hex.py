#!/usr/bin/python

import sys, os

# write x86.c using compiled arm binary
out = open("x86.c", "wb")

out.write("""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

unsigned char armcode[] = \"""")

f = open("arm", "rb")
armcode = f.read()
f.close()
randomdata = os.urandom(len(armcode))

for i in xrange(len(armcode)):
  c = armcode[i]
  d = randomdata[i]
  c = chr(ord(c) ^ ord(d))
  out.write("\\x%s" % c.encode('hex'))

out.write("""\";

unsigned char randomdata[] = \"""")

for c in randomdata:
    out.write("\\x%s" % c.encode('hex'))

out.write("""\";

void printarmhex(int offset)
{
  unsigned char current = armcode[offset] ^ randomdata[offset];
  current ^= 0xcc;
  printf("%02x", current);
}

void printjunk(int offset)
{
  unsigned char current = offset ^ randomdata[offset];
  current ^= 0xcc;
  printf("%02x", current);
}

void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
    int byteCount = 0;
    long word = 0;

    while (byteCount < len)
    {
        memcpy(&word, vptr + byteCount, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
        byteCount += sizeof(word);
    }
}

void signalhandler(int sig)
{
    signal(SIGALRM, SIG_IGN);
    raise(SIGSEGV);
}

int main()
{
  signal(SIGALRM, signalhandler);
  raise(SIGALRM);

  pid_t f = fork();

  if(!f)
  {
    // we are the child

    // wait to be ptraced
    ptrace(PTRACE_TRACEME);

    // output junk
    for(int i = 0; i < sizeof(armcode) - 1; i++)
    {
      printjunk(i);
    }

    printf("\\n");
    exit(0);
  }
  else
  {
    // we are the parent

    // ptrace child process
    if(ptrace(PTRACE_ATTACH, f, NULL, NULL) == -1)
    {
      exit(1);
    }

    // wait for child to be debuggable
    int waitpidstatus = 0;
    if(waitpid(f, &waitpidstatus, WUNTRACED) != f)
    {
      exit(1);
    }

    // hook printjunk() to redirect to printarmhex()
    unsigned char newcode[5] = { '\\0' };
    newcode[0] = 0xe9;
    int offset = (int)printarmhex - (int)printjunk - 5;
    memcpy(newcode+1, &offset, 4);
    ptrace_write(f, (unsigned long)printjunk, newcode, 5);

    // continue child
    if(ptrace(PTRACE_CONT, f, NULL, NULL) == -1)
    {
      exit(1);
    }

    // wait for child to terminate
    waitpid(f, &waitpidstatus, 0);
  }
  return 0;
}""");

out.close()
