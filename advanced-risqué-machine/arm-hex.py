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

unsigned char getrandombyte()
{
  int len = rand() % 0xff + 1;
  int index = rand() % 0xff;
  int* randnums = malloc(len * sizeof(int));
  for(int i = 0; i < len; i++)
  {
    randnums[i] = rand();
  }
  return randnums[index % len] & 0xff;
}

void printarmhex(int offset)
{
  unsigned char current = armcode[offset];
  current ^= getrandombyte();
  printf("%02x", current);
}

void printjunk(int offset)
{
  unsigned char current = offset ^ randomdata[offset];
  current ^= getrandombyte();
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

void alarmhandler(int sig)
{
  signal(SIGALRM, SIG_IGN);
  raise(SIGPIPE);
}

void pipehandler(int sig)
{
  signal(SIGPIPE, SIG_IGN);
  raise(SIGUSR2);
}

void usr2handler(int sig)
{
  signal(SIGUSR2, SIG_IGN);
  raise(SIGUSR1);
}

void usr1handler(int sig)
{
  signal(SIGUSR1, SIG_IGN);
  for(int i = 0; i < sizeof(randomdata); i++)
  {
    armcode[i] ^= randomdata[i];
  }
  raise(SIGILL);
}

int main()
{
  signal(SIGALRM, alarmhandler);
  signal(SIGPIPE, pipehandler);
  signal(SIGUSR2, usr2handler);
  signal(SIGUSR1, usr1handler);
  raise(SIGALRM);

  unsigned int* randomseed = malloc(sizeof(unsigned int));
  FILE *fp;
  fp = fopen("/dev/urandom", "rb");
  fread(randomseed, sizeof(unsigned int), 1, fp);

  srand(*(unsigned int*)randomseed);

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
