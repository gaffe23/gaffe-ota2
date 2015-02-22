#include <stdio.h>

int main()
{

	// these two strings XORed together give the flag
	char a[] = "\xe0\x5b\x6a\xb4\x18\xc6\x99\x08\x45\x3c\x2e\xd9\x5f\x06\x1f\x06\x05\x0a\xb0\x1b\xe5\x0a\xef\xf2\xd7\x0c\xdd\xa1\xa0\xd4\x46\x69\x15\xd1\x2b\x67\xb5\x28";
	char b[] = "\x86\x37\x0b\xd3\x63\xa9\xf4\x6f\x65\x58\x5b\xbd\x3a\x2a\x3f\x72\x6d\x63\xc3\x3b\x8c\x79\xc3\xd2\xbb\x65\xb6\xc4\x8c\xf4\x35\x06\x35\xbc\x4e\x13\xd4\x55";

	// switch from Thumb mode to ARM mode and then try to keep running.
	// this is practically asking to hit an illegal instruction.

	// copy pc to r0
	asm("mov %r0,%pc");

	// add 8 to pc (because that's where the code continues after this block of inline asm)
	asm("add %r0,#8");

	// zero out r1. we're going to store a mask in r1 that will allow us to switch from Thumb mode to ARM mode.
	asm("eor %r1,%r1");

	// subtract 2 to make r1 = 0xffffffffe
	asm("sub %r1,#2");

	// bitwise AND r0 with 0xfffffffe to clear the least significant bit of the target address.
	// in Thumb mode, the least significant bit of the program counter is set to 1 (a fact which debuggers transparently hide).
	// changing the LSB back to 0 and running one of the "exchange instruction set" instructions will cause a switch to ARM mode.
	asm("and %r0,%r0,%r1");

	// use "bx" to branch to the next instruction, but with the LSB toggled so that we'll switch from Thumb to ARM.
	asm("bx %r0");

	// this loop subtracts 2 byte values together and then outputs the result. it should
	// actually be XORing them to produce the right character values.
	for(int i = 0; i < 38; i++)
	{
		// if you step through and record the values being subtracted and XOR them together,
		// or just patch the executable to change SUB to EOR, then you'll get the flag.
		printf("%c", a[i] ^ b[i]);
	}
	return 0;
}
