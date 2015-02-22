CFLAGS		= -std=gnu99

ARM_CC		= arm-linux-gnueabi-gcc -mthumb
ARM_STRIP	= arm-linux-gnueabi-strip

X86_CC		= clang -m32
X86_STRIP	= strip

all:
	rm -f x86
	$(ARM_CC) $(CFLAGS) -o arm arm.c
	$(ARM_STRIP) arm
	./arm-hex.py
	$(X86_CC) $(CFLAGS) -o x86 x86.c
	$(X86_STRIP) x86

clean:
	rm -f arm
	rm -f x86.c
	rm -f x86
