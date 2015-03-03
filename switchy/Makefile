CC	= clang
CFLAGS	= -m32 -std=gnu99

all:
	./switchy.py
	$(CC) $(CFLAGS) -o switchy switchy.c
	strip switchy --keep-symbol=main

clean:
	rm -f switchy.h switchy.c switchy
