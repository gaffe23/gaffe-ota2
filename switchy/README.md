# Switchy - Solution overview

For this challenge, we're given a `tar.bz2` file. First, I decompress it with `tar jxvf 639c6e1ff3e75935601984458f5309f4.tar.bz2`. This gives us a file called `7fcdb7907692cbd6ea87600ab11377b3`.

This is a reverse engineering challenge, so the file is probably an executable, but let's run the `file` command on it just to see what it is:

	$ file 7fcdb7907692cbd6ea87600ab11377b3
	7fcdb7907692cbd6ea87600ab11377b3: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=ed173f80ccccc36c7c25b5093a93f67e28bc0acc, not stripped

It does look like an executable, so let's run it and see what happens:

	$ ./7fcdb7907692cbd6ea87600ab11377b3
	☃▒▒▒▒▒☃Q

	┤b┤┼├┤ ▒├ ☃⎻↑172↑31↑22↑4 ☃┼ ·/⎺├▒/⎽┬☃├c▒≤
	$

Yuck, it spit out a bunch of weird characters and messed up my terminal. I have to run `reset` to get things looking normal again.

Okay, clearly this program is not just going to give us the flag outright, so let's take a look at the output of `strace` to learn more about what it's doing:

	$ strace ./7fcdb7907692cbd6ea87600ab11377b3
	execve("./7fcdb7907692cbd6ea87600ab11377b3", ["./7fcdb7907692cbd6ea87600ab11377"...], [/* 39 vars */]) = 0
	[ Process PID=21852 runs in 32 bit mode. ]
	brk(0)                                  = 0x924f000
	access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
	mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xfffffffff77d1000
	access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
	open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
	fstat64(3, {st_mode=S_IFREG|0644, st_size=68502, ...}) = 0
	mmap2(NULL, 68502, PROT_READ, MAP_PRIVATE, 3, 0) = 0xfffffffff77c0000
	close(3)                                = 0
	access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
	open("/lib/i386-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
	read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\340\233\1\0004\0\0\0"..., 512) = 512
	fstat64(3, {st_mode=S_IFREG|0755, st_size=1754876, ...}) = 0
	mmap2(NULL, 1759868, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xfffffffff7612000
	mmap2(0xf77ba000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1a8000) = 0xfffffffff77ba000
	mmap2(0xf77bd000, 10876, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xfffffffff77bd000
	close(3)                                = 0
	mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xfffffffff7611000
	set_thread_area(0xff81c8e0)             = 0
	mprotect(0xf77ba000, 8192, PROT_READ)   = 0
	mprotect(0x804a000, 4096, PROT_READ)    = 0
	mprotect(0xf77f4000, 4096, PROT_READ)   = 0
	munmap(0xf77c0000, 68502)               = 0
	fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 7), ...}) = 0
	mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xfffffffff77d0000
	write(1, "c", 1c)                        = 1
	write(1, "\333", 1                     = 1
	write(1, "}", 1})                        = 1
	write(1, "\333", 1                     = 1
	write(1, "\227", 1▒)                     = 1
	write(1, "\352", 1                     = 1
	write(1, "L", 1L)                        = 1
	write(1, "\311", 1                     = 1
	write(1, "&", 1&)                        = 1
	write(1, "\16", 1)                      = 1
	┬⎼☃├e(1← "\7"← 1)                       = 1
	┬⎼☃├e(1← "\267"← 1▒)                     = 1
	)                       = 1
	┬⎼☃├e(1← "☃"← 1☃)                        = 1
	┬⎼☃├e(1← "\256"← 1▒)                     = 1
	┬⎼☃├e(1← "\37"← 1)                      = 1
	┬⎼☃├e(1← "\267"← 1▒)                     = 1
	┬⎼☃├e(1← "\37"← 1)                      = 1
	┬⎼☃├e(1← "\374"← 1▒)                     = 1
	┬⎼☃├e(1← "\333"← 1                     = 1
	┬⎼☃├e(1← "\374"← 1▒)                     = 1
	┬⎼☃├e(1← "\267"← 1▒)                     = 1
	┬⎼☃├e(1← "\37"← 1)                      = 1
	┬⎼☃├e(1← "\374"← 1▒)                     = 1
	┬⎼☃├e(1← "\333"← 1                     = 1
	┬⎼☃├e(1← "\374"← 1▒)                     = 1
	┬⎼☃├e(1← "\267"← 1▒)                     = 1
	┬⎼☃├e(1← "\246"← 1▒)                     = 1
	┬⎼☃├e(1← "\374"← 1▒)                     = 1
	┬⎼☃├e(1← "☃"← 1☃)                        = 1
	┬⎼☃├e(1← "Q"← 1Q)                        = 1
	┬⎼☃├e(1← "\16"← 1)                      = 1
	┬⎼☃├e(1← "\311"← 1                     = 1
	┬⎼☃├e(1← "F"← 1F)                        = 1
	┬⎼☃├e(1← "\┼"← 1
	)                       = 1
	e│☃├_±⎼⎺┤⎻(▮)                           = ?
	→→→ e│☃├ed ┬☃├▒ ▮ →→→

It messed up my terminal again, but at least I can see that it's outputting junk characters one-by-one. It called `write` 34 times, once for each character of the junk output.

Anyway, there doesn't seem to be anything else very interesting-looking in the output of `strace`. It's time to start disassembling the program, so let's load it up in good ol' `gdb`. I'm going to use [gdb-peda](https://github.com/longld/peda), which adds quite a lot of helpful displays and commands to `gdb`.

	gdb-peda$ b main
	Breakpoint 1 at 0x80486d9
	gdb-peda$ r
	Starting program: /home/ubuntu/ctf/2015/ota2/switchy/7fcdb7907692cbd6ea87600ab11377b3
	Breakpoint 1, 0x080486d9 in main ()
	[...]
	gdb-peda$ disas main
	Dump of assembler code for function main:
	   0x080486d0 <+0>:     push   ebp
	   0x080486d1 <+1>:     mov    ebp,esp
	   0x080486d3 <+3>:     sub    esp,0x128
	=> 0x080486d9 <+9>:     mov    DWORD PTR [ebp-0x4],0x0
	   0x080486e0 <+16>:    mov    eax,ds:0x804b050
	   0x080486e5 <+21>:    mov    DWORD PTR [esp],eax
	   0x080486e8 <+24>:    call   0x8048470
	   0x080486ed <+29>:    lea    ecx,ds:0x8048fa4
	   0x080486f3 <+35>:    movsx  edx,al
	   0x080486f6 <+38>:    mov    DWORD PTR [esp],ecx
	   0x080486f9 <+41>:    mov    DWORD PTR [esp+0x4],edx
	   0x080486fd <+45>:    call   0x8048330 <printf@plt>
	   0x08048702 <+50>:    mov    ecx,DWORD PTR ds:0x804b160
	   0x08048708 <+56>:    mov    DWORD PTR [esp],ecx
	   0x0804870b <+59>:    mov    DWORD PTR [ebp-0x8],eax
	   0x0804870e <+62>:    call   0x8048340 <fflush@plt>
	   0x08048713 <+67>:    mov    ecx,DWORD PTR ds:0x804b058
	   0x08048719 <+73>:    mov    DWORD PTR [esp],ecx
	   0x0804871c <+76>:    mov    DWORD PTR [ebp-0xc],eax
	   0x0804871f <+79>:    call   0x8048470
	   0x08048724 <+84>:    lea    ecx,ds:0x8048fa4
	   0x0804872a <+90>:    movsx  edx,al
	   0x0804872d <+93>:    mov    DWORD PTR [esp],ecx
	   0x08048730 <+96>:    mov    DWORD PTR [esp+0x4],edx
	   0x08048734 <+100>:   call   0x8048330 <printf@plt>
	   0x08048739 <+105>:   mov    ecx,DWORD PTR ds:0x804b160
	   0x0804873f <+111>:   mov    DWORD PTR [esp],ecx
	   0x08048742 <+114>:   mov    DWORD PTR [ebp-0x10],eax
	   0x08048745 <+117>:   call   0x8048340 <fflush@plt>
	   0x0804874a <+122>:   mov    ecx,DWORD PTR ds:0x804b060
	   0x08048750 <+128>:   mov    DWORD PTR [esp],ecx
	   0x08048753 <+131>:   mov    DWORD PTR [ebp-0x14],eax
	   0x08048756 <+134>:   call   0x8048470
	   0x0804875b <+139>:   lea    ecx,ds:0x8048fa4
	   0x08048761 <+145>:   movsx  edx,al
	   0x08048764 <+148>:   mov    DWORD PTR [esp],ecx
	   0x08048767 <+151>:   mov    DWORD PTR [esp+0x4],edx
	   0x0804876b <+155>:   call   0x8048330 <printf@plt>
	   0x08048770 <+160>:   mov    ecx,DWORD PTR ds:0x804b160
	   0x08048776 <+166>:   mov    DWORD PTR [esp],ecx
	   0x08048779 <+169>:   mov    DWORD PTR [ebp-0x18],eax
	   0x0804877c <+172>:   call   0x8048340 <fflush@plt>
	   0x08048781 <+177>:   mov    ecx,DWORD PTR ds:0x804b068
	   0x08048787 <+183>:   mov    DWORD PTR [esp],ecx
	   0x0804878a <+186>:   mov    DWORD PTR [ebp-0x1c],eax
	   0x0804878d <+189>:   call   0x8048470
	   0x08048792 <+194>:   lea    ecx,ds:0x8048fa4
	   0x08048798 <+200>:   movsx  edx,al
	   0x0804879b <+203>:   mov    DWORD PTR [esp],ecx
	   0x0804879e <+206>:   mov    DWORD PTR [esp+0x4],edx
	   0x080487a2 <+210>:   call   0x8048330 <printf@plt>
	   0x080487a7 <+215>:   mov    ecx,DWORD PTR ds:0x804b160
	   0x080487ad <+221>:   mov    DWORD PTR [esp],ecx
	   0x080487b0 <+224>:   mov    DWORD PTR [ebp-0x20],eax
	   0x080487b3 <+227>:   call   0x8048340 <fflush@plt>
	   0x080487b8 <+232>:   mov    ecx,DWORD PTR ds:0x804b070
	   0x080487be <+238>:   mov    DWORD PTR [esp],ecx
	   0x080487c1 <+241>:   mov    DWORD PTR [ebp-0x24],eax
	[...]
	   0x08048e1c <+1868>:  mov    ecx,DWORD PTR ds:0x804b13c
	   0x08048e22 <+1874>:  mov    DWORD PTR [esp],ecx
	   0x08048e25 <+1877>:  mov    DWORD PTR [ebp-0x104],eax
	   0x08048e2b <+1883>:  call   0x8048470
	   0x08048e30 <+1888>:  lea    ecx,ds:0x8048fa4
	   0x08048e36 <+1894>:  movsx  edx,al
	   0x08048e39 <+1897>:  mov    DWORD PTR [esp],ecx
	   0x08048e3c <+1900>:  mov    DWORD PTR [esp+0x4],edx
	   0x08048e40 <+1904>:  call   0x8048330 <printf@plt>
	   0x08048e45 <+1909>:  mov    ecx,DWORD PTR ds:0x804b160
	   0x08048e4b <+1915>:  mov    DWORD PTR [esp],ecx
	   0x08048e4e <+1918>:  mov    DWORD PTR [ebp-0x108],eax
	   0x08048e54 <+1924>:  call   0x8048340 <fflush@plt>
	   0x08048e59 <+1929>:  mov    ecx,DWORD PTR ds:0x804b144
	   0x08048e5f <+1935>:  mov    DWORD PTR [esp],ecx
	   0x08048e62 <+1938>:  mov    DWORD PTR [ebp-0x10c],eax
	   0x08048e68 <+1944>:  call   0x8048470
	   0x08048e6d <+1949>:  lea    ecx,ds:0x8048fa4
	   0x08048e73 <+1955>:  movsx  edx,al
	   0x08048e76 <+1958>:  mov    DWORD PTR [esp],ecx
	   0x08048e79 <+1961>:  mov    DWORD PTR [esp+0x4],edx
	   0x08048e7d <+1965>:  call   0x8048330 <printf@plt>
	   0x08048e82 <+1970>:  mov    ecx,DWORD PTR ds:0x804b160
	   0x08048e88 <+1976>:  mov    DWORD PTR [esp],ecx
	   0x08048e8b <+1979>:  mov    DWORD PTR [ebp-0x110],eax
	   0x08048e91 <+1985>:  call   0x8048340 <fflush@plt>
	   0x08048e96 <+1990>:  lea    ecx,ds:0x8048fa7
	   0x08048e9c <+1996>:  mov    DWORD PTR [esp],ecx
	   0x08048e9f <+1999>:  mov    DWORD PTR [ebp-0x114],eax
	   0x08048ea5 <+2005>:  call   0x8048330 <printf@plt>
	   0x08048eaa <+2010>:  mov    ecx,0x0
	   0x08048eaf <+2015>:  mov    DWORD PTR [ebp-0x118],eax
	   0x08048eb5 <+2021>:  mov    eax,ecx
	   0x08048eb7 <+2023>:  add    esp,0x128
	   0x08048ebd <+2029>:  pop    ebp
	   0x08048ebe <+2030>:  ret
	End of assembler dump.
	gdb-peda$

What we see is a really long repeating pattern of instructions. Let's break down what's happening in this repeating pattern:

* It starts by loading some value stored within the binary into `ecx` using the `lea` instruction.

* Then it moves the value of `ecx` onto the stack. This value is apparently used as an argument to call a function located at `0x8048470`.

* Then it uses the `lea` instruction to load the data at address `0x8048fa4` into `ecx`. This value seems to be the same every time, so it's apparently a constant value within the binary. Let's take a look at it and see what it is:

		gdb-peda$ x/s 0x8048fa4
		0x8048fa4:      "%c"

 Looks like a format string. Since the program is giving us a single character of output at a time, it's safe to say that this is the format string being used to output the junk characters we saw earlier.

* It loads `al` (the lowest byte of `eax`) into `edx`. It looks like the value of `eax` comes from the function call to `0x8048fa4` (i.e., it's that function's return value).

* It loads `ecx` (the format string) and `edx` (the output of the function at `0x8048470`) onto the stack as arguments to `printf`.

* It calls `printf` to output a single character: the return value of `0x8048470` stored in `edx`.

* It loads the value `0x804b160` into ecx and then loads it onto the stack. This value is apparently going to be used as an argument to `fflush`. Let's take a closer look at what kind of data is at that address:

		gdb-peda$ x/s 0x804b160
		0x804b160:      "\300J\374", <incomplete sequence \367>
		gdb-peda$ x/wx 0x804b160
		0x804b160:      0xf7fc4ac0
		gdb-peda$ x/wx 0xf7fc4ac0
		0xf7fc4ac0 <_IO_2_1_stdout_>:   0xfbad2084

 It looks like this is essentially a pointer to the `stdout` file descriptor. This makes sense as an argument to `fflush`. Usually programs will call this function in order to force buffered output from `printf` to be printed to the screen.

* It loads the value of `eax` into some position on the stack, which seems to increase each time.

* After this, the pattern repeats, with the `lea` instruction loading a new value to be passed on the stack as an argument to the function `0x8048470`.

Since the function at `0x8048470` gets called over and over again, it definitely seems like it is playing an important role in all of this. We should probably try to understand what this function is doing. Let's disassemble it and see what we can find out about it:

	gdb-peda$ x/50i 0x8048470
	   0x8048470:   push   ebp
	   0x8048471:   mov    ebp,esp
	   0x8048473:   sub    esp,0x10
	   0x8048476:   mov    eax,DWORD PTR [ebp+0x8]
	   0x8048479:   mov    DWORD PTR [ebp-0x8],eax
	   0x804847c:   mov    ecx,eax
	   0x804847e:   sub    ecx,0x14
	   0x8048481:   mov    DWORD PTR [ebp-0xc],ecx
	   0x8048484:   mov    DWORD PTR [ebp-0x10],eax
	   0x8048487:   ja     0x80486bb
	   0x804848d:   mov    eax,DWORD PTR [ebp-0x10]
	   0x8048490:   mov    ecx,DWORD PTR [eax*4+0x8048f50]
	   0x8048497:   jmp    ecx
	   0x8048499:   movsx  eax,BYTE PTR ds:0x804b024
	   0x80484a0:   movsx  ecx,BYTE PTR ds:0x804b025
	   0x80484a7:   xor    eax,ecx
	   0x80484a9:   mov    dl,al
	   0x80484ab:   mov    BYTE PTR [ebp-0x1],dl
	   0x80484ae:   jmp    0x80486bf
	   0x80484b3:   movsx  eax,BYTE PTR ds:0x804b026
	   0x80484ba:   movsx  ecx,BYTE PTR ds:0x804b027
	   0x80484c1:   xor    eax,ecx
	   0x80484c3:   mov    dl,al
	   0x80484c5:   mov    BYTE PTR [ebp-0x1],dl
	   0x80484c8:   jmp    0x80486bf
	   0x80484cd:   movsx  eax,BYTE PTR ds:0x804b028
	   0x80484d4:   movsx  ecx,BYTE PTR ds:0x804b029
	   0x80484db:   xor    eax,ecx
	   0x80484dd:   mov    dl,al
	   0x80484df:   mov    BYTE PTR [ebp-0x1],dl
	   0x80484e2:   jmp    0x80486bf
	   0x80484e7:   movsx  eax,BYTE PTR ds:0x804b02a
	   0x80484ee:   movsx  ecx,BYTE PTR ds:0x804b02b
	   0x80484f5:   xor    eax,ecx
	   0x80484f7:   mov    dl,al
	   0x80484f9:   mov    BYTE PTR [ebp-0x1],dl
	   0x80484fc:   jmp    0x80486bf
	   0x8048501:   movsx  eax,BYTE PTR ds:0x804b02c
	   0x8048508:   movsx  ecx,BYTE PTR ds:0x804b02d
	   0x804850f:   xor    eax,ecx
	   0x8048511:   mov    dl,al
	   0x8048513:   mov    BYTE PTR [ebp-0x1],dl
	   0x8048516:   jmp    0x80486bf
	   0x804851b:   movsx  eax,BYTE PTR ds:0x804b02e
	   0x8048522:   movsx  ecx,BYTE PTR ds:0x804b02f
	   0x8048529:   xor    eax,ecx
	   0x804852b:   mov    dl,al
	   0x804852d:   mov    BYTE PTR [ebp-0x1],dl
	   0x8048530:   jmp    0x80486bf
	   0x8048535:   movsx  eax,BYTE PTR ds:0x804b030

It looks like we have some kind of repeating pattern in here too. Let's break down what this function is doing. At the start of the function, it loads its first argument into `eax` and then copies it into a location inside its own stack frame at `[ebp-0x8]`. After that, it compares some values together in order to determine some kind of jump behavior.

The instruction `mov ecx,DWORD PTR [eax*4+0x8048f50]` essentially takes `eax` (the argument to the function) and multiplies it by 4, and then adds it to the value `0x8048f50`. The program stores the result of this calculation in `ecx`. Directly afterwards, the program does something very interesting: it unconditionally jumps to the address contained in `ecx`. Apparently this calculation of `(eax * 4) + 0x8048f50` is meant to calculate an actual address to jump to within the program.

After this, we reach the repeating blocks of code, which each do something like this:

* Move some byte value stored within the binary into `eax`.

* Move another byte value into `ecx`. This byte value seems to comes directly after the previous byte value that was just loaded into `eax`.

* XOR `eax` and `ecx` together and store the result in `eax`.

* Move `al` into `dl`. ('al' and 'dl' refer to the lowest byte of `eax` and `edx`, respectively.)

* Store `dl`, which now contains the result of the XOR operation, at the address `[ebp-0x1]`.

* Jump unconditionally to address `0x80486bf`.

Each block jumps unconditionally to this block `0x80486bf` once it's done. Let's see what that block does:

	gdb-peda$ x/10i 0x80486bf
	   0x80486bf:   movsx  eax,BYTE PTR [ebp-0x1]
	   0x80486c3:   add    esp,0x10
	   0x80486c6:   pop    ebp
	   0x80486c7:   ret
	   0x80486c8:   nop    DWORD PTR [eax+eax*1+0x0]
	   0x80486d0 <main>:    push   ebp
	   0x80486d1 <main+1>:  mov    ebp,esp
	   0x80486d3 <main+3>:  sub    esp,0x128
	=> 0x80486d9 <main+9>:  mov    DWORD PTR [ebp-0x4],0x0
	   0x80486e0 <main+16>: mov    eax,ds:0x804b050
	gdb-peda$

This part consists of only a couple of instructions. It retrieves the result of the XOR operation that was stored earlier at address `[ebp-0x1]`, and then stores it in `eax`. On x86, the `eax` register usually contains the return value for an instruction. Right after this, the function cleans up the stack and returns, so the function is actually returning the byte value that is calculated from the XOR operation.

Having the function this much, what conclusions can we draw about it? Well, since it seems to conditionally choose only one option out of the repeating pattern, and it uses an offset to calculate which option to jump to, we can conclude that this code was almost certainly generated from a C `switch` statement. That also makes sense given the name of the challenge, "Switchy".

Overall, it looks like the program is XORing various values together in order to print its output byte by byte. The flag might be in the binary somewhere, but currently the program is just outputting garbage. Let's step through the program and see what the actual data looks like as it's printing the individual characters.

I begin stepping through `main`. I step into the first call to the function `0x8048470`. I step through the `jmp` instruction that implements the C `switch` statement. Then, I reach the point where the function has loaded its two byte values and is about to XOR them together:

	gdb-peda$ si
	[-----------------------------------------------------registers-----------------------------------------------------]
	EAX: 0x66 (b'f')
	EBX: 0xf7fc4000 --> 0x1a9da8
	ECX: 0x5
	EDX: 0xffffd9a4 --> 0xf7fc4000 --> 0x1a9da8
	ESI: 0x0
	EDI: 0x0
	EBP: 0xffffd848 --> 0xffffd978 --> 0x0
	ESP: 0xffffd838 --> 0x9 (b'\t')
	EIP: 0x8048591 (xor    eax,ecx)
	[-------------------------------------------------------code--------------------------------------------------------]
	   0x804857e:   jmp    0x80486bf
	   0x8048583:   movsx  eax,BYTE PTR ds:0x804b036
	   0x804858a:   movsx  ecx,BYTE PTR ds:0x804b037
	=> 0x8048591:   xor    eax,ecx
	   0x8048593:   mov    dl,al
	   0x8048595:   mov    BYTE PTR [ebp-0x1],dl
	   0x8048598:   jmp    0x80486bf
	   0x804859d:   movsx  eax,BYTE PTR ds:0x804b038
	[-------------------------------------------------------stack-------------------------------------------------------]
	00:0000| esp 0xffffd838 --> 0x9 (b'\t')
	01:0004|     0xffffd83c --> 0xfffffff5
	02:0008|     0xffffd840 --> 0x9 (b'\t')
	03:0012|     0xffffd844 --> 0x7b1ea71
	04:0016| ebp 0xffffd848 --> 0xffffd978 --> 0x0
	05:0020|     0xffffd84c --> 0x80486ed (<main+29>:       lea    ecx,ds:0x8048fa4)
	06:0024|     0xffffd850 --> 0x9 (b'\t')
	07:0028|     0xffffd854 --> 0xf7ff0d56 (<_dl_unload_cache+6>:   add    ebx,0xc2aa)
	[-------------------------------------------------------------------------------------------------------------------]
	Legend: code, data, rodata, value
	0x08048591 in ?? ()
	gdb-peda$

One of the byte values is in `eax`, and the other byte value is in `ecx`. If we look at `gdb-peda`'s register display, we see that `eax` is set to `0x66` (the letter 'f' in ASCII), and `ecx` is `0x5`.

When we step some more, we see that the two values are XORed together to produce the value `0x63` (the letter 'c' in ASCII):

	gdb-peda$ si
	[-----------------------------------------------------registers-----------------------------------------------------]
	EAX: 0x63 (b'c')
	EBX: 0xf7fc4000 --> 0x1a9da8
	ECX: 0x5
	EDX: 0xffffd963 --> 0xffd000f7
	ESI: 0x0
	EDI: 0x0
	EBP: 0xffffd848 --> 0xffffd978 --> 0x0
	ESP: 0xffffd838 --> 0x9 (b'\t')
	EIP: 0x8048595 (mov    BYTE PTR [ebp-0x1],dl)
	[-------------------------------------------------------code--------------------------------------------------------]
	   0x804858a:   movsx  ecx,BYTE PTR ds:0x804b037
	   0x8048591:   xor    eax,ecx
	   0x8048593:   mov    dl,al
	=> 0x8048595:   mov    BYTE PTR [ebp-0x1],dl
	   0x8048598:   jmp    0x80486bf
	   0x804859d:   movsx  eax,BYTE PTR ds:0x804b038
	   0x80485a4:   movsx  ecx,BYTE PTR ds:0x804b039
	   0x80485ab:   xor    eax,ecx
	[-------------------------------------------------------stack-------------------------------------------------------]
	00:0000| esp 0xffffd838 --> 0x9 (b'\t')
	01:0004|     0xffffd83c --> 0xfffffff5
	02:0008|     0xffffd840 --> 0x9 (b'\t')
	03:0012|     0xffffd844 --> 0x7b1ea71
	04:0016| ebp 0xffffd848 --> 0xffffd978 --> 0x0
	05:0020|     0xffffd84c --> 0x80486ed (<main+29>:       lea    ecx,ds:0x8048fa4)
	06:0024|     0xffffd850 --> 0x9 (b'\t')
	07:0028|     0xffffd854 --> 0xf7ff0d56 (<_dl_unload_cache+6>:   add    ebx,0xc2aa)
	[-------------------------------------------------------------------------------------------------------------------]
	Legend: code, data, rodata, value
	0x08048595 in ?? ()
	gdb-peda$

At this point, I want to check to see if the output we're getting here actually matches what the overall program output. The output messes up the terminal, but we can still read the output precisely by piping it into `xxd`. `xxd` will show us what the output is in hex, and will not attempt to print non-ASCII characters. Let's briefly try this in another terminal and see what the output looks like:

	$ ./7fcdb7907692cbd6ea87600ab11377b3 | xxd
	0000000: 63db 7ddb 97ea 4cc9 260e 07b7 0d69 ae1f  c.}...L.&....i..
	0000010: b71f fcdb fcb7 1ffc dbfc b7a6 fc69 510e  .............iQ.
	0000020: c946 0a                                  .F.

We can see that the first byte of the output is indeed `0x63`, so it looks like we are at the actual spot in the program where this first byte of output is generated. Let's step into the next call to `0x8048470` and see if this continues to hold true:

	[-----------------------------------------------------registers-----------------------------------------------------]
	EAX: 0x6c (b'l')
	EBX: 0xf7fc4000 --> 0x1a9da8
	ECX: 0xffffffb7
	EDX: 0x0
	ESI: 0x0
	EDI: 0x0
	EBP: 0xffffd848 --> 0xffffd978 --> 0x0
	ESP: 0xffffd838 --> 0xe
	EIP: 0x8048613 (xor    eax,ecx)
	[-------------------------------------------------------code--------------------------------------------------------]
	   0x8048600:   jmp    0x80486bf
	   0x8048605:   movsx  eax,BYTE PTR ds:0x804b040
	   0x804860c:   movsx  ecx,BYTE PTR ds:0x804b041
	=> 0x8048613:   xor    eax,ecx
	   0x8048615:   mov    dl,al
	   0x8048617:   mov    BYTE PTR [ebp-0x1],dl
	   0x804861a:   jmp    0x80486bf
	   0x804861f:   movsx  eax,BYTE PTR ds:0x804b042
	[-------------------------------------------------------stack-------------------------------------------------------]
	00:0000| esp 0xffffd838 --> 0xe
	01:0004|     0xffffd83c --> 0xfffffffa
	02:0008|     0xffffd840 --> 0xe
	03:0012|     0xffffd844 --> 0x0
	04:0016| ebp 0xffffd848 --> 0xffffd978 --> 0x0
	05:0020|     0xffffd84c --> 0x8048724 (<main+84>:       lea    ecx,ds:0x8048fa4)
	06:0024|     0xffffd850 --> 0xe
	07:0028|     0xffffd854 --> 0x63 (b'c')
	[-------------------------------------------------------------------------------------------------------------------]
	Legend: code, data, rodata, value
	0x08048613 in ?? ()

This time, `eax` is set to `0x6c` ('l' in ASCII). `ecx` is set to `0xffffffb7`, but we can effectively consider it to be `0xb7` since it's going to be interpreted as a byte value later on. Next, we'll step onward to the XOR:

	[-----------------------------------------------------registers-----------------------------------------------------]
	EAX: 0xffffffdb
	EBX: 0xf7fc4000 --> 0x1a9da8
	ECX: 0xffffffb7
	EDX: 0x0
	ESI: 0x0
	EDI: 0x0
	EBP: 0xffffd848 --> 0xffffd978 --> 0x0
	ESP: 0xffffd838 --> 0xe
	EIP: 0x8048615 (mov    dl,al)
	[-------------------------------------------------------code--------------------------------------------------------]
	   0x8048605:   movsx  eax,BYTE PTR ds:0x804b040
	   0x804860c:   movsx  ecx,BYTE PTR ds:0x804b041
	   0x8048613:   xor    eax,ecx
	=> 0x8048615:   mov    dl,al
	   0x8048617:   mov    BYTE PTR [ebp-0x1],dl
	   0x804861a:   jmp    0x80486bf
	   0x804861f:   movsx  eax,BYTE PTR ds:0x804b042
	   0x8048626:   movsx  ecx,BYTE PTR ds:0x804b043
	[-------------------------------------------------------stack-------------------------------------------------------]
	00:0000| esp 0xffffd838 --> 0xe
	01:0004|     0xffffd83c --> 0xfffffffa
	02:0008|     0xffffd840 --> 0xe
	03:0012|     0xffffd844 --> 0x0
	04:0016| ebp 0xffffd848 --> 0xffffd978 --> 0x0
	05:0020|     0xffffd84c --> 0x8048724 (<main+84>:       lea    ecx,ds:0x8048fa4)
	06:0024|     0xffffd850 --> 0xe
	07:0028|     0xffffd854 --> 0x63 (b'c')
	[-------------------------------------------------------------------------------------------------------------------]
	Legend: code, data, rodata, value
	0x08048615 in ?? ()

The result of this XOR is `0xdb`, a non-printable character. We can see from the output of `xxd` above that `0xdb` is indeed the second byte of the program's output.

You may have noticed by now that each time `0x8048470` has been called so far, the value of `eax` has been set to an ASCII value. We know that the flag format for this CTF is `flag{secret text}`. The fact that the first two values of `eax` inside this function before the XOR have been 'f' followed by 'l' suggests that we might be close to finding the flag. Let's keep stepping through the program and looking at these values to see if this is actually the case.

Next character:

	[-----------------------------------------------------registers-----------------------------------------------------]
	EAX: 0x61 (b'a')
	EBX: 0xf7fc4000 --> 0x1a9da8
	ECX: 0x1c
	EDX: 0x0
	ESI: 0x0
	EDI: 0x0
	EBP: 0xffffd848 --> 0xffffd978 --> 0x0
	ESP: 0xffffd838 --> 0x6
	EIP: 0x8048543 (xor    eax,ecx)
	[-------------------------------------------------------code--------------------------------------------------------]
	   0x8048530:   jmp    0x80486bf
	   0x8048535:   movsx  eax,BYTE PTR ds:0x804b030
	   0x804853c:   movsx  ecx,BYTE PTR ds:0x804b031
	=> 0x8048543:   xor    eax,ecx
	   0x8048545:   mov    dl,al
	   0x8048547:   mov    BYTE PTR [ebp-0x1],dl
	   0x804854a:   jmp    0x80486bf
	   0x804854f:   movsx  eax,BYTE PTR ds:0x804b032
	[-------------------------------------------------------stack-------------------------------------------------------]
	00:0000| esp 0xffffd838 --> 0x6
	01:0004|     0xffffd83c --> 0xfffffff2
	02:0008|     0xffffd840 --> 0x6
	03:0012|     0xffffd844 --> 0x0
	04:0016| ebp 0xffffd848 --> 0xffffd978 --> 0x0
	05:0020|     0xffffd84c --> 0x804875b (<main+139>:      lea    ecx,ds:0x8048fa4)
	06:0024|     0xffffd850 --> 0x6
	07:0028|     0xffffd854 --> 0xffffffdb
	[-------------------------------------------------------------------------------------------------------------------]
	Legend: code, data, rodata, value
	0x08048543 in ?? ()

Yep, the next character is an 'a'. On to the next one:

	[-----------------------------------------------------registers-----------------------------------------------------]
	EAX: 0x67 (b'g')
	EBX: 0xf7fc4000 --> 0x1a9da8
	ECX: 0xffffffbc
	EDX: 0x0
	ESI: 0x0
	EDI: 0x0
	EBP: 0xffffd848 --> 0xffffd978 --> 0x0
	ESP: 0xffffd838 --> 0x2
	EIP: 0x80484db (xor    eax,ecx)
	[-------------------------------------------------------code--------------------------------------------------------]
	   0x80484c8:   jmp    0x80486bf
	   0x80484cd:   movsx  eax,BYTE PTR ds:0x804b028
	   0x80484d4:   movsx  ecx,BYTE PTR ds:0x804b029
	=> 0x80484db:   xor    eax,ecx
	   0x80484dd:   mov    dl,al
	   0x80484df:   mov    BYTE PTR [ebp-0x1],dl
	   0x80484e2:   jmp    0x80486bf
	   0x80484e7:   movsx  eax,BYTE PTR ds:0x804b02a
	[-------------------------------------------------------stack-------------------------------------------------------]
	00:0000| esp 0xffffd838 --> 0x2
	01:0004|     0xffffd83c --> 0xffffffee
	02:0008|     0xffffd840 --> 0x2
	03:0012|     0xffffd844 --> 0x0
	04:0016| ebp 0xffffd848 --> 0xffffd978 --> 0x0
	05:0020|     0xffffd84c --> 0x8048792 (<main+194>:      lea    ecx,ds:0x8048fa4)
	06:0024|     0xffffd850 --> 0x2
	07:0028|     0xffffd854 --> 0x7d (b'}')
	[-------------------------------------------------------------------------------------------------------------------]
	Legend: code, data, rodata, value
	0x080484db in ?? ()

Okay, this one was 'g'. I don't think it's a coincidence that these first 4 values spell out "flag". It looks like the `eax` values inside these sections of the program will give us the flag. However, it's going to be pretty arduous to step into this function 34 times and read the value of `eax` out of the debugger's register display to get the entire output of the program. Let's see if we can devise something to make this more convenient.

We know that `eax` will contain the actual values we care about. `ecx` contains some kind of garbage that we don't care about. The value in `ecx` is being XORed with `eax` to produce some weird, non-printable characters that mess up the terminal display. Once the XOR operation is done, the result is moved from `al` into `dl` to produce the final result.

One way of handling this situation is to simply patch the XOR operations with some other instruction in order to change the program's behavior. One common choice on x86 is the `nop` instruction, which stands for "No Operation Performed". It is an instruction that does absolutely nothing. If we patch the binary to replace the XOR operations with `nop` instructions, then `eax` will never get XORed with `ecx`. As a result, the program will load the correct values of `al` directly into `dl`, and the function will return the characters we want.

There are lots of ways to patch binaries. For stuff like this, I like to use `vim` and `xxd` together as a hex editor. Many disassemblers, such as IDA, have built-in functionality for patching binaries as well, which may be a better choice depending on what you're more comfortable with.

First, we have to figure out what actual bytes to overwrite. Unfortunately, `gdb` doesn't show us the opcode bytes for the instructions, so we need to disassemble the program using `objdump`:

	$ objdump -d -M intel 7fcdb7907692cbd6ea87600ab11377b3

	7fcdb7907692cbd6ea87600ab11377b3:     file format elf32-i386


	Disassembly of section .init:

	080482f8 <.init>:
	[...]
	80484cd:       0f be 05 28 b0 04 08    movsx  eax,BYTE PTR ds:0x804b028
	 80484d4:       0f be 0d 29 b0 04 08    movsx  ecx,BYTE PTR ds:0x804b029
	 80484db:       31 c8                   xor    eax,ecx
	 80484dd:       88 c2                   mov    dl,al
	 80484df:       88 55 ff                mov    BYTE PTR [ebp-0x1],dl
	[...]

From `objdump`'s disassembly, we can see that the opcode bytes for the instruction `xor eax,ecx` are `31 c8`. We want to overwrite this pattern of bytes with `90 90` throughout the program. This will replace `xor eax,ecx` with two `nop` instructions, which will remove the XOR operations entirely from the program.

To do that, I create a copy of the binary and open it up in `vim`. Then, I use `vim` and `xxd` together to obtain a hex dump of the program, and make modifications to it. Then I convert the hex dump back to raw binary, and save the patched version of the program. Here are the steps I use:

* Create a new copy of the file so that we still have access to the original one: `cp 7fcdb7907692cbd6ea87600ab11377b3 patched`

* Open the new copy in `vim`: `vim patched`

* Convert the file to hex using `xxd`: `:%!xxd -p`

* Remove all newlines: `:%s/\n//g` (I do this in case any instructions are split up across multiple lines)

* Replace every instance of `31c8` with `9090`: `:%s/31c8/9090/g`

* Convert the file back to raw binary: `:%!xxd -r -p`

* Save the modified file and exit `vim`: `:wq`

Now that we've patched out all of the XOR operations, we can try running the patched binary and seeing what we get:

	$ ./patched
	flag{switch jump pogo pogo bounce}

Success! The flag is: `flag{switch jump pogo pogo bounce}`

Realistically, it may have been faster and easier to just step through the program and collect the `eax` values, but I believe in automating solutions and reducing manual drugery wherever possible.
