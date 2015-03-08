# Advanced Risqué Machine - Solution overview

The challenge consists of a `tar.bz2` file, so we decompress it and see a file named `ccb516735156cbd2cb9282504e8663e6`. Let's run `file` on it to see what it is:

	$ file ccb516735156cbd2cb9282504e8663e6
	ccb516735156cbd2cb9282504e8663e6: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=d0207b3a4d5cd9248355e541f92de2a2b85041ec, stripped

Okay, looks like an executable. That makes sense, since this is a reverse engineering challenge. Let's run it and see what happens:

	$ ./ccb516735156cbd2cb9282504e8663e6
	[1]    26295 illegal hardware instruction (core dumped)  ./ccb516735156cbd2cb9282504e8663e6

That's not very nice. Let's run it under `strace` to see why it's doing that:

	trace ./ccb516735156cbd2cb9282504e8663e6
	execve("./ccb516735156cbd2cb9282504e8663e6", ["./ccb516735156cbd2cb9282504e8663"...], [/* 39 vars */]) = 0
	[...]
	rt_sigaction(SIGALRM, {0x8048850, [ALRM], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
	rt_sigaction(SIGPIPE, {0x80488a0, [PIPE], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
	rt_sigaction(SIGUSR2, {0x80488f0, [USR2], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
	rt_sigaction(SIGUSR1, {0x8048940, [USR1], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
	gettid()                                = 26402
	tgkill(26402, 26402, SIGALRM)           = 0
	--- SIGALRM {si_signo=SIGALRM, si_code=SI_TKILL, si_pid=26402, si_uid=1000} ---
	rt_sigaction(SIGALRM, {SIG_IGN, [ALRM], SA_RESTART}, {0x8048850, [ALRM], SA_RESTART}, 8) = 0
	tgkill(26402, 26402, SIGPIPE)           = 0
	--- SIGPIPE {si_signo=SIGPIPE, si_code=SI_TKILL, si_pid=26402, si_uid=1000} ---
	rt_sigaction(SIGPIPE, {SIG_IGN, [PIPE], SA_RESTART}, {0x80488a0, [PIPE], SA_RESTART}, 8) = 0
	tgkill(26402, 26402, SIGUSR2)           = 0
	--- SIGUSR2 {si_signo=SIGUSR2, si_code=SI_TKILL, si_pid=26402, si_uid=1000} ---
	rt_sigaction(SIGUSR2, {SIG_IGN, [USR2], SA_RESTART}, {0x80488f0, [USR2], SA_RESTART}, 8) = 0
	tgkill(26402, 26402, SIGUSR1)           = 0
	--- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_TKILL, si_pid=26402, si_uid=1000} ---
	rt_sigaction(SIGUSR1, {SIG_IGN, [USR1], SA_RESTART}, {0x8048940, [USR1], SA_RESTART}, 8) = 0
	tgkill(26402, 26402, SIGILL)            = 0
	--- SIGILL {si_signo=SIGILL, si_code=SI_TKILL, si_pid=26402, si_uid=1000} ---
	+++ killed by SIGILL (core dumped) +++
	[1]    26399 illegal hardware instruction (core dumped)  strace ./ccb516735156cbd2cb9282504e8663e6

We can see from the `rt_sigaction` calls that it's installing signal handlers for `SIGALRM`, `SIGPIPE`, `SIGUSR2`, and `SIGUSR1`. Then, it produces those signals in that same order (`SIGALRM`, `SIGPIPE`, `SIGUSR2`, and `SIGUSR1`), and then ends up hitting a `SIGILL` and exiting.

Let's open it up in IDA and see what we can see. IDA finds the `main` function at `080489D0`. Right at the beginning of `main`, it's calling `_signal` 4 times to install signal handlers, and then calling `_raise` in order to raise a `SIGALRM`:

	.text:080489E1 8D 0D 50 88 04 08                             lea     ecx, handler
	.text:080489E7 C7 45 F0 00 00 00 00                          mov     [ebp+var_10], 0
	.text:080489EE C7 04 24 0E 00 00 00                          mov     dword ptr [esp], 0Eh ; sig
	.text:080489F5 89 4C 24 04                                   mov     [esp+4], ecx    ; handler
	.text:080489F9 89 45 CC                                      mov     [ebp+var_34], eax
	.text:080489FC E8 9F FA FF FF                                call    _signal
	.text:08048A01 B9 0D 00 00 00                                mov     ecx, 0Dh
	.text:08048A06 8D 15 A0 88 04 08                             lea     edx, sub_80488A0
	.text:08048A0C C7 04 24 0D 00 00 00                          mov     dword ptr [esp], 0Dh ; sig
	.text:08048A13 89 54 24 04                                   mov     [esp+4], edx    ; handler
	.text:08048A17 89 45 C8                                      mov     [ebp+var_38], eax
	.text:08048A1A 89 4D C4                                      mov     [ebp+var_3C], ecx
	.text:08048A1D E8 7E FA FF FF                                call    _signal
	.text:08048A22 B9 0C 00 00 00                                mov     ecx, 0Ch
	.text:08048A27 8D 15 F0 88 04 08                             lea     edx, sub_80488F0
	.text:08048A2D C7 04 24 0C 00 00 00                          mov     dword ptr [esp], 0Ch ; sig
	.text:08048A34 89 54 24 04                                   mov     [esp+4], edx    ; handler
	.text:08048A38 89 45 C0                                      mov     [ebp+var_40], eax
	.text:08048A3B 89 4D BC                                      mov     [ebp+var_44], ecx
	.text:08048A3E E8 5D FA FF FF                                call    _signal
	.text:08048A43 B9 0A 00 00 00                                mov     ecx, 0Ah
	.text:08048A48 8D 15 40 89 04 08                             lea     edx, sub_8048940
	.text:08048A4E C7 04 24 0A 00 00 00                          mov     dword ptr [esp], 0Ah ; sig
	.text:08048A55 89 54 24 04                                   mov     [esp+4], edx    ; handler
	.text:08048A59 89 45 B8                                      mov     [ebp+var_48], eax
	.text:08048A5C 89 4D B4                                      mov     [ebp+var_4C], ecx
	.text:08048A5F E8 3C FA FF FF                                call    _signal
	.text:08048A64 B9 0E 00 00 00                                mov     ecx, 0Eh
	.text:08048A69 C7 04 24 0E 00 00 00                          mov     dword ptr [esp], 0Eh ; sig
	.text:08048A70 89 45 B0                                      mov     [ebp+var_50], eax
	.text:08048A73 89 4D AC                                      mov     [ebp+var_54], ecx
	.text:08048A76 E8 05 FA FF FF                                call    _raise

Let's check out the `SIGALRM` handler, which IDA has automatically named `handler`:

	.text:08048850                               ; void handler(int)
	.text:08048850                               handler         proc near               ; DATA XREF: main+11o
	.text:08048850
	.text:08048850                               var_14          = dword ptr -14h
	.text:08048850                               var_10          = dword ptr -10h
	.text:08048850                               var_C           = dword ptr -0Ch
	.text:08048850                               var_8           = dword ptr -8
	.text:08048850                               var_4           = dword ptr -4
	.text:08048850                               arg_0           = dword ptr  8
	.text:08048850
	.text:08048850 55                                            push    ebp
	.text:08048851 89 E5                                         mov     ebp, esp
	.text:08048853 83 EC 28                                      sub     esp, 28h
	.text:08048856 8B 45 08                                      mov     eax, [ebp+arg_0]
	.text:08048859 B9 0E 00 00 00                                mov     ecx, 0Eh
	.text:0804885E BA 01 00 00 00                                mov     edx, 1
	.text:08048863 89 45 FC                                      mov     [ebp+var_4], eax
	.text:08048866 C7 04 24 0E 00 00 00                          mov     dword ptr [esp], 0Eh ; sig
	.text:0804886D 89 54 24 04                                   mov     [esp+4], edx    ; handler
	.text:08048871 89 4D F8                                      mov     [ebp+var_8], ecx
	.text:08048874 E8 27 FC FF FF                                call    _signal
	.text:08048879 B9 0D 00 00 00                                mov     ecx, 0Dh
	.text:0804887E C7 04 24 0D 00 00 00                          mov     dword ptr [esp], 0Dh ; sig
	.text:08048885 89 45 F4                                      mov     [ebp+var_C], eax
	.text:08048888 89 4D F0                                      mov     [ebp+var_10], ecx
	.text:0804888B E8 F0 FB FF FF                                call    _raise
	.text:08048890 89 45 EC                                      mov     [ebp+var_14], eax
	.text:08048893 83 C4 28                                      add     esp, 28h
	.text:08048896 5D                                            pop     ebp
	.text:08048897 C3                                            retn
	.text:08048897                               handler         endp

Looks like it's pretty straightforward: it acknowledges the received signal by calling `_signal` and then calls `_raise` to create a `SIGPIPE`. If we flip back to `main`, we see that the `SIGPIPE` handler the program installed is at `80488A0`. This function is not that much different from the previous one; it acknowledges the `SIGPIPE` and then calls `_raise` to create a `SIGUSR2`. If we check out the `SIGUSR2` handler, we see that it raises a `SIGUSR1`.

Once we reach the `SIGUSR1` handler at `08048940`, things start getting slightly more interesting:

	.text:08048940                               ; void sigusr1_handler(int)
	.text:08048940                               sigusr1_handler proc near               ; DATA XREF: main+78o
	.text:08048940
	.text:08048940                               var_1C          = dword ptr -1Ch
	.text:08048940                               var_18          = dword ptr -18h
	.text:08048940                               var_14          = dword ptr -14h
	.text:08048940                               var_10          = dword ptr -10h
	.text:08048940                               var_C           = dword ptr -0Ch
	.text:08048940                               var_8           = dword ptr -8
	.text:08048940                               arg_0           = dword ptr  8
	.text:08048940
	.text:08048940 55                                            push    ebp
	.text:08048941 89 E5                                         mov     ebp, esp
	.text:08048943 53                                            push    ebx
	.text:08048944 83 EC 24                                      sub     esp, 24h
	.text:08048947 8B 45 08                                      mov     eax, [ebp+arg_0]
	.text:0804894A B9 0A 00 00 00                                mov     ecx, 0Ah
	.text:0804894F BA 01 00 00 00                                mov     edx, 1
	.text:08048954 89 45 F8                                      mov     [ebp+var_8], eax
	.text:08048957 C7 04 24 0A 00 00 00                          mov     dword ptr [esp], 0Ah ; sig
	.text:0804895E 89 54 24 04                                   mov     [esp+4], edx    ; handler
	.text:08048962 89 4D F0                                      mov     [ebp+var_10], ecx
	.text:08048965 E8 36 FB FF FF                                call    _signal
	.text:0804896A C7 45 F4 00 00 00 00                          mov     [ebp+var_C], 0
	.text:08048971 89 45 EC                                      mov     [ebp+var_14], eax
	.text:08048974
	.text:08048974                               loc_8048974:                            ; CODE XREF: sigusr1_handler+6Dj
	.text:08048974 81 7D F4 09 16 00 00                          cmp     [ebp+var_C], 1609h
	.text:0804897B 0F 83 31 00 00 00                             jnb     loc_80489B2
	.text:08048981 8B 45 F4                                      mov     eax, [ebp+var_C]
	.text:08048984 0F B6 04 05 59 B6 04 08                       movzx   eax, byte_804B659[eax]
	.text:0804898C 8B 4D F4                                      mov     ecx, [ebp+var_C]
	.text:0804898F 0F B6 14 0D 50 A0 04 08                       movzx   edx, byte_804A050[ecx]
	.text:08048997 31 C2                                         xor     edx, eax
	.text:08048999 88 D3                                         mov     bl, dl
	.text:0804899B 88 1C 0D 50 A0 04 08                          mov     byte_804A050[ecx], bl
	.text:080489A2 8B 45 F4                                      mov     eax, [ebp+var_C]
	.text:080489A5 05 01 00 00 00                                add     eax, 1
	.text:080489AA 89 45 F4                                      mov     [ebp+var_C], eax
	.text:080489AD E9 C2 FF FF FF                                jmp     loc_8048974
	.text:080489B2                               ; ---------------------------------------------------------------------------
	.text:080489B2
	.text:080489B2                               loc_80489B2:                            ; CODE XREF: sigusr1_handler+3Bj
	.text:080489B2 B8 04 00 00 00                                mov     eax, 4
	.text:080489B7 C7 04 24 04 00 00 00                          mov     dword ptr [esp], 4 ; sig
	.text:080489BE 89 45 E8                                      mov     [ebp+var_18], eax
	.text:080489C1 E8 BA FA FF FF                                call    _raise
	.text:080489C6 89 45 E4                                      mov     [ebp+var_1C], eax
	.text:080489C9 83 C4 24                                      add     esp, 24h
	.text:080489CC 5B                                            pop     ebx
	.text:080489CD 5D                                            pop     ebp
	.text:080489CE C3                                            retn
	.text:080489CE                               sigusr1_handler endp

Like before, this code acknowledges the `SIGUSR1` at the beginning, and then raises a `SIGILL` at the end, so that's almost certainly what's causing the `SIGILL` we saw earlier. However, in between those two parts, at `08048974`, there's some other stuff going on. The program is looping through 0x1609 (=5641) times and XORing two values together. If we look at the values at `0804B659` and `0804A050`, they seem to be basically random junk. This generally makes sense, if they're being XORed together to produce some other data.

This kind of thing shows up a lot in reverse engineering challenges. Having the data XORed with something makes it so that you can't see the data when running `strings` on the binary, because the data isn't in plain text. When you run the program, it XORs various things together to get back the original data only during runtime, making it harder to retrieve.

For starters, let's modify the program so that it doesn't raise that `SIGILL` anymore so that we can see what it does afterwards. There are many different ways of doing this: some people patch programs using disassemly tools, some people use hex editors, etc. I've gotten accustomed to using `vim` and `xxd`, so that's how I'll do it here.

From the disassembly, we can see that the function call in `sigusr1_handler` that produces the `SIGILL` is located at `080489C1`, and it's 6 bytes long with the opcode bytes `E8 BA FA FF FF`. I create a new copy of the binary and then open up the copy in `vim`. Then, I run the command `:%!xxd`, which runs `xxd` against the contents of the file we're editing, providing us with an editable hexdump. I search for the string `e8ba` to find the opcode we want to get rid of, but it's not found. This means that the instruction apparently isn't byte-aligned within the file. Instead, I search for `bafa` and find the following line:

	00009c0: e8e8 bafa ffff 8945 e483 c424 5b5d c390  .......E...$[]..

I replace the "e8 bafa ffff" with "90 9090 9090" to replace the `call` instruction with `nop` instructions, so that it looks like this:

	00009c0: e890 9090 9090 8945 e483 c424 5b5d c390  .......E...$[]..

After that, I convert the file from the hex dump format back into the original raw format by running `:%!xxd -r`, and then save and quit by running `:wq`.

Having patched out the call to `_raise`, I try running the patched copy, hoping that it will give me something good. I run it, and it gives me a fairly random-looking sequence of hex digits. In fact, it looks like it gives different output every time I run it, which is disconcerting. If the output changes every time, it's not likely to contain the flag.

Just in case, I run `xxd` on it to convert from hex back to raw data and see if it contains anything interesting, but it unfortunately doesn't:

	$ ./ccb516735156cbd2cb9282504e8663e6 | xxd -r -p > test
	$ file test
	test: data

One thing that is a bit reassuring is that if we look at the length of the file, it's actually 5640 bytes:

	$ wc test
	  11  123 5640 test

It's probably not a coincidence that the program XORs 5641 bytes of data together, and then later on gives us 5640 bytes of hex-encoded output. However, it's not at all clear what's happening in between the XOR operations and the actual output, so we're going to have to dig deeper in order to find out what's happening there.
