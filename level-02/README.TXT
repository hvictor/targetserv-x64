**Level 02: Win 11 x64 ASLR + DEP Bypass & Egghunting**

HINTS ON HOW TO SOLVE THIS LEVEL:
1. Perform Reverse Engineering using IDA or Ghidra and discover the updated network communication protocol.

2. Bypass ASLR:
- Discover the vulnerability allowing you to leak the Base Address of the main module
- Discover the vulnerability allowing you to leak the location of an interesting Return Address
- Discover the vulnerability allowing you to overwrite that Return Address

3. Bypass DEP:
- Build your ROP chain 

4. Achieve Code Execution:
- Run the application multiple times. Note where you shellcode is being stored across different runs.
- Find a way to execute your shellcode, independently of its dynamic position in memory.

WARNING: Your egghunter could take VERY long (days) to find the shellcode in the x64 virtual address space:
In order to validate your exploit quickly, pause debugging in the egghunter code and set the current address to a small distance from your shellcode, e.g. 0x1000 bytes.
Independently of which egghunter you are using, it will quickly find your shellcode. This way you don't have to wait many hours / days to assess correctness of your exploit.

HINTS ON WHAT NOT TO DO:
- Do not exploit the same vulnerability as Level 01.