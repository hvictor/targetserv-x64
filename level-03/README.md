**Level 03: File Xfer Exploitation on Windows 11**

HINTS ON HOW TO SOLVE THIS LEVEL:
1. Perform Reverse Engineering using IDA or Ghidra and discover the network communication protocol to perform File Transfers.

2. Bypass ASLR:
- Discover the vulnerability allowing you to leak the Base Address of the main module
- Discover the memory corruption vulnerability affecting one of the File Transfer processes.

3. Bypass DEP:
- Build your ROP chain 

4. Achieve Code Execution:
- Find a way to execute your shellcode. Exploitation may require separate communications.

HINTS ON WHAT NOT TO DO:
- Do not exploit memory corruption vulns from the previous levels.
