# Purple-Tools

### reflectiveShellcode.ps1
this powershell script downloads the shellcode from the specified server and port and without writing it to the disk, reflectively executes it in the memory.
for now it doesn't work.

### shellcode.bin
raw shellcode for popping a calc

### base64.txt
is the shellcode for popping calc encoded with base64

### secondreflect.ps1
tried to get [reflectiveShellcode.ps1](https://github.com/crzyscholar/Purple-Tools/blob/main/reflectiveShellcode.ps1) work

### thirdreflect.ps1 
tried to fix [secondreflect.ps1](https://github.com/crzyscholar/Purple-Tools/blob/main/thirdreflect.ps1) unsuccessfully 

### bypassAMSI.ps1
Turla used a similar powershell script to bypass Microsoft Antimalware Scan Interface(AMSI)

### wmiSubscription.ps1
this is one of the persistence techniques used by turla. $maliciousCommand being the powershell one-liner.
comes with cleanup commands.

### dll.c 
test dll for testing out dll injection

### injectDll.c
dll injection

### injection.c
injection

### jitDecryption.c
just in time decryption(I tried) for evasion
