$encodedFile = "C:\path\to\harmless_script.b64"
$decodedFile = "C:\path\to\decoded_script.ps1"

$encodedText = Get-Content -Path $encodedFile -Raw
$bytes = [System.Convert]::FromBase64String($encodedText)
$plainText = [System.Text.Encoding]::UTF8.GetString($bytes)

Set-Content -Path $decodedFile -Value $plainText -Force
Invoke-Expression -Command $decodedFile

