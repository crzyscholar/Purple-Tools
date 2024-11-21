$inputFile = "C:\path\to\harmless_script.ps1"
$outputFile = "C:\path\to\harmless_script.b64"

$plainText = Get-Content -Path $inputFile -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)
$encodedText = [System.Convert]::ToBase64String($bytes)
Set-Content -Path $outputFile -Value $encodedText

