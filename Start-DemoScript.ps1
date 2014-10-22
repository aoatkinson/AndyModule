# Start-DemoScript

param (
    [Parameter(Mandatory=$true)][string]$file
)

$script = Get-Content $file

$line = 0
while ($line -lt $script.Length) {
    $content = ""
    while ($script[$line] -ne $null -and !$script[$line].StartsWith("#pause-demo")) {
        $content += $script[$line] + "`n"
        $line++
    }
    .\Format-Color.ps1 -content $content
    pause
    Invoke-Expression $content
    $line++
}

"Demo $file completed"
pause
