cd $env:userprofile

$module = Test-ModuleManifest .\module.psd1

$demos = @()
foreach ($demo in $module.PrivateData.DemoFiles.Keys) {
    $demoObj = New-Object PSObject -Property @{Name=$demo;Value=$module.PrivateData.DemoFiles[$demo]}
    $demos += $demoObj
}

$default = 0
while ($true) {
    cls
    $choices = @()
    $caption = "Choose demo"
    $message = "Which demo do you want to start?"
    for ($index = 0;$index -lt $demos.Count; $index++) {
        $output = "{0}) {1}`n" -f $index,$demos[$index].Name
        Write-Host $output
        $output = "`t{0}`n" -f $demos[$index].Value
        Write-Host $output
        $choices += New-Object System.Management.Automation.Host.ChoiceDescription $index,$demos[$index].Name
    }
    $demoChoices = [System.Management.Automation.Host.ChoiceDescription[]] $choices
    $selection = $host.ui.PromptForChoice($caption,$message,$demoChoices,$default)
    $demoscript = "{0}.ps1" -f $demos[$selection].Name
    cls
    "Starting demo {0}..." -f $demoscript
    .\Start-DemoScript.ps1 $demoscript
    $default++
    if ($default -ge $demos.Count) {
        $default = 0
    }
}