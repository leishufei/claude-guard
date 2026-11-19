#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$executable = Join-Path $projectRoot 'dist\ClaudeGuard.exe'
$script = Join-Path $projectRoot 'main.py'
$icon = Join-Path $projectRoot 'assets\App.ico'
if (Test-Path -LiteralPath $executable) {
    $target = $executable
    $arguments = ''
    $workingDirectory = Split-Path $executable -Parent
} else {
    $pythonw = Join-Path (Split-Path (Get-Command python.exe).Source -Parent) 'pythonw.exe'
    if (-not (Test-Path -LiteralPath $pythonw)) {
        throw '未找到 pythonw.exe，请先运行 build.ps1 生成 EXE。'
    }
    $target = $pythonw
    $arguments = '"' + $script + '"'
    $workingDirectory = $projectRoot
}
$desktopPath = [Environment]::GetFolderPath('Desktop')
$shortcutPath = Join-Path $desktopPath 'Claude Guard.lnk'
if (Test-Path -LiteralPath $shortcutPath) {
    $existing = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
    if ($existing.TargetPath -ne $target) {
        Remove-Item -LiteralPath $shortcutPath -Force
    }
}
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $target
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = $workingDirectory
$shortcut.IconLocation = $icon + ',0'
$shortcut.Description = 'Claude Guard · Claude Desktop 安全启动、流量守护与环境切换'
$shortcut.Save()
& (Join-Path $PSScriptRoot 'refresh-icons.ps1') -Path $shortcutPath
Write-Output $shortcutPath
