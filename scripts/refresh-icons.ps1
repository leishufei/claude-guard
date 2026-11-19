#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path
)

$ErrorActionPreference = 'Stop'
if (-not ('ClaudeGuard.ShellIcons' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace ClaudeGuard {
    public static class ShellIcons {
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern void SHChangeNotify(
            uint eventId, uint flags, string item1, IntPtr item2);
    }
}
'@
}
foreach ($item in $Path) {
    $resolved = (Resolve-Path -LiteralPath $item).Path
    [ClaudeGuard.ShellIcons]::SHChangeNotify(0x2000, 0x1005, $resolved, [IntPtr]::Zero)
}
[ClaudeGuard.ShellIcons]::SHChangeNotify(0x08000000, 0x1000, $null, [IntPtr]::Zero)
