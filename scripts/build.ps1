#requires -Version 5.1
param([string]$OutputDirectory = 'dist')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $projectRoot
try {
    python -B -m unittest discover -s tests -p 'test_*.py'
    if ($LASTEXITCODE -ne 0) { throw 'Python 单元测试失败。' }
    $outputPath = Join-Path $projectRoot $OutputDirectory
    $targetExe = Join-Path $outputPath 'ClaudeGuard.exe'
    $buildDir = Join-Path $env:TEMP 'ClaudeGuard-build'
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    $specPath = Join-Path $buildDir 'ClaudeGuard.spec'
    $specContent = @'
# -*- mode: python ; coding: utf-8 -*-
import os

project_root = os.environ['CLAUDE_BUILD_ROOT']
a = Analysis(
    [os.path.join(project_root, 'src', 'claude_tool.py')],
    pathex=[os.path.join(project_root, 'src')],
    binaries=[],
    datas=[
        (os.path.join(project_root, 'assets', 'App.ico'), '.'),
        (os.path.join(project_root, 'assets', 'fonts'), 'fonts'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PySide6.QtNetwork', 'PySide6.QtOpenGL', 'PySide6.QtOpenGLWidgets',
        'PySide6.QtPdf', 'PySide6.QtPdfWidgets', 'PySide6.QtPrintSupport',
        'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtQuickWidgets',
        'PySide6.QtSql', 'PySide6.QtTest', 'PySide6.QtVirtualKeyboard',
        'tkinter', 'unittest', 'pydoc', 'doctest',
    ],
    noarchive=False,
)

drop_dlls = {
    'opengl32sw.dll', 'qt6network.dll', 'qt6opengl.dll', 'qt6pdf.dll',
    'qt6qml.dll', 'qt6qmlmeta.dll', 'qt6qmlmodels.dll', 'qt6qmlworkerscript.dll',
    'qt6quick.dll', 'qt6virtualkeyboard.dll',
}
keep_plugins = {
    'qwindows.dll', 'qmodernwindowsstyle.dll', 'qsvgicon.dll', 'qico.dll', 'qsvg.dll',
}

def keep_entry(dest, _src, _kind):
    norm = dest.replace('/', '\\').lower()
    base = os.path.basename(norm)
    if base in drop_dlls or norm.startswith('pyside6\\translations\\'):
        return False
    if norm.startswith('pyside6\\plugins\\'):
        return base in keep_plugins
    return True

a.binaries = [e for e in a.binaries if keep_entry(*e)]
a.datas = [e for e in a.datas if keep_entry(*e)]

pyz = PYZ(a.pure, a.zipped_data)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ClaudeGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    icon=[os.path.join(project_root, 'assets', 'App.ico')],
)
'@
    Set-Content -Path $specPath -Value $specContent -Encoding UTF8
    $env:CLAUDE_BUILD_ROOT = $projectRoot
    try {
        python -B -m PyInstaller --noconfirm `
            --distpath $outputPath `
            --workpath $buildDir `
            $specPath
        if ($LASTEXITCODE -ne 0) { throw 'EXE 打包失败。' }
    } finally {
        Remove-Item Env:CLAUDE_BUILD_ROOT -ErrorAction SilentlyContinue
    }
    & (Join-Path $PSScriptRoot 'refresh-icons.ps1') -Path $targetExe
    Write-Output ('已生成：' + $targetExe)
} finally {
    Pop-Location
}
