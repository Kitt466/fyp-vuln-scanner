# PyInstaller build spec for VulnScan (one-file, windowed).
# Build on each OS separately:   pyinstaller vulnscan.spec
#   Windows -> dist\VulnScan.exe      Linux -> dist/VulnScan
# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ["run_vulnscan.py"],
    pathex=[],
    binaries=[],
    datas=[("vulnscan/config.yaml", "vulnscan")],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    # Qt modules VulnScan doesn't use; excluding them keeps the file much smaller.
    excludes=[
        "tkinter",
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebChannel",
        "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.QtQuick", "PySide6.QtQml",
        "PySide6.QtMultimedia", "PySide6.QtCharts", "PySide6.QtDataVisualization",
        "PySide6.QtPdf", "PySide6.QtBluetooth", "PySide6.QtSensors",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="VulnScan",
    debug=False,
    strip=False,
    upx=False,
    console=False,          # no terminal window behind the GUI
    runtime_tmpdir=None,
)
