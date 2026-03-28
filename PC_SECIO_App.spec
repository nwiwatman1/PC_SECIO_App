# PC_SECIO_App.spec  —  PyInstaller build spec
# Run with:  pyinstaller PC_SECIO_App.spec

block_cipher = None

a = Analysis(
    ['pc_secio.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'psutil', 'psutil._pswindows',
        'sqlite3', 'json', 'csv',
        'urllib.request', 'urllib.parse',
        'socket', 'threading', 'tkinter',
        'tkinter.ttk', 'tkinter.messagebox', 'tkinter.filedialog',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'PIL', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PC_SECIO_App',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # no black console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version=None,
    uac_admin=True,         # request admin rights (needed for all connections)
)
