# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(
    ['WWMI_FIX_14.py'],
    pathex=[],
    binaries=[],
    datas=[('version_info.txt', '.'), ('manifest.xml', '.'), ('C:\\Genshin Migoto\\3dmigoto\\Mods\\Skill Issue\\genshin_env\\Scripts\\FixTexture.zip', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='WWMI_FIX_14',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
    manifest='manifest.xml',
)
