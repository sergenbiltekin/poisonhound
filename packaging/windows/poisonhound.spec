# PyInstaller spec for the standalone Windows executables.
#
# Produces two onefile exes:
#   - poisonhound.exe          the foreground CLI (poisonhound.cli:main)
#   - poisonhound-service.exe  the Windows Service wrapper (poisonhound.win_service:main)
#
# Build with (from the repo root, inside a venv with `.[dev,build-exe]` installed):
#   pyinstaller packaging/windows/poisonhound.spec --distpath dist/windows --clean
#
# scapy and pywin32 both need hidden imports that PyInstaller can't infer by
# static analysis alone; pyinstaller-hooks-contrib ships pre-built hooks for
# scapy that cover almost all of it automatically. win32timezone is the one
# pywin32 import that's missed even with the contrib hooks installed, since
# nothing imports it directly - it's loaded dynamically by pywintypes.

import os

from PyInstaller.utils.hooks import copy_metadata

REPO_ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
SRC = os.path.join(REPO_ROOT, "src")
DASHBOARD = os.path.join(SRC, "poisonhound", "dashboard")

# poisonhound.__version__ reads importlib.metadata.version("poisonhound"),
# which needs the package's dist-info to be present at runtime - normally
# supplied by an installed wheel, but a frozen exe has no such install.
# copy_metadata() bundles it in so __version__ still resolves from
# pyproject.toml's version instead of needing a second hardcoded copy here.
datas = [
    (os.path.join(DASHBOARD, "templates"), "poisonhound/dashboard/templates"),
    (os.path.join(DASHBOARD, "static"), "poisonhound/dashboard/static"),
] + copy_metadata("poisonhound")
hidden_imports = ["win32timezone"]

cli_analysis = Analysis(
    [os.path.join(SPECPATH, "entry_cli.py")],
    pathex=[SRC],
    datas=datas,
    hiddenimports=hidden_imports,
)
cli_pyz = PYZ(cli_analysis.pure)
cli_exe = EXE(
    cli_pyz,
    cli_analysis.scripts,
    cli_analysis.binaries,
    cli_analysis.datas,
    [],
    name="poisonhound",
    console=True,
)

service_analysis = Analysis(
    [os.path.join(SPECPATH, "entry_service.py")],
    pathex=[SRC],
    datas=datas,
    hiddenimports=hidden_imports,
)
service_pyz = PYZ(service_analysis.pure)
service_exe = EXE(
    service_pyz,
    service_analysis.scripts,
    service_analysis.binaries,
    service_analysis.datas,
    [],
    name="poisonhound-service",
    console=True,
)
