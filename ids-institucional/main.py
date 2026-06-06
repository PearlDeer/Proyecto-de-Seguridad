import os
import sys
from pathlib import Path


BASE_PATH = Path(__file__).resolve().parent
VENV_PYTHON = BASE_PATH / "venv" / "bin" / "python"
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.theme.dbus=false;qt.qpa.theme.gnome=false")
os.environ.setdefault("QT_QPA_PLATFORMTHEME", "")
if (
    VENV_PYTHON.exists()
    and Path(sys.executable).absolute() != VENV_PYTHON.absolute()
    and os.environ.get("IDS_NO_VENV_REEXEC") != "1"
):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), *sys.argv])

from PyQt6.QtWidgets import QApplication

from app.gui.main_window import MainWindow
from app.gui.styles import APP_STYLESHEET
from app.utils.config_loader import ensure_project_files


def main() -> int:
    """Punto de entrada de la aplicacion IDS Institucional."""
    base_path = BASE_PATH
    ensure_project_files(base_path)

    app = QApplication(sys.argv)
    app.setApplicationName("IDS Institucional")
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLESHEET)

    window = MainWindow(base_path)
    window.showMaximized()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
