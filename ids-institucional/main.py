import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from app.gui.main_window import MainWindow
from app.gui.styles import APP_STYLESHEET
from app.utils.config_loader import ensure_project_files


def main() -> int:
    """Punto de entrada de la aplicacion IDS Institucional."""
    base_path = Path(__file__).resolve().parent
    ensure_project_files(base_path)

    app = QApplication(sys.argv)
    app.setApplicationName("IDS Institucional")
    app.setStyleSheet(APP_STYLESHEET)

    window = MainWindow(base_path)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
