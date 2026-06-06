APP_STYLESHEET = """
QMainWindow, QWidget {
    background: #20242b;
    color: #e6e9ef;
    font-family: "Segoe UI", "Inter", "Noto Sans", Arial, sans-serif;
    font-size: 13px;
}
QFrame#Sidebar {
    background: #171b21;
    border-right: 1px solid #303640;
}
QFrame#Header, QFrame#Card, QFrame#Panel {
    background: #2a3038;
    border: 1px solid #3a424d;
    border-radius: 8px;
}
QFrame#Card {
    padding: 4px;
}
QLabel#Title {
    font-size: 22px;
    font-weight: 700;
}
QLabel#SectionTitle {
    font-size: 18px;
    font-weight: 700;
}
QLabel#Muted {
    color: #aeb6c2;
}
QPushButton {
    background: #344152;
    border: 1px solid #4a5565;
    border-radius: 6px;
    padding: 8px 12px;
    color: #f4f6f8;
    min-height: 18px;
}
QPushButton:hover {
    background: #405169;
}
QPushButton#NavButton {
    text-align: left;
    border: 0;
    border-radius: 6px;
    padding: 11px 14px;
    background: transparent;
}
QPushButton#NavButton:checked {
    background: #334155;
    border-left: 4px solid #3fb27f;
}
QLineEdit, QTextEdit, QComboBox, QSpinBox {
    background: #1d2229;
    border: 1px solid #46505d;
    border-radius: 6px;
    padding: 8px;
    color: #eef2f7;
}
QLineEdit[invalid="true"] {
    border: 1px solid #dc5b5b;
}
QTextEdit[invalid="true"] {
    border: 1px solid #dc5b5b;
}
QTableWidget {
    background: #1f252d;
    alternate-background-color: #252c35;
    gridline-color: #3a424d;
    border: 1px solid #3a424d;
    border-radius: 6px;
    selection-background-color: #3f536a;
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #313946;
    color: #f3f5f8;
    border: 0;
    padding: 8px;
    font-weight: 600;
}
QSplitter::handle {
    background: #303640;
}
QCheckBox {
    spacing: 8px;
}
"""

COLORS = {
    "green": "#3fb27f",
    "yellow": "#d5a93b",
    "red": "#dc5b5b",
    "muted": "#aeb6c2",
}
