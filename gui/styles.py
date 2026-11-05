"""
Slogovna datoteka PyQt5 - temna tema nadzorne plošče NetSentinel IDS.
"""

DARK_STYLESHEET = """
    QMainWindow {
        background-color: #1e1e1e;
        color: #aaa;
    }

    QWidget {
        background-color: #1e1e1e;
        color: #aaa;
    }

    QTabWidget::pane {
        border: 1px solid #444;
    }

    QTabBar::tab {
        background-color: #2b2b2b;
        color: #aaa;
        padding: 8px 20px;
        margin: 2px;
        border: 1px solid #444;
    }

    QTabBar::tab:selected {
        background-color: #3b3b3b;
        color: #fff;
        border-bottom: 3px solid #00ff00;
    }

    QPushButton {
        background-color: #3b3b3b;
        color: #fff;
        border: 1px solid #555;
        border-radius: 4px;
        padding: 6px 12px;
        font-weight: bold;
    }

    QPushButton:hover {
        background-color: #4b4b4b;
        border: 1px solid #00ff00;
    }

    QPushButton:pressed {
        background-color: #2b2b2b;
    }

    QLineEdit {
        background-color: #2b2b2b;
        color: #fff;
        border: 1px solid #444;
        border-radius: 4px;
        padding: 5px;
        selection-background-color: #00ff00;
    }

    QLineEdit:focus {
        border: 1px solid #00ff00;
    }

    QSpinBox, QDoubleSpinBox {
        background-color: #2b2b2b;
        color: #fff;
        border: 1px solid #444;
        border-radius: 4px;
        padding: 5px;
    }

    QSpinBox::up-button, QSpinBox::down-button,
    QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
        background-color: #3b3b3b;
        width: 16px;
    }

    QComboBox {
        background-color: #2b2b2b;
        color: #fff;
        border: 1px solid #444;
        border-radius: 4px;
        padding: 5px;
        selection-background-color: #00ff00;
    }

    QComboBox::drop-down {
        border: none;
    }

    QComboBox QAbstractItemView {
        background-color: #2b2b2b;
        color: #fff;
        selection-background-color: #00ff00;
        selection-color: #000;
    }

    QTableWidget {
        background-color: #2b2b2b;
        color: #aaa;
        border: 1px solid #444;
        gridline-color: #333;
    }

    QTableWidget::item {
        padding: 5px;
        border-bottom: 1px solid #333;
    }

    QTableWidget::item:selected {
        background-color: #00ff00;
        color: #000;
    }

    QHeaderView::section {
        background-color: #3b3b3b;
        color: #ddd;
        padding: 5px;
        border: 1px solid #444;
        font-weight: bold;
    }

    QLabel {
        color: #aaa;
    }

    QGroupBox {
        color: #fff;
        border: 1px solid #444;
        border-radius: 4px;
        margin-top: 10px;
        padding-top: 10px;
        font-weight: bold;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 3px 0 3px;
    }

    QCheckBox {
        color: #aaa;
        spacing: 5px;
    }

    QCheckBox::indicator {
        width: 18px;
        height: 18px;
    }

    QCheckBox::indicator:unchecked {
        background-color: #2b2b2b;
        border: 1px solid #444;
    }

    QCheckBox::indicator:checked {
        background-color: #00ff00;
        border: 1px solid #00ff00;
    }

    QScrollBar:vertical {
        background-color: #2b2b2b;
        width: 12px;
        margin: 0;
    }

    QScrollBar::handle:vertical {
        background-color: #555;
        border-radius: 6px;
        min-height: 20px;
    }

    QScrollBar::handle:vertical:hover {
        background-color: #00ff00;
    }

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        border: none;
        background: none;
    }

    QStatusBar {
        background-color: #2b2b2b;
        color: #aaa;
        border-top: 1px solid #444;
    }

    QStatusBar::item {
        border: none;
    }
"""
