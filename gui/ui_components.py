from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QFrame, QLabel, QVBoxLayout


def card_style() -> str:
    return """
        QFrame {
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 3px;
        }
    """


class SummaryCard(QFrame):
    def __init__(
        self,
        title: str,
        accent: str,
        subtitle: str = "Čakam podatke",
        value_size: int = 18,
        margins=(14, 12, 14, 12),
        title_color: str = "#94a3b8",
    ):
        super().__init__()
        self._accent = accent
        self.setStyleSheet(card_style())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(*margins)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {title_color}; font-weight: bold;")
        self.value_label = QLabel("0")
        self.value_label.setFont(QFont("Segoe UI", value_size, QFont.Bold))
        self.value_label.setStyleSheet(f"color: {accent};")
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setStyleSheet("color: #64748b;")

        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)

    def set_value(self, value: str, subtitle: str = None, accent: str = None):
        self.value_label.setText(value)
        self.value_label.setStyleSheet(f"color: {accent or self._accent};")
        if subtitle is not None:
            self.subtitle_label.setText(subtitle)
