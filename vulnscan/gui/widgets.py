"""Small shared widgets."""
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout


def label(text="", name=None, wrap=False):
    lbl = QLabel(text)
    if name:
        lbl.setObjectName(name)
    lbl.setWordWrap(wrap)
    return lbl


class Card(QFrame):
    """Rounded panel with its own vertical layout."""

    def __init__(self, parent=None, spacing=10, margins=18):
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(margins, margins, margins, margins)
        self.body.setSpacing(spacing)


class StatCard(Card):
    def __init__(self, caption, parent=None):
        super().__init__(parent, spacing=2, margins=14)
        self.num = label("-", "StatNum")
        self.body.addWidget(self.num)
        self.body.addWidget(label(caption.upper(), "StatLabel"))

    def set(self, value, color=None):
        self.num.setText(str(value))
        self.num.setStyleSheet(f"color: {color};" if color else "")


class ChipRow(QHBoxLayout):
    def __init__(self):
        super().__init__()
        self.setSpacing(6)
        self.addStretch(1)

    def set_chips(self, chips):
        """chips: list of (text, warn: bool)."""
        while self.count() > 1:
            item = self.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for i, (text, warn) in enumerate(chips):
            self.insertWidget(i, label(text, "ChipWarn" if warn else "Chip"))


def context_chips(ctx):
    chips = []
    if ctx.get("asset_name"):
        chips.append((ctx["asset_name"], False))
    if ctx.get("business_function"):
        chips.append((ctx["business_function"], False))
    chips.append(("Internet-facing" if ctx.get("internet_facing") else "Internal only",
                  bool(ctx.get("internet_facing"))))
    chips.append(("Sensitive data" if ctx.get("sensitive_data") else "No sensitive data",
                  bool(ctx.get("sensitive_data"))))
    chips.append((f"Criticality: {ctx.get('criticality', 'medium').capitalize()}",
                  ctx.get("criticality") == "high"))
    return chips
