"""History page: list of past point-in-time scans stored locally."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QLineEdit,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from .. import storage
from . import theme
from .widgets import label

STATUS_COLOR = {"done": theme.ACCENT, "running": theme.SEVERITY["MEDIUM"],
                "failed": theme.SEVERITY["CRITICAL"], "cancelled": theme.MUTED}


class HistoryPage(QWidget):
    open_requested = Signal(str)   # scan id

    COLUMNS = ["Target", "Asset", "Profile", "Started", "Status", "CVEs", "Top priority"]

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 20)
        root.setSpacing(12)

        head = QHBoxLayout()
        head.addWidget(label("Scan history", "H1"))
        head.addStretch(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by target or asset...")
        self.search.setClearButtonEnabled(True)
        self.search.setMaximumWidth(300)
        self.search.textChanged.connect(self._apply_filter)
        head.addWidget(self.search)
        root.addLayout(head)
        root.addWidget(label("Stored only on this computer. Double-click a scan to open it.",
                             "Muted"))

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.doubleClicked.connect(lambda _i: self._open())
        root.addWidget(self.table, 1)

        row = QHBoxLayout()
        self.open_btn = QPushButton("Open")
        self.open_btn.clicked.connect(self._open)
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setObjectName("Danger")
        self.delete_btn.clicked.connect(self._delete)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        row.addWidget(self.open_btn)
        row.addWidget(self.delete_btn)
        row.addStretch(1)
        row.addWidget(refresh)
        root.addLayout(row)

    def refresh(self):
        scans = storage.list_all()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(scans))
        for i, s in enumerate(scans):
            summary = (s["result"] or {}).get("summary") if s["result"] else None
            top = summary.get("top_finding") if summary else None
            values = [
                s["target"],
                s["context"].get("asset_name") or "-",
                self.cfg["profiles"].get(s["profile"], {}).get("label", s["profile"])
                + (" (demo)" if (s["result"] or {}).get("backend") == "demo" else ""),
                s["created_at"].replace("T", " "),
                s["status"],
                str(summary["cves"]) if summary else "-",
                top["priority"] if top else "-",
            ]
            for j, v in enumerate(values):
                item = QTableWidgetItem(v)
                if j == 0:
                    item.setData(Qt.UserRole, s["id"])
                if j == 4:
                    item.setForeground(QColor(STATUS_COLOR.get(s["status"], theme.INK)))
                if j == 6 and top:
                    item.setForeground(QColor(theme.PRIORITY.get(top["priority"], theme.INK)))
                self.table.setItem(i, j, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        self._apply_filter()

    def _apply_filter(self):
        q = self.search.text().strip().lower()
        for i in range(self.table.rowCount()):
            text = " ".join((self.table.item(i, c).text() if self.table.item(i, c) else "")
                            for c in (0, 1)).lower()
            self.table.setRowHidden(i, bool(q) and q not in text)

    def _selected_id(self):
        row = self.table.currentRow()
        if row < 0 or self.table.isRowHidden(row):
            return None
        item = self.table.item(row, 0)
        return item.data(Qt.UserRole) if item else None

    def _open(self):
        scan_id = self._selected_id()
        if scan_id:
            self.open_requested.emit(scan_id)

    def _delete(self):
        scan_id = self._selected_id()
        if not scan_id:
            return
        if QMessageBox.question(self, "Delete scan",
                                "Delete this scan from history? This cannot be undone.") \
                == QMessageBox.Yes:
            storage.delete(scan_id)
            self.refresh()
