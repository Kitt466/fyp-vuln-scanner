"""New scan page: target, profile (FR-01/02) and asset context (FR-13)."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QGridLayout, QHBoxLayout,
                               QLineEdit, QPushButton, QScrollArea, QVBoxLayout,
                               QWidget)

from ..config import is_admin
from ..validation import CRITICALITY, clean_context, validate_target
from .widgets import Card, label


class NewScanPage(QWidget):
    start_requested = Signal(str, str, dict, str)   # target, profile, context, backend
    backend_changed = Signal(str)

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        host = QWidget()
        scroll.setWidget(host)
        page = QVBoxLayout(host)
        page.setContentsMargins(28, 24, 28, 24)
        page.setSpacing(16)

        page.addWidget(label("New scan", "H1"))
        page.addWidget(label(
            "Detect open ports and service versions, match them to NVD CVEs, and rank "
            "the findings by how important this asset is to you.", "Muted", wrap=True))

        # ---- Target and profile ----
        target_card = Card()
        target_card.body.addWidget(label("Target", "H2"))
        self.target = QLineEdit()
        self.target.setObjectName("Mono")
        self.target.setPlaceholderText("192.168.56.101, 10.0.0.0/28 or host.local")
        self.target.returnPressed.connect(self._submit)
        target_card.body.addWidget(self.target)
        target_card.body.addWidget(label(
            f"Single IP, CIDR range (up to {cfg['limits']['max_addresses']} addresses) "
            "or hostname.", "Hint"))

        target_card.body.addSpacing(6)
        row_top = QGridLayout()
        row_top.setHorizontalSpacing(14)
        row_top.addWidget(label("Scan profile", "H2"), 0, 0)
        row_top.addWidget(label("Data source", "H2"), 0, 1)
        self.backend = QComboBox()
        self.backend.addItem("Live scan (Nmap + NVD)", "engine")
        self.backend.addItem("Demo data (no network traffic)", "demo")
        self.backend.setCurrentIndex(max(self.backend.findData(cfg["backend"]), 0))
        self.backend.currentIndexChanged.connect(
            lambda: self.backend_changed.emit(self.backend.currentData()))
        self.profile = QComboBox()
        row_top.addWidget(self.profile, 1, 0)
        row_top.addWidget(self.backend, 1, 1)
        row_top.setColumnStretch(0, 2)
        row_top.setColumnStretch(1, 1)
        for key, p in cfg["profiles"].items():
            self.profile.addItem(p.get("label", key), key)
        idx = self.profile.findData(cfg["default_profile"])
        self.profile.setCurrentIndex(max(idx, 0))
        self.profile.currentIndexChanged.connect(self._update_profile_hint)
        target_card.body.addLayout(row_top)
        self.profile_hint = label("", "Hint", wrap=True)
        self.profile_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        target_card.body.addWidget(self.profile_hint)
        page.addWidget(target_card)

        # ---- Asset context ----
        ctx_card = Card()
        ctx_card.body.addWidget(label("Asset context", "H2"))
        ctx_card.body.addWidget(label(
            "Used to prioritise findings beyond the raw CVSS score.", "Hint"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        self.asset_name = QLineEdit()
        self.asset_name.setMaxLength(80)
        self.asset_name.setPlaceholderText("e.g. Office file server")
        self.business_function = QLineEdit()
        self.business_function.setMaxLength(120)
        self.business_function.setPlaceholderText("e.g. Stores HR and payroll records")
        self.criticality = QComboBox()
        for c in CRITICALITY:
            self.criticality.addItem(c.capitalize(), c)
        self.criticality.setCurrentIndex(1)
        grid.addWidget(label("Asset name", "Muted"), 0, 0)
        grid.addWidget(label("Business function", "Muted"), 0, 1)
        grid.addWidget(self.asset_name, 1, 0)
        grid.addWidget(self.business_function, 1, 1)
        grid.addWidget(label("Business criticality", "Muted"), 2, 0)
        grid.addWidget(self.criticality, 3, 0)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        ctx_card.body.addLayout(grid)
        self.internet_facing = QCheckBox("Internet-facing (reachable from outside the network)")
        self.sensitive_data = QCheckBox("Stores sensitive data (personal, financial or confidential)")
        ctx_card.body.addWidget(self.internet_facing)
        ctx_card.body.addWidget(self.sensitive_data)
        page.addWidget(ctx_card)

        # ---- Authorisation + start ----
        self.authorised = QCheckBox("I own this target or have written permission to scan it.")
        page.addWidget(self.authorised)
        self.error = label("", "Error", wrap=True)
        self.error.hide()
        page.addWidget(self.error)
        row = QHBoxLayout()
        self.start_btn = QPushButton("Start scan")
        self.start_btn.setObjectName("Primary")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.clicked.connect(self._submit)
        row.addWidget(self.start_btn)
        row.addStretch(1)
        page.addLayout(row)
        page.addStretch(1)

        self._update_profile_hint()

    def _update_profile_hint(self):
        key = self.profile.currentData()
        p = self.cfg["profiles"].get(key, {})
        text = f"{p.get('description', '')}\nnmap {p.get('args', '')}"
        if p.get("requires_admin") and not is_admin():
            text += ("\nNote: OS detection needs administrator/root rights. Run VulnScan "
                     "as administrator (Windows) or with sudo (Linux).")
        self.profile_hint.setText(text)

    def set_busy(self, busy: bool):
        self.start_btn.setEnabled(not busy)
        self.start_btn.setText("Scan in progress..." if busy else "Start scan")

    def _submit(self):
        if not self.start_btn.isEnabled():
            return
        errors = []
        try:
            target = validate_target(self.target.text(), self.cfg["limits"]["max_addresses"])
        except ValueError as exc:
            errors.append(str(exc))
            target = None
        if not self.authorised.isChecked():
            errors.append("Confirm you are authorised to scan this target.")
        if errors:
            self.error.setText("\n".join(errors))
            self.error.show()
            return
        self.error.hide()
        context = clean_context({
            "asset_name": self.asset_name.text(),
            "business_function": self.business_function.text(),
            "criticality": self.criticality.currentData(),
            "internet_facing": self.internet_facing.isChecked(),
            "sensitive_data": self.sensitive_data.isChecked(),
        })
        self.start_requested.emit(target, self.profile.currentData(), context,
                                  self.backend.currentData())
