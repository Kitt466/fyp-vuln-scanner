"""Scan page: live progress, then the results dashboard (FR-18, NFR-04, NFR-06)."""
import datetime
import html
import os
import re

from PySide6.QtCore import (QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt,
                            Signal)
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout,
                               QHeaderView, QLineEdit, QMessageBox, QPlainTextEdit,
                               QProgressBar, QPushButton, QSplitter, QStackedWidget,
                               QTableView, QTableWidget, QTableWidgetItem, QTabWidget,
                               QTextBrowser, QVBoxLayout, QWidget)

from .. import reports
from ..pipeline import (CONFIDENCE_ORDER, PRIORITY_ORDER, SEVERITY_ORDER, coverage_rows,
                        flat_findings)
from . import theme
from .widgets import Card, ChipRow, StatCard, context_chips, label

STAGES = [("scan", "Port & service scan"), ("parse", "Normalise results"),
          ("cve", "CVE lookup (NVD)"), ("risk", "Context risk scoring"),
          ("mitigation", "Mitigation advice")]
STAGE_KEYS = [k for k, _ in STAGES] + ["done"]
STAGE_TEXT = {"scan": "Scanning ports and services...", "parse": "Normalising results...",
              "cve": "Looking up CVEs in the NVD...", "risk": "Scoring risk with asset context...",
              "mitigation": "Generating mitigation advice...", "done": "Complete"}


# --------------------------------------------------------------------------
# Findings table model
# --------------------------------------------------------------------------
class FindingsModel(QAbstractTableModel):
    COLUMNS = ["Priority", "Risk", "CVSS", "Confidence", "CVE", "Target", "Service",
               "Recommendation"]
    SORT_ROLE = Qt.UserRole + 1
    FINDING_ROLE = Qt.UserRole + 2

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        f = self.rows[index.row()]
        col = self.COLUMNS[index.column()]

        if role == self.FINDING_ROLE:
            return f
        if role == Qt.DisplayRole:
            if col == "Priority":
                return f["priority"]
            if col == "Risk":
                return f"{f['risk_score']:.1f}"
            if col == "CVSS":
                if f.get("scored") is False:
                    return "Not scored yet"
                return f"{f['cvss']} {f['severity'].capitalize()} (v{f['cvss_version']})"
            if col == "Confidence":
                return f["confidence"] + (" *" if f["match_method"] == "keyword" else "")
            if col == "CVE":
                return f["id"]
            if col == "Target":
                return f"{f['host']}:{f['port']}/{f['protocol']}"
            if col == "Service":
                return f"{f['product']} {f['version']}".strip() or f["service"]
            if col == "Recommendation":
                return f["mitigation"]["summary"]
        if role == self.SORT_ROLE:
            if col == "Priority":
                rank = PRIORITY_ORDER.index(f["priority"]) if f["priority"] in PRIORITY_ORDER else 9
                return rank * 100 - float(f["risk_score"])
            if col == "Risk":
                return float(f["risk_score"])
            if col == "CVSS":
                return float(f["cvss"] or 0)
            if col == "Confidence":
                return CONFIDENCE_ORDER.index(f["confidence"]) if f["confidence"] in CONFIDENCE_ORDER else 9
            return self.data(index, Qt.DisplayRole)
        if role == Qt.ForegroundRole:
            if col == "Priority":
                return QColor(theme.PRIORITY.get(f["priority"], theme.INK))
            if col == "CVSS":
                return QColor(theme.SEVERITY.get(f["severity"], theme.INK))
            if col == "Confidence":
                return QColor(theme.CONFIDENCE.get(f["confidence"], theme.INK))
        if role == Qt.FontRole and col in ("Priority", "Risk", "CVE"):
            font = QFont()
            font.setBold(col == "Priority")
            if col in ("Risk", "CVE"):
                font.setFamilies(["Cascadia Mono", "DejaVu Sans Mono", "Consolas", "monospace"])
            return font
        if role == Qt.ToolTipRole:
            if col == "Recommendation":
                m = f["mitigation"]
                steps = "".join(f"<li>{html.escape(s)}</li>" for s in m["steps"])
                return (f"<b>{html.escape(m['summary'])}</b>"
                        f"{'<ol>' + steps + '</ol>' if steps else ''}")
            if col == "Confidence" and f["match_method"] == "keyword":
                return "* Matched by keyword search, not product/version (lower confidence)"
        return None


class FindingsFilter(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.severity = "ALL"
        self.text = ""
        self.setSortRole(FindingsModel.SORT_ROLE)

    def set_severity(self, sev):
        self.severity = sev
        self.invalidateFilter()

    def set_text(self, text):
        self.text = text.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        f = self.sourceModel().rows[row]
        if self.severity != "ALL" and f["severity"] != self.severity:
            return False
        if self.text:
            hay = " ".join(str(f.get(k, "")) for k in
                           ("id", "host", "port", "service", "product", "version", "description"))
            return self.text in hay.lower()
        return True


# --------------------------------------------------------------------------
# Scan page
# --------------------------------------------------------------------------
class ScanPage(QWidget):
    cancel_requested = Signal()
    new_scan_requested = Signal()
    retry_requested = Signal()
    status_message = Signal(str)

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.scan = None
        self.log = []

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 20)
        root.setSpacing(12)

        # ---- header ----
        self.title = label("No scan selected", "H1")
        self.title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.meta = label("Start a new scan or open one from History.", "Muted")
        self.chips = ChipRow()
        root.addWidget(self.title)
        root.addWidget(self.meta)
        root.addLayout(self.chips)

        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)
        self.stack.addWidget(QWidget())               # 0: empty
        self.stack.addWidget(self._build_progress())  # 1: live progress
        self.stack.addWidget(self._build_results())   # 2: results
        self.stack.addWidget(self._build_failed())    # 3: failed / cancelled

    # ------------------------------------------------------------------ build
    def _build_progress(self):
        card = Card()
        top = QHBoxLayout()
        self.stage_label = label("Starting...", "H2")
        self.pct_label = label("0%", "Muted")
        top.addWidget(self.stage_label)
        top.addStretch(1)
        top.addWidget(self.pct_label)
        card.body.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setFixedHeight(10)
        card.body.addWidget(self.bar)
        stages = QHBoxLayout()
        self.stage_labels = {}
        for i, (key, text) in enumerate(STAGES, 1):
            lbl = label(f"{i}  {text}", "Stage")
            stages.addWidget(lbl, 1)
            self.stage_labels[key] = lbl
        card.body.addLayout(stages)
        self.console = QPlainTextEdit()
        self.console.setObjectName("Console")
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(500)
        card.body.addWidget(self.console, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_btn = QPushButton("Cancel scan")
        self.cancel_btn.setObjectName("Danger")
        self.cancel_btn.clicked.connect(self._confirm_cancel)
        row.addWidget(self.cancel_btn)
        card.body.addLayout(row)
        return card

    def _build_results(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        stats = QHBoxLayout()
        self.stat_ports = StatCard("Open ports")
        self.stat_assessed = StatCard("Assessed")
        self.stat_cves = StatCard("CVEs found")
        self.stat_top = StatCard("Highest priority")
        for s in (self.stat_ports, self.stat_assessed, self.stat_cves, self.stat_top):
            stats.addWidget(s, 1)
        lay.addLayout(stats)

        self.banner = label("", "Banner", wrap=True)   # NFR-06
        self.banner.hide()
        lay.addWidget(self.banner)
        self.top_line = label("", "Muted", wrap=True)
        lay.addWidget(self.top_line)

        bar = QHBoxLayout()
        self.sev_filter = QComboBox()
        self.sev_filter.addItem("All severities", "ALL")
        for s in SEVERITY_ORDER:
            self.sev_filter.addItem(s.capitalize(), s)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search CVE, port, product...")
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.sev_filter)
        bar.addWidget(self.search, 1)
        bar.addSpacing(12)
        self.btn_retry = QPushButton("Retry AI advice")
        self.btn_retry.setToolTip("Ask Gemini again for findings that only have fallback "
                                  "guidance. No re-scan needed.")
        self.btn_retry.clicked.connect(self.retry_requested.emit)
        self.btn_retry.hide()
        bar.addWidget(self.btn_retry)
        self.btn_pdf = QPushButton("Export PDF")
        self.btn_html = QPushButton("Export HTML")
        self.btn_json = QPushButton("Export JSON")
        for b, kind in ((self.btn_pdf, "pdf"), (self.btn_html, "html"), (self.btn_json, "json")):
            b.clicked.connect(lambda _=False, k=kind: self._export(k))
            bar.addWidget(b)
        lay.addLayout(bar)
        lay.addWidget(label(
            "Reports contain vulnerability findings and asset details. Save them somewhere "
            "only you or authorised people can access.", "Notice", wrap=True))   # NFR-10

        self.model = FindingsModel(self)
        self.proxy = FindingsFilter(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.setWordWrap(False)
        hh = self.table.horizontalHeader()
        for i in range(len(FindingsModel.COLUMNS) - 1):
            hh.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(len(FindingsModel.COLUMNS) - 1, QHeaderView.Stretch)
        self.table.selectionModel().currentRowChanged.connect(self._show_detail)
        self.sev_filter.currentIndexChanged.connect(
            lambda: self.proxy.set_severity(self.sev_filter.currentData()))
        self.search.textChanged.connect(self.proxy.set_text)

        self.tabs = QTabWidget()
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        self.tabs.addTab(self.detail, "Finding details")
        self.coverage = QTableWidget(0, 5)
        self.coverage.setHorizontalHeaderLabels(["Target", "Service", "Product / version",
                                                 "Status", "CVEs"])
        self.coverage.verticalHeader().hide()
        self.coverage.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.coverage.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.coverage.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.tabs.addTab(self.coverage, "Coverage")
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("Console")
        self.log_view.setReadOnly(True)
        self.tabs.addTab(self.log_view, "Scan log")

        split = QSplitter(Qt.Vertical)
        split.addWidget(self.table)
        split.addWidget(self.tabs)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setChildrenCollapsible(False)
        lay.addWidget(split, 1)
        return w

    def _build_failed(self):
        card = Card()
        self.fail_title = label("Scan failed", "H2")
        self.fail_msg = label("", "Error", wrap=True)
        self.fail_msg.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.fail_log = QPlainTextEdit()
        self.fail_log.setObjectName("Console")
        self.fail_log.setReadOnly(True)
        again = QPushButton("Start a new scan")
        again.clicked.connect(self.new_scan_requested.emit)
        card.body.addWidget(self.fail_title)
        card.body.addWidget(self.fail_msg)
        card.body.addWidget(self.fail_log, 1)
        row = QHBoxLayout()
        row.addWidget(again)
        row.addStretch(1)
        card.body.addLayout(row)
        return card

    # ------------------------------------------------------------- header
    def _set_header(self, scan):
        profile = self.cfg["profiles"].get(scan["profile"], {})
        self.title.setText(scan["target"])
        parts = [f"{profile.get('label', scan['profile'])} scan",
                 f"started {scan['created_at'].replace('T', ' ')}"]
        if scan.get("finished_at"):
            parts.append(f"finished {scan['finished_at'].replace('T', ' ')}")
        self.meta.setText("  |  ".join(parts))
        result = scan.get("result") or {}
        chips = context_chips(scan["context"])
        if (scan.get("backend") or result.get("backend")) == "demo":
            chips.insert(0, ("Demo data", True))
        for host in result.get("hosts", []):
            if host.get("os"):
                chips.append((f"OS: {host['os']}", False))
        self.chips.set_chips(chips)

    # ------------------------------------------------------------- live
    def start_live(self, scan):
        self.scan = scan
        self.log = []
        self._set_header(scan)
        self.console.clear()
        self.bar.setValue(0)
        self.pct_label.setText("0%")
        self.stage_label.setText("Starting...")
        self.cancel_btn.setEnabled(True)
        self.cancel_btn.setText("Cancel scan")
        for lbl in self.stage_labels.values():
            self._restyle(lbl, "Stage")
        self.stack.setCurrentIndex(1)

    @staticmethod
    def _restyle(widget, name):
        if widget.objectName() != name:
            widget.setObjectName(name)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def on_progress(self, stage, pct, msg):
        if msg:
            ts = datetime.datetime.now().isoformat(timespec="seconds")
            self.log.append({"t": ts, "msg": msg})
            self.console.appendPlainText(f"{ts[11:]}  {msg}")
        self.bar.setValue(pct)
        self.pct_label.setText(f"{pct}%")
        self.stage_label.setText(STAGE_TEXT.get(stage, stage))
        idx = STAGE_KEYS.index(stage) if stage in STAGE_KEYS else -1
        for i, (key, _) in enumerate(STAGES):
            name = "StageDone" if idx > i else "StageActive" if idx == i else "Stage"
            self._restyle(self.stage_labels[key], name)

    def _confirm_cancel(self):
        if QMessageBox.question(self, "Cancel scan", "Stop this scan? Partial results "
                                "will not be saved.") == QMessageBox.Yes:
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.setText("Cancelling...")
            self.cancel_requested.emit()

    # ------------------------------------------------------------- results
    def show_scan(self, scan):
        """Display a stored scan record (done, failed or cancelled)."""
        self.scan = scan
        self._set_header(scan)
        if scan["status"] != "done" or not scan.get("result"):
            self.fail_title.setText("Scan cancelled" if scan["status"] == "cancelled"
                                    else "Scan failed")
            self.fail_msg.setText(scan.get("error") or "No result was produced.")
            self.fail_log.setPlainText(self._log_text(scan.get("log", [])))
            self.stack.setCurrentIndex(3)
            return

        r = scan["result"]
        s = r["summary"]
        top = s["top_finding"]
        self.stat_ports.set(s["open_ports"])
        self.stat_assessed.set(f"{s['assessed']}/{s['open_ports']}",
                               None if s["complete"] else theme.SEVERITY["HIGH"])
        self.stat_cves.set(s["cves"])
        self.stat_top.set(top["priority"] if top else "-",
                          theme.PRIORITY.get(top["priority"]) if top else None)

        if not s["complete"]:
            self.banner.setText(
                f"Assessment incomplete: {s['not_assessed']} of {s['open_ports']} services "
                "were not assessed, so no findings there does NOT mean they are safe. "
                "See the Coverage tab for the reasons.")
            self.banner.show()
        else:
            self.banner.hide()
        if top:
            self.top_line.setText(
                f"Fix first: {top['id']} on {top['host']}:{top['port']} ({top['service']}), "
                f"{top['priority']}, risk {top['risk_score']}/10.")
            self.top_line.show()
        else:
            self.top_line.hide()

        missing = sum(1 for f in flat_findings(r)
                      if f["mitigation"].get("source") == "fallback")
        self.btn_retry.setVisible(r.get("backend") != "demo" and missing > 0)
        self.set_retry_busy(False, missing)
        self.sev_filter.setCurrentIndex(0)
        self.search.clear()
        self.model.set_rows(flat_findings(r))
        self.table.sortByColumn(0, Qt.AscendingOrder)   # priority order (NFR-04)
        self._fill_coverage(r)
        self.log_view.setPlainText(self._log_text(scan.get("log", [])))
        if self.proxy.rowCount():
            first = self.proxy.index(0, 0)
            self.table.setCurrentIndex(first)
            self._show_detail(first)
        else:
            self.detail.setHtml(f"<p style='color:{theme.MUTED}'>No known vulnerabilities "
                                "were matched to the assessed services.</p>")
        self.tabs.setCurrentIndex(0 if s["complete"] or s["cves"] else 1)
        self.stack.setCurrentIndex(2)

    def set_retry_busy(self, busy, missing=None):
        self.btn_retry.setEnabled(not busy)
        for b in (self.btn_pdf, self.btn_html, self.btn_json):
            b.setEnabled(not busy)
        if busy:
            self.btn_retry.setText("Retrying AI advice...")
        else:
            self.btn_retry.setText(f"Retry AI advice ({missing})" if missing else
                                   "Retry AI advice")

    @staticmethod
    def _log_text(log):
        return "\n".join(f"{l['t'][11:]}  {l['msg']}" for l in log)

    def _fill_coverage(self, result):
        rows = coverage_rows(result)
        self.coverage.setRowCount(len(rows))
        for i, c in enumerate(rows):
            status = "Assessed" if c["assessed"] else f"Not assessed: {c['reason']}"
            values = [f"{c['host']}:{c['port']}/{c['protocol']}", c["service"],
                      (c["product"] + " " + c["version"]).strip() or "-", status,
                      str(c["cves"]) if c["assessed"] else "-"]
            for j, v in enumerate(values):
                item = QTableWidgetItem(v)
                if j == 3:
                    item.setForeground(QColor(theme.ACCENT if c["assessed"]
                                              else theme.SEVERITY["HIGH"]))
                self.coverage.setItem(i, j, item)
        self.coverage.resizeColumnsToContents()
        self.coverage.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

    def _show_detail(self, current, _previous=None):
        if not current.isValid():
            return
        f = self.proxy.data(current, FindingsModel.FINDING_ROLE)
        if not f:
            return
        e = html.escape
        m = f["mitigation"]
        sev_c = theme.SEVERITY.get(f["severity"], theme.INK)
        pri_c = theme.PRIORITY.get(f["priority"], theme.INK)
        conf_c = theme.CONFIDENCE.get(f["confidence"], theme.INK)
        steps = "".join(f"<li style='margin-bottom:4px'>{e(s)}</li>" for s in m["steps"])
        source = reports.source_text(m)
        refs = "<br>".join(f"<a style='color:{theme.ACCENT}' href='{e(r)}'>{e(r)}</a>"
                           for r in m["references"])
        keyword = (" (matched by keyword search, so treat with caution)"
                   if f["match_method"] == "keyword" else "")
        unscored = ("<p style='color:#f2c94c'>NVD has not scored this CVE yet, so its "
                    "severity and risk are shown as zero. Check the NVD record.</p>"
                    if f.get("scored") is False else "")
        vector = (f"<br><span style='font-family:monospace'>{e(f['cvss_vector'])}</span>"
                  if f.get("cvss_vector") else "")
        self.detail.setHtml(f"""
            <div style="font-size:10pt">
            <p style="font-size:13pt;margin:0"><b style="font-family:monospace">{e(f['id'])}</b>
              &nbsp; <b style="color:{pri_c}">{e(f['priority'])}</b>
              &nbsp; <span style="color:{sev_c}">{e(f['severity'])} / CVSS {f['cvss']}
              (v{e(f['cvss_version'])})</span></p>
            <p style="color:{theme.MUTED};margin:4px 0 10px 0">
              {e(f['host'])}:{f['port']}/{e(f['protocol'])} &nbsp;|&nbsp;
              {e((f['product'] + ' ' + f['version']).strip() or f['service'])} &nbsp;|&nbsp;
              risk {f['risk_score']}/10 &nbsp;|&nbsp;
              confidence <span style="color:{conf_c}">{e(f['confidence'])}</span>{e(keyword)}{vector}</p>
            {unscored}
            <p>{e(f['description'])}</p>
            <p style="margin-top:12px"><b>Recommendation</b><br>{e(m['summary'])}</p>
            {'<ol>' + steps + '</ol>' if steps else ''}
            <p style="color:{theme.MUTED};font-size:9pt">{e(source)}<br>{refs}</p>
            </div>""")

    # ------------------------------------------------------------- export
    def _export(self, kind):
        if not self.scan or not self.scan.get("result"):
            return
        profile = self.cfg["profiles"].get(self.scan["profile"], {})
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", self.scan["target"])
        stamp = (self.scan.get("finished_at") or self.scan["created_at"])[:10]
        default = os.path.join(os.path.expanduser("~"),
                               f"VulnScan-{safe_target}-{stamp}.{kind}")
        filters = {"pdf": "PDF report (*.pdf)", "html": "HTML report (*.html)",
                   "json": "JSON data (*.json)"}
        path, _ = QFileDialog.getSaveFileName(self, f"Export {kind.upper()} report",
                                              default, filters[kind])
        if not path:
            return
        if not path.lower().endswith("." + kind):
            path += "." + kind
        try:
            if kind == "pdf":
                reports.write_pdf(self.scan, profile, path)
            elif kind == "html":
                reports.write_html(self.scan, profile, path)
            else:
                reports.write_json(self.scan, path)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", f"Could not save the report:\n{exc}")
            return
        self.status_message.emit(f"Saved {kind.upper()} report to {path}")
