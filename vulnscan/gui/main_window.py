"""Main window: sidebar navigation, page stack and scan orchestration."""
import sys
import uuid

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QListWidget, QMainWindow,
                               QMessageBox, QStackedWidget, QVBoxLayout, QWidget)

from .. import __version__, storage
from ..config import find_nmap, load_config, nmap_version
from . import theme
from .history import HistoryPage
from .new_scan import NewScanPage
from .scan_view import ScanPage
from .widgets import label
from .worker import RetryAdviceWorker, ScanWorker

PAGE_NEW, PAGE_SCAN, PAGE_HISTORY = range(3)


class MainWindow(QMainWindow):
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.worker = None
        self.current_id = None
        self.setWindowTitle("VulnScan")
        self.resize(1240, 820)
        self.setMinimumSize(980, 640)

        central = QWidget()
        self.setCentralWidget(central)
        row = QHBoxLayout(central)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        # ---- sidebar ----
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(200)
        side_lay = QVBoxLayout(side)
        side_lay.setContentsMargins(0, 0, 0, 0)
        brand = label("▚ VulnScan", "Brand")
        side_lay.addWidget(brand)
        self.nav = QListWidget()
        self.nav.setObjectName("NavList")
        self.nav.addItems(["New scan", "Current scan", "History"])
        self.nav.setCursor(Qt.PointingHandCursor)
        side_lay.addWidget(self.nav, 1)
        self.pill = label("", "ModePill")
        self.pill.setAlignment(Qt.AlignCenter)
        side_lay.addWidget(self.pill)
        row.addWidget(side)

        # ---- pages ----
        self.pages = QStackedWidget()
        self.new_page = NewScanPage(cfg)
        self.scan_page = ScanPage(cfg)
        self.history_page = HistoryPage(cfg)
        self.pages.addWidget(self.new_page)
        self.pages.addWidget(self.scan_page)
        self.pages.addWidget(self.history_page)
        row.addWidget(self.pages, 1)

        self.nav.currentRowChanged.connect(self._navigate)
        self.new_page.start_requested.connect(self.start_scan)
        self.new_page.backend_changed.connect(self._set_mode_pill)
        self._set_mode_pill(self.new_page.backend.currentData())
        self.scan_page.cancel_requested.connect(self.cancel_scan)
        self.scan_page.retry_requested.connect(self.retry_advice)
        self.scan_page.new_scan_requested.connect(lambda: self.nav.setCurrentRow(PAGE_NEW))
        self.scan_page.status_message.connect(lambda m: self.statusBar().showMessage(m, 8000))
        self.history_page.open_requested.connect(self.open_scan)

        self._build_status_bar()
        self.nav.setCurrentRow(PAGE_NEW)

    def _set_mode_pill(self, backend):
        demo = backend == "demo"
        color = theme.SEVERITY["MEDIUM"] if demo else theme.ACCENT
        self.pill.setText("DEMO DATA" if demo else "LIVE SCAN")
        self.pill.setStyleSheet(f"color: {color}; border: 1px solid {color};")
        self.pill.setToolTip("Sample data, no network traffic." if demo
                             else "Real Nmap, NVD and AI mitigation.")

    def _build_status_bar(self):
        sb = self.statusBar()
        nmap = find_nmap(self.cfg)
        version = nmap_version(nmap) if nmap else None
        nmap_lbl = label(f"Nmap {version}" if version else
                         "Nmap NOT FOUND (needed for live scans)")
        nmap_lbl.setToolTip(nmap or "Install from nmap.org or set nmap.path in config.yaml")
        if not version:
            nmap_lbl.setStyleSheet(f"color: {theme.SEVERITY['HIGH']};")
        sb.addPermanentWidget(nmap_lbl)
        keys = [
            "NVD key set" if self.cfg["nvd"].get("api_key") else "No NVD key (slower lookups)",
            "Gemini key set" if self.cfg["gemini"].get("api_key")
            else "No Gemini key (fallback advice)",
        ]
        sb.addPermanentWidget(label(" | ".join(keys)))
        sb.addPermanentWidget(label(f"v{__version__}"))
        sb.showMessage(f"Config: {self.cfg['_source']}", 8000)

    def _navigate(self, row):
        if row == PAGE_HISTORY:
            self.history_page.refresh()
        self.pages.setCurrentIndex(row)

    # ------------------------------------------------------------- scans
    def start_scan(self, target, profile, context, backend):
        if self.worker is not None:
            return
        if backend == "engine" and not find_nmap(self.cfg):
            QMessageBox.warning(self, "Nmap not found",
                                "VulnScan needs Nmap for real scans.\n\nInstall it from "
                                "https://nmap.org/download.html (on Windows tick 'Add to PATH'),"
                                " or set nmap.path in config.yaml.")
            return
        scan_id = uuid.uuid4().hex[:12]
        storage.create(scan_id, target, profile, context)
        self.current_id = scan_id
        meta = {"id": scan_id, "target": target, "profile": profile, "context": context,
                "created_at": storage.now(), "finished_at": None, "backend": backend}

        self.worker = ScanWorker(self.cfg, target, profile, context, backend, self)
        self.worker.progress.connect(self.scan_page.on_progress)
        self.worker.succeeded.connect(self._on_success)
        self.worker.failed.connect(self._on_failed)
        self.worker.cancelled.connect(self._on_cancelled)
        self.worker.finished.connect(self._on_worker_done)

        self.new_page.set_busy(True)
        self.scan_page.start_live(meta)
        self.nav.setCurrentRow(PAGE_SCAN)
        self.worker.start()

    def cancel_scan(self):
        if self.worker is not None:
            self.worker.cancel()

    def _on_success(self, result):
        storage.finish(self.current_id, result, self.scan_page.log)
        self.scan_page.show_scan(storage.get(self.current_id))
        self.statusBar().showMessage("Scan complete", 6000)
        QApplication.alert(self)

    def _on_failed(self, message):
        self.scan_page.on_progress("failed", 100, f"Error: {message}")
        storage.fail(self.current_id, message, self.scan_page.log)
        self.scan_page.show_scan(storage.get(self.current_id))

    def _on_cancelled(self):
        self.scan_page.on_progress("cancelled", 100, "Scan cancelled by user")
        storage.cancel(self.current_id, self.scan_page.log)
        self.scan_page.show_scan(storage.get(self.current_id))

    # ------------------------------------------------------------- retry AI
    def retry_advice(self):
        scan = self.scan_page.scan
        if self.worker is not None or not scan or not scan.get("result"):
            return
        self.retry_id = scan["id"]
        self.retry_log = []
        worker = RetryAdviceWorker(self.cfg, scan["result"], self)
        worker.progress.connect(self._on_retry_progress)
        worker.succeeded.connect(self._on_retry_done)
        worker.failed.connect(lambda m: QMessageBox.warning(self, "Retry failed", m))
        worker.finished.connect(self._on_worker_done)
        self.worker = worker
        self.new_page.set_busy(True)
        self.scan_page.set_retry_busy(True)
        worker.start()

    def _on_retry_progress(self, _stage, _pct, msg):
        if msg:
            self.retry_log.append({"t": storage.now(), "msg": f"[retry] {msg}"})
            self.statusBar().showMessage(msg)

    def _on_retry_done(self, result, done):
        storage.update_result(self.retry_id, result, self.retry_log)
        self.statusBar().showMessage(f"AI advice added for {done} finding(s)", 8000)

    def _on_worker_done(self):
        was_retry = isinstance(self.worker, RetryAdviceWorker)
        self.worker.deleteLater()
        self.worker = None
        if was_retry and self.scan_page.scan and self.scan_page.scan["id"] == self.retry_id:
            self.scan_page.show_scan(storage.get(self.retry_id))
        self.new_page.set_busy(False)
        if self.pages.currentIndex() == PAGE_HISTORY:
            self.history_page.refresh()

    def open_scan(self, scan_id):
        if self.worker is not None and scan_id == self.current_id:
            self.nav.setCurrentRow(PAGE_SCAN)
            return
        if self.worker is not None:
            QMessageBox.information(self, "Scan in progress",
                                    "Wait for the current scan to finish before opening "
                                    "another one.")
            return
        scan = storage.get(scan_id)
        if scan:
            self.scan_page.show_scan(scan)
            self.nav.setCurrentRow(PAGE_SCAN)

    def closeEvent(self, event):
        if self.worker is not None:
            if QMessageBox.question(self, "Scan in progress",
                                    "A scan is still running. Cancel it and quit?") \
                    != QMessageBox.Yes:
                event.ignore()
                return
            self.worker.cancel()
            self.worker.wait(5000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("VulnScan")
    app.setOrganizationName("VulnScan")
    app.setStyle("Fusion")
    app.setStyleSheet(theme.STYLESHEET)
    storage.init()
    window = MainWindow(load_config())
    window.show()
    return app.exec()
