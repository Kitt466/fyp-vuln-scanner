"""Background threads so the window stays responsive."""
import copy
import threading

from PySide6.QtCore import QThread, Signal

from .. import pipeline


class ScanWorker(QThread):
    progress = Signal(str, int, str)   # stage, percent, message
    succeeded = Signal(object)         # normalised result dict
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, cfg, target, profile, context, backend, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.backend = backend
        self.target = target
        self.profile = profile
        self.context = context
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def run(self):
        try:
            result = pipeline.run(self.cfg, self.target, self.profile, self.context,
                                  emit=self.progress.emit, cancel_event=self._cancel,
                                  backend=self.backend)
        except pipeline.ScanCancelled:
            self.cancelled.emit()
        except Exception as exc:  # any backend failure is shown, not crashed on
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.succeeded.emit(result)


class RetryAdviceWorker(QThread):
    """Re-requests AI advice for findings that only have fallback guidance."""
    progress = Signal(str, int, str)
    succeeded = Signal(object, int)    # updated result, number of findings fixed
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, cfg, result, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.result = copy.deepcopy(result)
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def run(self):
        from ..engine.runner import retry_mitigation

        def report(stage, pct, msg):
            if self._cancel.is_set():
                raise pipeline.ScanCancelled()
            self.progress.emit(stage, int(pct), msg)

        def wait(seconds):
            if self._cancel.wait(seconds):
                raise pipeline.ScanCancelled()

        try:
            done = retry_mitigation(self.cfg, self.result, report, wait)
        except pipeline.ScanCancelled:
            self.cancelled.emit()
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.succeeded.emit(self.result, done)
