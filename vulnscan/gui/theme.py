"""Colours and the Qt stylesheet (dark analyst-console theme)."""

BG = "#0e1116"
PANEL = "#151a21"
PANEL_2 = "#1b2129"
LINE = "#262e39"
INK = "#e6e9ee"
MUTED = "#8b95a3"
ACCENT = "#3ddc97"

SEVERITY = {"CRITICAL": "#ff4d4f", "HIGH": "#ff8a3d", "MEDIUM": "#f2c94c",
            "LOW": "#5aa9ff", "NONE": "#6b7280"}
PRIORITY = {"P1": "#ff4d4f", "P2": "#ff8a3d", "P3": "#f2c94c", "P4": "#5aa9ff"}
CONFIDENCE = {"High": "#3ddc97", "Medium": "#f2c94c", "Low": "#ff8a3d"}

MONO = '"Cascadia Mono", "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace'

STYLESHEET = f"""
QWidget {{
    background: {BG}; color: {INK};
    font-family: "Segoe UI", "Noto Sans", Ubuntu, Roboto, sans-serif; font-size: 10pt;
}}
QMainWindow::separator {{ background: {LINE}; width: 1px; }}
QToolTip {{ background: {PANEL_2}; color: {INK}; border: 1px solid {LINE}; padding: 6px; }}

#Sidebar {{ background: {PANEL}; border-right: 1px solid {LINE}; }}
#Brand {{ font-size: 14pt; font-weight: 700; padding: 18px 16px 14px 16px; background: transparent; }}
#NavList {{ background: transparent; border: none; padding: 4px 8px; }}
#NavList::item {{ padding: 10px 12px; border-radius: 6px; color: {MUTED}; margin: 2px 0; }}
#NavList::item:hover {{ background: {PANEL_2}; color: {INK}; }}
#NavList::item:selected {{ background: {PANEL_2}; color: {INK}; border-left: 3px solid {ACCENT}; }}
#ModePill {{ font-family: {MONO}; font-size: 8pt; font-weight: 700; padding: 6px 10px;
            border-radius: 10px; margin: 12px; background: transparent; }}

QFrame#Card {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 10px; }}
QFrame#Card QLabel, QFrame#Card QCheckBox {{ background: transparent; }}
QLabel#H1 {{ font-size: 17pt; font-weight: 700; background: transparent; }}
QLabel#H2 {{ font-size: 11.5pt; font-weight: 600; background: transparent; }}
QLabel#Muted {{ color: {MUTED}; background: transparent; }}
QLabel#Hint {{ color: {MUTED}; font-size: 9pt; background: transparent; }}
QLabel#Error {{ color: #ffb3b4; background: #2a1517; border: 1px solid #5c2326;
               border-radius: 6px; padding: 8px 10px; }}
QLabel#Banner {{ color: #ffd7b3; background: #2a1e12; border: 1px solid #6b4520;
                border-radius: 6px; padding: 8px 10px; }}
QLabel#Notice {{ color: {MUTED}; background: {PANEL_2}; border: 1px solid {LINE};
                border-radius: 6px; padding: 6px 10px; font-size: 9pt; }}
QLabel#Chip {{ color: {MUTED}; border: 1px solid {LINE}; border-radius: 10px;
              padding: 2px 10px; font-size: 9pt; background: transparent; }}
QLabel#ChipWarn {{ color: #ff8a3d; border: 1px solid #6b4520; border-radius: 10px;
                  padding: 2px 10px; font-size: 9pt; background: transparent; }}
QLabel#StatNum {{ font-family: {MONO}; font-size: 20pt; font-weight: 700; background: transparent; }}
QLabel#StatLabel {{ color: {MUTED}; font-size: 8pt; background: transparent; }}
QLabel#Stage {{ color: {MUTED}; border: 1px solid {LINE}; border-radius: 6px; padding: 6px 8px;
               font-size: 9pt; background: {BG}; }}
QLabel#StageActive {{ color: {INK}; border: 1px solid #f2c94c; border-radius: 6px; padding: 6px 8px;
                     font-size: 9pt; background: {BG}; }}
QLabel#StageDone {{ color: {ACCENT}; border: 1px solid #1f5c43; border-radius: 6px; padding: 6px 8px;
                   font-size: 9pt; background: {BG}; }}

QLineEdit, QComboBox, QPlainTextEdit, QTextBrowser {{
    background: {BG}; border: 1px solid {LINE}; border-radius: 6px; padding: 7px 9px;
    selection-background-color: #1f5c43;
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {ACCENT}; }}
QLineEdit#Mono, QPlainTextEdit#Console {{ font-family: {MONO}; }}
QPlainTextEdit#Console {{ background: #090b0f; color: #c9d4e0; font-size: 9.5pt; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {PANEL_2}; border: 1px solid {LINE};
                               selection-background-color: #1f5c43; }}
QCheckBox {{ spacing: 8px; background: transparent; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {MUTED}; border-radius: 3px;
                        background: {BG}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QPushButton {{ background: {PANEL_2}; border: 1px solid {LINE}; border-radius: 6px;
              padding: 8px 14px; font-weight: 600; }}
QPushButton:hover {{ border-color: {MUTED}; }}
QPushButton:disabled {{ color: #4b5563; }}
QPushButton#Primary {{ background: {ACCENT}; color: #062a1b; border-color: {ACCENT}; padding: 10px 18px; }}
QPushButton#Primary:hover {{ background: #5ae6ab; }}
QPushButton#Primary:disabled {{ background: #1f5c43; color: #6b9c86; }}
QPushButton#Danger {{ color: #ff8587; }}

QProgressBar {{ background: {BG}; border: 1px solid {LINE}; border-radius: 5px; height: 10px;
               text-align: center; color: transparent; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}

QTableView, QTableWidget {{ background: {PANEL}; alternate-background-color: #171d25;
    border: 1px solid {LINE}; border-radius: 6px; gridline-color: {LINE};
    selection-background-color: #1d3a30; selection-color: {INK}; }}
QHeaderView::section {{ background: {PANEL_2}; color: {MUTED}; border: none;
    border-bottom: 1px solid {LINE}; padding: 7px 8px; font-size: 8.5pt; font-weight: 600; }}
QTableCornerButton::section {{ background: {PANEL_2}; border: none; }}

QTabWidget::pane {{ border: 1px solid {LINE}; border-radius: 6px; top: -1px; background: {PANEL}; }}
QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 8px 14px; border: none; }}
QTabBar::tab:selected {{ color: {INK}; border-bottom: 2px solid {ACCENT}; }}
QSplitter::handle {{ background: {LINE}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: {LINE}; border-radius: 5px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; }}
QScrollBar::handle:horizontal {{ background: {LINE}; border-radius: 5px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QStatusBar {{ background: {PANEL}; color: {MUTED}; border-top: 1px solid {LINE}; }}
QStatusBar QLabel {{ background: transparent; color: {MUTED}; padding: 0 8px; }}
QScrollArea {{ border: none; }}
"""
