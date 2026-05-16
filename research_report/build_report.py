from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import math
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import tkinter as tk
from PIL import Image, ImageDraw, ImageFont, ImageGrab
from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Image as RLImage,
    LongTable,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ids_app.product_gui import IDSProductGUI
from ids_app import product_terminal

OUT_DIR = ROOT / "research_report" / "output"
ASSET_DIR = OUT_DIR / "assets"
RAW_ASSET_DIR = ROOT / "automation" / "product" / "report_assets"
REPORT_PATH = OUT_DIR / "ids_sentinel_terminal_research_report.pdf"
ACCENT = colors.HexColor("#1F4E79")
ACCENT_LIGHT = colors.HexColor("#DCE6F1")
TEXT = colors.HexColor("#1F1F1F")
MUTED = colors.HexColor("#5A5A5A")
GRID = colors.HexColor("#C8D0D9")
BODY_FONT = "Times-Roman"
BODY_BOLD = "Times-Bold"
MONO = "Courier"
ACCESS_DATE = "May 15, 2026"


@dataclass
class SourceNote:
    source_id: str
    title: str
    authors: str
    year: str
    url: str
    access_note: str
    relevance: str


@dataclass
class FunctionInfo:
    name: str
    start: int
    end: int
    kind: str


@dataclass
class ModuleInfo:
    path: str
    line_count: int
    function_count: int
    class_count: int
    functions: list[FunctionInfo]
    classes: list[FunctionInfo]


@dataclass
class ListingSpec:
    path: str
    start: int
    end: int
    title: str
    explanation: str


class NumberedCanvas(canvas.Canvas):
    last_page_count = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        page_count = len(self._saved_page_states)
        type(self).last_page_count = page_count
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(page_count)
            super().showPage()
        super().save()

    def draw_footer(self, page_count: int) -> None:
        self.setStrokeColor(colors.HexColor("#D9D9D9"))
        self.line(0.75 * inch, 0.62 * inch, 7.75 * inch, 0.62 * inch)
        self.setFont(BODY_FONT, 8.5)
        self.setFillColor(MUTED)
        self.drawString(0.78 * inch, 0.4 * inch, "IDS Sentinel Terminal Research Report")
        self.drawRightString(7.72 * inch, 0.4 * inch, f"Page {self._pageNumber} of {page_count}")


def ensure_dirs() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    RAW_ASSET_DIR.mkdir(parents=True, exist_ok=True)


def styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    sample["Title"].fontName = BODY_BOLD
    sample["Title"].fontSize = 24
    sample["Title"].leading = 30
    sample["Title"].textColor = ACCENT
    sample["Title"].spaceAfter = 16
    sample["Heading1"].fontName = BODY_BOLD
    sample["Heading1"].fontSize = 17
    sample["Heading1"].leading = 22
    sample["Heading1"].spaceBefore = 10
    sample["Heading1"].spaceAfter = 10
    sample["Heading1"].textColor = ACCENT
    sample["Heading2"].fontName = BODY_BOLD
    sample["Heading2"].fontSize = 13
    sample["Heading2"].leading = 17
    sample["Heading2"].spaceBefore = 8
    sample["Heading2"].spaceAfter = 6
    sample["Heading2"].textColor = colors.HexColor("#203864")
    sample["BodyText"].fontName = BODY_FONT
    sample["BodyText"].fontSize = 10.5
    sample["BodyText"].leading = 15
    sample["BodyText"].textColor = TEXT
    sample["BodyText"].spaceAfter = 8
    sample.add(
        ParagraphStyle(
            name="Small",
            parent=sample["BodyText"],
            fontSize=9,
            leading=12,
            textColor=MUTED,
            spaceAfter=6,
        )
    )
    sample.add(
        ParagraphStyle(
            name="Caption",
            parent=sample["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=MUTED,
            spaceBefore=4,
            spaceAfter=10,
        )
    )
    sample.add(
        ParagraphStyle(
            name="BulletBody",
            parent=sample["BodyText"],
            leftIndent=14,
            firstLineIndent=-8,
            spaceBefore=0,
            spaceAfter=4,
        )
    )
    sample.add(
        ParagraphStyle(
            name="CodeCommentary",
            parent=sample["BodyText"],
            fontSize=9.5,
            leading=13.5,
            textColor=TEXT,
            backColor=colors.HexColor("#FAFAFA"),
            borderPadding=6,
            borderColor=GRID,
            borderWidth=0.4,
            borderRadius=2,
        )
    )
    return sample


def paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(text), style)


def bullet(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(f"• {text}"), style)


def table_style(header_bg: colors.Color = ACCENT_LIGHT) -> TableStyle:
    return TableStyle(
        [
            ("FONTNAME", (0, 0), (-1, 0), BODY_BOLD),
            ("BACKGROUND", (0, 0), (-1, 0), header_bg),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#18324C")),
            ("GRID", (0, 0), (-1, -1), 0.35, GRID),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.3),
            ("LEADING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
    )


def load_json_command(args: list[str]) -> Any:
    result = subprocess.run(
        ["python", "-m", "ids_app.product_app", *args, "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "command failed")
    return json.loads(result.stdout)


def run_text_command(args: list[str]) -> str:
    result = subprocess.run(
        ["python", "-m", "ids_app.product_app", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return (result.stdout + ("\n" + result.stderr if result.stderr else "")).strip()


def try_import(name: str) -> bool:
    with contextlib.suppress(Exception):
        __import__(name)
        return True
    return False


def repo_counts() -> dict[str, int]:
    files = [p for p in ROOT.rglob("*") if p.is_file()]
    return {
        "files": len(files),
        "py_files": sum(1 for p in files if p.suffix == ".py"),
        "csv_files": sum(1 for p in files if p.suffix.lower() == ".csv"),
        "json_files": sum(1 for p in files if p.suffix.lower() == ".json"),
        "md_files": sum(1 for p in files if p.suffix.lower() == ".md"),
    }


def parse_module(path: Path) -> ModuleInfo:
    text = path.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(text)
    funcs: list[FunctionInfo] = []
    classes: list[FunctionInfo] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes.append(FunctionInfo(node.name, node.lineno, node.end_lineno or node.lineno, "class"))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append(FunctionInfo(node.name, node.lineno, node.end_lineno or node.lineno, "function"))
    return ModuleInfo(
        path=str(path.relative_to(ROOT)).replace("\\", "/"),
        line_count=len(text.splitlines()),
        function_count=len(funcs),
        class_count=len(classes),
        functions=funcs,
        classes=classes,
    )


def module_inventory() -> list[ModuleInfo]:
    targets = sorted((ROOT / "ids_app").glob("*.py")) + sorted((ROOT / "scripts").glob("*.py"))
    return [parse_module(path) for path in targets]


def resolve_font(size: int) -> ImageFont.ImageFont:
    candidates = [
        Path(os.environ.get("SystemRoot", "C:\\Windows")) / "Fonts" / "consola.ttf",
        Path(os.environ.get("SystemRoot", "C:\\Windows")) / "Fonts" / "cour.ttf",
    ]
    for candidate in candidates:
        if candidate.exists():
            with contextlib.suppress(Exception):
                return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def render_terminal_image(source_text: str, dest_path: Path, title: str, max_lines: int = 28) -> Path:
    lines = source_text.splitlines()[:max_lines]
    if not lines:
        lines = ["<no output>"]
    font = resolve_font(18)
    small = resolve_font(16)
    measure = Image.new("RGB", (10, 10), "white")
    draw = ImageDraw.Draw(measure)
    line_height = 26
    widths = [int(draw.textlength(line, font=font)) for line in lines]
    width = max(1080, max(widths) + 90)
    height = 96 + len(lines) * line_height + 30
    image = Image.new("RGB", (width, height), "#0B1220")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((12, 12, width - 12, height - 12), radius=18, fill="#0F172A", outline="#2D436A", width=2)
    draw.rounded_rectangle((34, 34, width - 34, height - 34), radius=14, fill="#101B34", outline="#314B75", width=1)
    draw.ellipse((52, 48, 66, 62), fill="#FF5F56")
    draw.ellipse((74, 48, 88, 62), fill="#FFBD2E")
    draw.ellipse((96, 48, 110, 62), fill="#27C93F")
    draw.text((128, 44), title, font=small, fill="#D8E3F7")
    y = 84
    for index, line in enumerate(lines, start=1):
        prefix = f"{index:02d} "
        draw.text((56, y), prefix, font=font, fill="#5BA7FF")
        draw.text((98, y), line, font=font, fill="#E5EEF9")
        y += line_height
    image.save(dest_path)
    return dest_path


def capture_gui(path: Path) -> Path:
    if path.exists():
        return path
    root = tk.Tk()
    app = IDSProductGUI(root)
    app.command_var.set("traffic")
    app.run_freeform_command()

    def _capture() -> None:
        root.update_idletasks()
        image = ImageGrab.grab(window=root.winfo_id())
        image.save(path)
        root.destroy()

    root.after(2200, _capture)
    root.mainloop()
    return path


def ensure_assets() -> dict[str, Path]:
    ensure_dirs()
    assets: dict[str, Path] = {}
    gui = capture_gui(RAW_ASSET_DIR / "gui_screenshot_window.png")
    assets["gui"] = gui
    text_outputs = {
        "status_terminal.png": run_text_command(["status"]),
        "attacks_terminal.png": run_text_command(["attacks"]),
        "ports_terminal.png": run_text_command(["ports", "--limit", "20"]),
    }
    for name, text in text_outputs.items():
        assets[name] = render_terminal_image(text, ASSET_DIR / name, title=name.replace("_", " ").replace(".png", ""))
    return assets


def source_notes() -> list[SourceNote]:
    return [
        SourceNote(
            "NIST-800-94",
            "Guide to Intrusion Detection and Prevention Systems (IDPS)",
            "Karen Scarfone and Peter Mell",
            "2007",
            "https://csrc.nist.gov/pubs/sp/800/94/final",
            "Accessed May 15, 2026.",
            "Operational foundation for how IDS and IPS technologies should be understood, designed, monitored, and maintained.",
        ),
        SourceNote(
            "NIST-800-61R2",
            "Computer Security Incident Handling Guide",
            "Paul Cichonski, Thomas Millar, Tim Grance, Karen Scarfone",
            "2012",
            "https://csrc.nist.gov/pubs/sp/800/61/r2/final",
            "Accessed May 15, 2026; page notes the document was withdrawn on April 3, 2025 and superseded by Rev. 3.",
            "Used to frame the product as part of an incident handling workflow rather than as a standalone algorithm.",
        ),
        SourceNote(
            "NIST-800-83R1",
            "Guide to Malware Incident Prevention and Handling for Desktops and Laptops",
            "Murugiah Souppaya and Karen Scarfone",
            "2013",
            "https://csrc.nist.gov/pubs/sp/800/83/r1/final",
            "Accessed May 15, 2026.",
            "Supports the report's discussion of file triage, malware-like indicators, and incident response preparedness.",
        ),
        SourceNote(
            "NIST-800-137",
            "Information Security Continuous Monitoring (ISCM) for Federal Information Systems and Organizations",
            "Kelley Dempsey et al.",
            "2011",
            "https://csrc.nist.gov/pubs/sp/800/137/final",
            "Accessed May 15, 2026.",
            "Provides the conceptual frame for continuous monitoring and why persistent telemetry matters.",
        ),
        SourceNote(
            "KDD-1999",
            "KDD Cup 1999: Computer Network Intrusion Detection",
            "SIGKDD Cup organizers",
            "1999",
            "https://www.kdd.org/kdd-cup/view/kdd-cup-1999/Data",
            "Accessed May 15, 2026.",
            "Primary source for the benchmark dataset bundled with this repository.",
        ),
        SourceNote(
            "UCI-KDD99",
            "KDD Cup 1999 Data",
            "Salvatore Stolfo, Wei Fan, Wenke Lee, Andreas Prodromidis, Philip Chan",
            "1999",
            "https://archive.ics.uci.edu/dataset/130/kdd+cup+1999+data",
            "Accessed May 15, 2026.",
            "Used for formal citation metadata, instance counts, and licensing context.",
        ),
        SourceNote(
            "CIC-IDS2017",
            "Intrusion Detection Evaluation Dataset (CIC-IDS2017)",
            "Canadian Institute for Cybersecurity, University of New Brunswick",
            "2017",
            "https://www.unb.ca/cic/datasets/ids-2017.html",
            "Accessed May 15, 2026.",
            "Authoritative dataset description for modern attacks, five-day collection schedule, and flow feature generation.",
        ),
        SourceNote(
            "UNSW-NB15",
            "The UNSW-NB15 Dataset",
            "UNSW Canberra at ADFA",
            "2015-2024 page snapshot",
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "Accessed May 15, 2026.",
            "Source for the dataset composition, attack families, record counts, and split sizes.",
        ),
        SourceNote(
            "DENNING-1987",
            "An Intrusion-Detection Model",
            "Dorothy E. Denning",
            "1987",
            "https://doi.org/10.1109/TSE.1987.232894",
            "Accessed via DOI and search metadata on May 15, 2026.",
            "Seminal conceptual basis for anomaly-oriented intrusion detection built around profiles and deviations.",
        ),
        SourceNote(
            "LEE-1999",
            "A Data Mining Framework for Building Intrusion Detection Models",
            "Wenke Lee, Salvatore Stolfo, Kui Mok",
            "1999",
            "https://doi.org/10.1109/SECPRI.1999.766909",
            "Accessed via DOI-linked search metadata on May 15, 2026.",
            "Seminal bridge from audit data toward data-mining-based intrusion detection workflows.",
        ),
        SourceNote(
            "LIU-LANG-2019",
            "Machine Learning and Deep Learning Methods for Intrusion Detection Systems: A Survey",
            "Hongyu Liu and Bo Lang",
            "2019",
            "https://www.mdpi.com/2076-3417/9/20/4396",
            "Accessed May 15, 2026.",
            "Broad survey used to situate this repository inside the ML and DL IDS landscape.",
        ),
        SourceNote(
            "CANTONE-2024",
            "On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection",
            "Marco Cantone, Claudio Marrocco, Alessandro Bria",
            "2024",
            "https://arxiv.org/abs/2402.10974",
            "Accessed May 15, 2026.",
            "Modern evidence that same-dataset accuracy can mask serious generalization failure across network environments.",
        ),
        SourceNote(
            "MITRE-ATTACK",
            "MITRE ATT&CK",
            "MITRE",
            "Living knowledge base",
            "https://attack.mitre.org/index.html",
            "Accessed May 15, 2026; landing page advertised ATT&CK v19.",
            "Used to connect the repository's hunt and IOC features to contemporary detection engineering language.",
        ),
        SourceNote(
            "PY-ZIPAPP",
            "zipapp - Manage executable Python zip archives",
            "Python Software Foundation",
            "2026 documentation snapshot",
            "https://docs.python.org/3.14/library/zipapp.html",
            "Accessed May 15, 2026.",
            "Supports the report's packaging discussion around distributable Python applications.",
        ),
        SourceNote(
            "PY-TKINTER",
            "tkinter - Python interface to Tcl/Tk",
            "Python Software Foundation",
            "2026 documentation snapshot",
            "https://docs.python.org/3/library/tkinter.html",
            "Accessed May 15, 2026.",
            "Used to contextualize the GUI layer and its cross-platform baseline.",
        ),
        SourceNote(
            "GH-OIDC-PYPI",
            "Configuring OpenID Connect in PyPI",
            "GitHub Docs",
            "2026",
            "https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-pypi",
            "Accessed May 15, 2026.",
            "Supports the release automation analysis for trusted package publishing.",
        ),
        SourceNote(
            "PYPI-TRUSTED-PUBLISHER",
            "Creating a PyPI project with a Trusted Publisher",
            "PyPI Documentation",
            "2026",
            "https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/",
            "Accessed May 15, 2026.",
            "Used in the packaging chapter to describe zero-token project bootstrapping.",
        ),
    ]


def feature_descriptions() -> dict[str, str]:
    return {
        "duration": "Connection duration in seconds. Short, repetitive sessions often characterize scanning and flooding, while longer sessions can signal interactive or application-level abuse.",
        "protocol_type": "Encoded transport protocol. Even in encoded form, the field captures major shifts among TCP, UDP, and ICMP-like behavior classes.",
        "service": "Encoded service indicator. It condenses port-and-protocol usage into an application-oriented signal that often separates benign browsing from attack staging.",
        "flag": "Encoded TCP flag state. This is especially informative for incomplete handshakes, resets, and other failure-heavy patterns common in hostile traffic.",
        "src_bytes": "Bytes sent from source to destination. Useful for distinguishing sparse probes from bulk transfer or flooding behavior.",
        "dst_bytes": "Bytes sent from destination to source. Combined with source bytes, this exposes asymmetric conversations and failed requests.",
        "land": "Boolean marker for source and destination equivalence. Historically useful for detecting malformed or deliberately abusive packet patterns.",
        "wrong_fragment": "Count of malformed or misplaced fragments. Elevated values are uncommon in healthy traffic and may point to evasion or corruption.",
        "urgent": "Urgent packet count. Rare in ordinary enterprise activity, so spikes deserve explanation.",
        "hot": "Count of suspicious content indicators derived from the original dataset schema. It acts as a coarse application-layer risk surrogate.",
        "num_failed_logins": "Failed authentication attempts. Directly relevant to brute-force and credential abuse patterns.",
        "logged_in": "Binary success marker for authenticated sessions. The repository's learned model treats this as highly separating for benign versus hostile behavior.",
        "num_compromised": "Number of compromised conditions reported in the source schema. High values are strong compromise indicators.",
        "root_shell": "Binary marker for root shell acquisition. This is a direct privilege escalation cue.",
        "su_attempted": "Whether privilege switching was attempted. Even low frequency events matter because they align with post-exploitation workflows.",
        "num_root": "Count of root-level operations or accesses. A useful escalation strength signal.",
        "num_file_creations": "File creation count within the session. Helpful when reasoning about payload dropper or exfiltration staging behavior.",
        "num_shells": "Shell spawns associated with the session. Repeated shell creation is highly suspicious in most network contexts.",
        "num_access_files": "Sensitive file access count. Supports coarse inference about reconnaissance or data collection.",
        "num_outbound_cmds": "Outbound command count. The field is almost always zero in the bundled data, which itself is a reminder that some legacy features have little discriminative value today.",
        "is_host_login": "Binary flag for privileged local host login. Rare and context-sensitive.",
        "is_guest_login": "Binary flag for guest access. Can signal low-trust account activity or misconfiguration.",
        "count": "Connections to the same host in a short window. This is one of the strongest attack separators in the repository's learned model.",
        "srv_count": "Connections to the same service in a short window. Useful for burst-style probes and service-specific flooding.",
        "serror_rate": "SYN error rate over the short window. High values often reveal handshake-heavy denial or probing traffic.",
        "srv_serror_rate": "Service-scoped SYN error rate. A tighter lens on service-targeted failures.",
        "rerror_rate": "Reset error rate over the window. Helpful for failed access attempts and aggressive scanning.",
        "srv_rerror_rate": "Service-scoped reset error rate. Useful when a single application endpoint is under stress.",
        "same_srv_rate": "Fraction of recent connections hitting the same service. Stable benign workflows and attack loops both affect this field, but in different combinations with error rates.",
        "diff_srv_rate": "Fraction of recent connections hitting different services. Elevated values can indicate horizontal service enumeration.",
        "srv_diff_host_rate": "How widely a service is spread across hosts in the recent window. Strong for spotting fan-out behavior.",
        "dst_host_count": "Historical count of connections to the destination host. In this repository it is one of the most separating host-centric indicators.",
        "dst_host_srv_count": "Historical count of connections to the destination host and service pair.",
        "dst_host_same_srv_rate": "Fraction of destination-host connections using the same service. A useful stability versus concentration measure.",
        "dst_host_diff_srv_rate": "Fraction of destination-host connections using different services. Supports service sweep detection.",
        "dst_host_same_src_port_rate": "Fraction of connections to the destination host sharing the same source port. The learned model ranks this unusually high, suggesting the dataset encodes repeatability patterns strongly here.",
        "dst_host_srv_diff_host_rate": "Fraction of a destination service's traffic arriving from different hosts. Useful for distinguishing one-to-one sessions from distributed activity.",
        "dst_host_serror_rate": "Host-level SYN error rate. One of the most class-separating host-centric fields in the bundled model.",
        "dst_host_srv_serror_rate": "Host-and-service SYN error rate. Important for service-targeted denial or misconfiguration patterns.",
        "dst_host_rerror_rate": "Host-level reset error rate.",
        "dst_host_srv_rerror_rate": "Host-and-service reset error rate. This often complements the SYN error fields by describing how targets refuse or terminate connections.",
    }


def command_descriptions() -> dict[str, str]:
    return {
        "shell": "Starts the interactive IDS shell that exposes the product's own command grammar rather than the host operating system shell.",
        "gui": "Opens the Tkinter-based graphical console for status review, scans, hunting, network probing, and file triage.",
        "status": "Summarizes installation mode, dataset volumes, learned model indicators, cached outputs, and historical runs.",
        "traffic": "Reports encoded traffic distribution from the bundled train and test CSV files.",
        "attacks": "Shows attack share statistics together with the most separating learned indicators.",
        "datasets": "Lists local sources and the hard-coded external dataset catalog.",
        "malware": "Infers malware-like behavior categories from CSV-derived features rather than from malware family labels.",
        "learn": "Builds or refreshes the repository's pure-Python Gaussian profile using bundled and generated CSV rows.",
        "scan": "Analyzes a CSV file row-by-row, scores risk, classifies behavior, and exports results by default.",
        "export": "Convenience alias for full-result CSV and JSON export production.",
        "import": "Copies an external CSV into the product import area so it can be indexed and analyzed consistently.",
        "download": "Fetches a public URL into the import area; useful for bringing in external benchmark material.",
        "index": "Inspects schema-like properties of a CSV file, including column counts and sample rows.",
        "hunt": "Searches datasets, imports, and reports for a textual pattern.",
        "ioc": "Manages and hunts indicators of compromise stored in the product IOC file.",
        "netstat": "Parses local network connections from the host's `netstat -ano` output.",
        "ports": "Shows local listening ports and UDP endpoints.",
        "port": "Explains a single port using the built-in service and risk knowledge base.",
        "probe": "Performs an authorized TCP connect probe against a host and bounded set of ports.",
        "dns": "Resolves a hostname and attempts reverse lookups where possible.",
        "ps": "Lists local processes for lightweight host triage.",
        "hash": "Calculates file hashes for later comparison and response workflows.",
        "filescan": "Hashes a file and applies simple suspicious-pattern triage logic.",
        "reports": "Lists generated downloadable analysis exports.",
        "runs": "Lists historical classical and DNN training runs from `automation/runs`.",
        "cache": "Enumerates cached command artifacts stored by the product.",
    }


def listing_specs() -> list[ListingSpec]:
    return [
        ListingSpec("ids_app/product_terminal.py", 1, 130, "Listing 1. Runtime bootstrap and packaged asset staging", "The opening block shows how the tool distinguishes a source checkout from an installed package and how it bootstraps bundled CSVs, IOC seeds, and the self-learning model into a writable runtime home."),
        ListingSpec("ids_app/product_terminal.py", 403, 563, "Listing 2. Streaming row ingestion and pure-Python model learning", "This excerpt is central to the report: it demonstrates that the self-learning path is intentionally dependency-light and can operate even when the heavier scientific stack is absent."),
        ListingSpec("ids_app/product_terminal.py", 573, 662, "Listing 3. Probabilistic scoring and behavioral classification", "These functions transform raw numeric feature values into log-probability scores, risk levels, and narrative behavior classes such as `dos_flood` or `probe_scan`."),
        ListingSpec("ids_app/product_terminal.py", 801, 941, "Listing 4. CSV analysis and export pipeline", "The analysis routine ties together row parsing, scoring, export generation, and cached metadata creation. It is the core of the operational terminal workflow."),
        ListingSpec("ids_app/product_terminal.py", 1114, 1309, "Listing 5. Local service knowledge, netstat parsing, and active probing", "This block explains why the network triage surface is useful but also why the report classifies it as Windows-shaped rather than fully portable."),
        ListingSpec("ids_app/product_terminal.py", 1402, 1578, "Listing 6. File triage, IOC handling, and text hunting", "The repository combines lightweight file hashing with IOC management and keyword search to approximate analyst-grade quick triage."),
        ListingSpec("ids_app/product_terminal.py", 1587, 1709, "Listing 7. Embedded shell command layer", "Instead of handing the operator directly to the host shell, the product offers bounded, read-oriented shell-like commands. That design reduces destructive risk and keeps the UX coherent."),
        ListingSpec("ids_app/product_terminal.py", 1713, 1928, "Listing 8. Status, traffic, attacks, malware, and run dashboards", "This range contains the presentation functions that convert cached and learned state into human-readable dashboards."),
        ListingSpec("ids_app/product_terminal.py", 2023, 2350, "Listing 9. Command dispatch, parser construction, and entrypoint handling", "The closing block reflects the product's current architectural trade-off: fast feature growth through a large monolithic dispatcher."),
        ListingSpec("ids_app/product_gui.py", 1, 205, "Listing 10. GUI theme, layout, and dark-mode composition", "The GUI is not a wrapper around a browser; it is a native Tk interface with a custom palette, pane layout, themed notebook tabs, and a command-driven workflow."),
        ListingSpec("ids_app/product_gui.py", 206, 348, "Listing 11. GUI command execution and output coloring", "The second half of the GUI shows how background threads execute terminal commands and stream tagged output back into the text console."),
        ListingSpec("ids_app/classical.py", 1, 113, "Listing 12. Classical training suite", "This file packages a compact benchmark set of supervised classifiers and records structured results into `automation/runs`."),
        ListingSpec("ids_app/dnn.py", 1, 145, "Listing 13. DNN training suite", "The DNN path is deliberately thinner than the classical suite, deferring the heavy dependency load to TensorFlow while preserving a consistent summary schema."),
        ListingSpec("ids_app/data.py", 1, 123, "Listing 14. Dataset loading and split management", "All higher-level workflows depend on these dataset loaders for sampling, summaries, and feature extraction."),
        ListingSpec("ids_app/storage.py", 1, 50, "Listing 15. Run and job storage primitives", "The storage helper is small but strategically important because it standardizes where automation summaries and run metadata live."),
        ListingSpec("ids_app/api.py", 1, 106, "Listing 16. API entrypoints", "This module exposes FastAPI endpoints for jobs and run metadata, but the report also flags it as a dependency surface that is not currently declared in package metadata."),
        ListingSpec("ids_app/terminal.py", 1, 220, "Listing 17. Legacy terminal interface overview", "The legacy terminal predates the productified CLI and still imports the scientific stack at module import time."),
        ListingSpec("ids_app/terminal.py", 320, 646, "Listing 18. Legacy train-and-shell orchestration", "This excerpt matters because it is the path that failed during verification when `joblib` was absent."),
        ListingSpec("pyproject.toml", 1, 60, "Listing 19. Installable package metadata and entrypoints", "The project metadata successfully defines a distributable CLI and GUI, but it currently omits the optional scientific and API dependencies that parts of the repo assume."),
        ListingSpec(".github/workflows/release.yml", 1, 80, "Listing 20. Release and PyPI workflow", "The workflow already implements artifact building, a smoke test, GitHub release uploads, and trusted publishing to PyPI."),
        ListingSpec("scripts/build_python_package.py", 1, 120, "Listing 21. Wheel and source distribution helper", "This helper stages a clean package tree and is especially useful in environments where `python -m build` is not the preferred path."),
    ]


def extract_code(path: str, start: int, end: int) -> str:
    text = (ROOT / path).read_text(encoding="utf-8", errors="ignore").splitlines()
    width = len(str(end))
    numbered = [f"{index:{width}d}: {line}" for index, line in enumerate(text[start - 1:end], start=start)]
    return "\n".join(numbered)


def environment_findings() -> list[tuple[str, str]]:
    return [
        ("Python runtime", subprocess.run(["python", "--version"], capture_output=True, text=True, check=False).stdout.strip() or subprocess.run(["python", "--version"], capture_output=True, text=True, check=False).stderr.strip()),
        ("reportlab", "available" if try_import("reportlab") else "missing"),
        ("Pillow", "available" if try_import("PIL") else "missing"),
        ("tkinter", "available" if try_import("tkinter") else "missing"),
        ("numpy", "available" if try_import("numpy") else "missing"),
        ("joblib", "available" if try_import("joblib") else "missing"),
        ("fastapi", "available" if try_import("fastapi") else "missing"),
        ("pydantic", "available" if try_import("pydantic") else "missing"),
        ("tensorflow", "available" if try_import("tensorflow") else "missing"),
    ]


def legacy_terminal_failure() -> str:
    result = subprocess.run(
        ["python", "-m", "ids_app.terminal", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return (result.stderr or result.stdout).strip()


def build_context() -> dict[str, Any]:
    assets = ensure_assets()
    status = load_json_command(["status"])
    attacks = load_json_command(["attacks"])
    datasets = load_json_command(["datasets"])
    runs = load_json_command(["runs"])
    ports = load_json_command(["ports"])
    counts = repo_counts()
    modules = module_inventory()
    subcommands = list(command_descriptions().items())
    legacy_failure = legacy_terminal_failure()
    return {
        "assets": assets,
        "status": status,
        "attacks": attacks,
        "datasets": datasets,
        "runs": runs,
        "ports": ports,
        "counts": counts,
        "modules": modules,
        "subcommands": subcommands,
        "sources": source_notes(),
        "feature_descriptions": feature_descriptions(),
        "legacy_failure": legacy_failure,
        "environment": environment_findings(),
    }


def module_overview_table(context: dict[str, Any]) -> LongTable:
    rows = [["Module", "Lines", "Functions", "Classes", "Dominant Role"]]
    for module in context["modules"]:
        if module.path.endswith("product_terminal.py"):
            role = "Primary CLI, analysis core, caching, IOC, network triage, parser"
        elif module.path.endswith("product_gui.py"):
            role = "Dark-mode Tk GUI for the product console"
        elif module.path.endswith("classical.py"):
            role = "Classical supervised model training suite"
        elif module.path.endswith("dnn.py"):
            role = "TensorFlow-based deep learning suite"
        elif module.path.endswith("api.py"):
            role = "FastAPI interface for runs and jobs"
        elif module.path.endswith("data.py"):
            role = "Dataset loading, sampling, and summary helpers"
        elif module.path.endswith("storage.py"):
            role = "Run and job persistence helpers"
        elif module.path.endswith("terminal.py"):
            role = "Legacy command console and training workflow"
        else:
            role = "Support module"
        rows.append([module.path, f"{module.line_count:,}", module.function_count, module.class_count, role])
    table = LongTable(rows, repeatRows=1, colWidths=[2.05 * inch, 0.7 * inch, 0.8 * inch, 0.7 * inch, 2.55 * inch])
    table.setStyle(table_style())
    return table


def runs_table(context: dict[str, Any]) -> LongTable:
    rows = [["Run ID", "Kind", "Train rows", "Test rows", "Best model", "Accuracy"]]
    for run in context["runs"]:
        best_model = run.get("best_model", "-")
        best_accuracy = max((item.get("metrics", {}).get("accuracy", 0.0) for item in run.get("results", [])), default=0.0)
        dataset = run.get("dataset", {})
        rows.append(
            [
                run.get("run_id", "-"),
                run.get("kind", "-"),
                f"{dataset.get('train_rows', 0):,}",
                f"{dataset.get('test_rows', 0):,}",
                best_model,
                f"{best_accuracy:.4f}",
            ]
        )
    table = LongTable(rows, repeatRows=1, colWidths=[1.8 * inch, 1.05 * inch, 0.8 * inch, 0.8 * inch, 1.65 * inch, 0.7 * inch])
    table.setStyle(table_style())
    return table


def dataset_comparison_table(context: dict[str, Any]) -> LongTable:
    train = context["status"]["datasets"]["train"]
    test = context["status"]["datasets"]["test"]
    rows = [
        ["Dataset", "Origin", "Rows", "Features/Columns", "Attack coverage note"],
        [
            "Bundled KDD train",
            "Local repo asset",
            f"{train['rows']:,}",
            str(train["columns"]),
            "Binary normal/attack labels from the KDD99 derivative used by the project.",
        ],
        [
            "Bundled KDD test",
            "Local repo asset",
            f"{test['rows']:,}",
            str(test["columns"]),
            "Held-out companion split with a similarly high attack share.",
        ],
        [
            "CIC-IDS2017",
            "UNB CIC official page",
            "5 days of PCAP/CSV flow capture",
            "80+ flow features",
            "FTP/SSH brute force, DoS, DDoS, Heartbleed, web attacks, infiltration, botnet, port scan.",
        ],
        [
            "UNSW-NB15",
            "UNSW official page",
            "2,540,044 total records; 175,341 train / 82,332 test split listed",
            "49 features plus class",
            "Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms.",
        ],
    ]
    table = LongTable(rows, repeatRows=1, colWidths=[1.25 * inch, 1.25 * inch, 1.25 * inch, 1.1 * inch, 2.45 * inch])
    table.setStyle(table_style())
    return table


def environment_table(context: dict[str, Any]) -> Table:
    rows = [["Component", "Observed state"]]
    rows.extend(context["environment"])
    table = Table(rows, colWidths=[1.8 * inch, 4.9 * inch])
    table.setStyle(table_style())
    return table


def make_bar_chart(title: str, items: list[tuple[str, float]], width: float = 6.5 * inch, height: float = 2.2 * inch) -> Drawing:
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=colors.white, strokeColor=GRID, strokeWidth=0.5))
    drawing.add(String(12, height - 16, title, fontName=BODY_BOLD, fontSize=11, fillColor=ACCENT))
    max_value = max((value for _, value in items), default=1.0)
    bar_area_top = height - 34
    bar_height = 18
    gap = 12
    start_y = bar_area_top - bar_height
    for index, (label, value) in enumerate(items):
        y = start_y - index * (bar_height + gap)
        bar_width = 0 if max_value == 0 else (value / max_value) * (width - 170)
        drawing.add(String(12, y + 4, label, fontName=BODY_FONT, fontSize=8.5, fillColor=TEXT))
        drawing.add(Rect(118, y, width - 150, bar_height, fillColor=colors.HexColor("#F3F6FA"), strokeColor=GRID, strokeWidth=0.25))
        drawing.add(Rect(118, y, bar_width, bar_height, fillColor=colors.HexColor("#4F81BD"), strokeColor=colors.HexColor("#4F81BD"), strokeWidth=0.25))
        drawing.add(String(width - 26, y + 4, f"{value:,.2f}", fontName=BODY_FONT, fontSize=8.2, fillColor=TEXT, textAnchor="end"))
    return drawing


def architecture_diagram() -> Drawing:
    width = 6.8 * inch
    height = 3.6 * inch
    drawing = Drawing(width, height)
    drawing.add(Rect(0, 0, width, height, fillColor=colors.white, strokeColor=GRID, strokeWidth=0.5))
    boxes = [
        (24, 250, 138, 44, "Entry Points", "product_app.py / pyproject"),
        (188, 250, 176, 44, "Core CLI", "product_terminal.py"),
        (390, 250, 140, 44, "GUI", "product_gui.py"),
        (188, 184, 176, 44, "Analytics", "learn / scan / export"),
        (24, 118, 138, 44, "Support", "data.py / storage.py"),
        (188, 118, 176, 44, "Optional ML", "classical.py / dnn.py"),
        (390, 118, 140, 44, "API", "api.py"),
        (188, 52, 176, 44, "Artifacts", "automation/runs + cache"),
    ]
    for x, y, w, h, title, subtitle in boxes:
        drawing.add(Rect(x, y, w, h, fillColor=ACCENT_LIGHT, strokeColor=colors.HexColor("#7A9CC6"), strokeWidth=0.7, rx=4, ry=4))
        drawing.add(String(x + 8, y + h - 16, title, fontName=BODY_BOLD, fontSize=10, fillColor=ACCENT))
        drawing.add(String(x + 8, y + 12, subtitle, fontName=BODY_FONT, fontSize=8.3, fillColor=TEXT))
    lines = [
        (162, 272, 188, 272),
        (364, 272, 390, 272),
        (276, 250, 276, 228),
        (276, 184, 276, 162),
        (162, 140, 188, 140),
        (364, 140, 390, 140),
        (276, 118, 276, 96),
    ]
    for x1, y1, x2, y2 in lines:
        drawing.add(Line(x1, y1, x2, y2, strokeColor=colors.HexColor("#7A7A7A"), strokeWidth=1))
    return drawing


def append_story_intro(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    train = context["status"]["datasets"]["train"]
    test = context["status"]["datasets"]["test"]
    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph("IDS Sentinel Terminal", s["Title"]))
    story.append(Paragraph("A research-style technical assessment of a productized intrusion-analysis CLI and GUI", s["Heading2"]))
    story.append(Paragraph(f"Prepared from repository evidence and web research on {ACCESS_DATE}", s["Small"]))
    story.append(Spacer(1, 0.3 * inch))
    summary = (
        f"This report examines the IDS Sentinel Terminal repository as both a software product and a research artifact. "
        f"The current codebase bundles two KDD-derived CSV assets with {train['rows']:,} training rows and {test['rows']:,} test rows, "
        f"ships a pure-Python self-learning model, exposes a Tk-based GUI, and records multiple historical classical and deep-learning runs. "
        f"The report also situates the project against NIST guidance, MITRE ATT&CK, and more modern benchmark datasets such as CIC-IDS2017 and UNSW-NB15."
    )
    story.append(paragraph(summary, s["BodyText"]))
    story.append(Spacer(1, 0.25 * inch))
    story.append(bullet("Purpose: determine what this repository already delivers as an analyst-facing tool and where its scientific and engineering limits remain.", s["BulletBody"]))
    story.append(bullet("Method: combine local repo inspection, executable command evidence, live GUI capture, and authoritative external sources.", s["BulletBody"]))
    story.append(bullet("Scope: architecture, datasets, scoring logic, training artifacts, operational commands, packaging, risks, and optimization priorities.", s["BulletBody"]))
    story.append(PageBreak())


def append_abstract(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    attacks = context["attacks"]["model_indicators"]
    story.append(Paragraph("Abstract", s["Heading1"]))
    text = (
        "IDS Sentinel Terminal is an attempt to recast a machine-learning-oriented intrusion detection repository into a user-facing defensive product. "
        "Instead of stopping at model training scripts, the project now exposes an installable command-line interface, a native graphical console, cached downloadable reports, local network and file triage commands, and a pure-Python behavioral model that can score CSV traffic rows without the heavy scientific stack. "
        "This report studies the repository in the manner of a software-centric research paper: first by grounding the design against established IDS literature and operational guidance, then by analyzing the codebase, data assets, packaged artifacts, and historical training runs, and finally by identifying the engineering and research gaps that still separate the tool from a production-grade security platform. "
        f"Two observations dominate the evidence. First, the repository's own learned profile finds high separation in features such as {attacks[0]['feature']}, {attacks[1]['feature']}, and {attacks[2]['feature']}, which is consistent with classical KDD-style connection statistics. Second, the installable package surface is materially ahead of the dependency story: the primary CLI can run in a light Python environment, but legacy training and API modules still require undeclared dependencies such as joblib, numpy, FastAPI, Pydantic, and TensorFlow. "
        "The report therefore concludes that IDS Sentinel Terminal is already useful as a local analysis shell and demonstrator of CSV-based traffic triage, yet it remains scientifically constrained by its benchmark choices and operationally constrained by partial packaging and cross-platform assumptions."
    )
    story.append(paragraph(text, s["BodyText"]))
    story.append(Paragraph("Research Questions", s["Heading2"]))
    story.append(bullet("How closely does the repository's current design align with established IDS operational guidance and contemporary research expectations?", s["BulletBody"]))
    story.append(bullet("What can be verified directly from the code and historical artifacts about the product's capabilities, limitations, and reproducibility?", s["BulletBody"]))
    story.append(bullet("Which defects or architectural pressures most urgently limit the project's credibility as a cross-platform downloadable tool?", s["BulletBody"]))
    story.append(PageBreak())


def append_chapter_introduction(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    counts = context["counts"]
    story.append(Paragraph("1. Introduction and Research Framing", s["Heading1"]))
    paragraphs = [
        "The repository under study no longer behaves like a bare academic notebook or a one-off training script collection. It has been evolved into a named product, IDS Sentinel Terminal, with packaging metadata, a GUI, release automation, cached outputs, and user-facing commands for traffic inspection, hunting, file hashing, local network review, and IOC management. That shift matters because productization changes the evaluation standard. Once a codebase claims to be a tool, the question is not only whether an algorithm works on a benchmark, but also whether a user can install it, understand its outputs, and operate it safely across real environments.",
        f"A quick structural count highlights that transition. The working tree presently contains {counts['files']:,} files overall, including {counts['py_files']} Python files and {counts['csv_files']} CSV files. The central orchestrator, `ids_app/product_terminal.py`, spans more than two thousand lines and consolidates analysis, caching, IOC operations, lightweight shell behavior, local host triage, parser construction, and entrypoint handling. The GUI, by contrast, is compact and native: a single Tkinter module translates the command surface into a dark-mode analyst console. The code therefore exhibits a recognizable product pattern, but it does so through a monolithic coordination layer rather than through sharply separated services.",
        "This report treats the repository as a combined software engineering and applied security artifact. It asks whether the product's current behaviors are coherent with accepted intrusion detection doctrine, whether the repository's benchmark choices remain defensible, and whether the packaging and release machinery are sufficiently truthful about runtime expectations. The goal is not to dismiss the code for being incomplete. The goal is to establish precisely where it is already solid, where it is only locally convincing, and where it still depends on assumptions that would fail in a stricter operational setting.",
        "Methodologically, the report uses four evidence streams. First, it analyzes the repository itself, including module structure, parser design, packaged assets, historical run summaries, and release workflows. Second, it executes the live product commands that are available in the current Python environment, recording status, attacks, dataset catalog, ports, and GUI output. Third, it validates failure paths, such as the legacy training console, in order to distinguish implemented capabilities from merely intended ones. Fourth, it situates these observations against standards and literature from NIST, MITRE, and representative intrusion-detection research.",
        "A useful way to read the remainder of the document is to keep three layers in mind. The first layer is operational: the user experience of commands, caches, reports, and screens. The second layer is analytic: how the product scores rows, learns a lightweight model, and summarizes traffic. The third layer is scientific: whether the benchmark logic and evaluation assumptions still hold when compared with post-KDD datasets and cross-dataset generalization research. A credible product in this space has to satisfy all three layers at once.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(architecture_diagram())
    story.append(Paragraph("Figure 1. High-level repository architecture reconstructed from the codebase.", s["Caption"]))


def append_chapter_foundations(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("2. Standards and Literature Foundation", s["Heading1"]))
    paragraphs = [
        "The conceptual ancestry of this repository is easy to locate. Denning's 1987 model framed intrusion detection around monitored profiles and deviations from normal behavior, establishing the durable idea that security violations can often be surfaced statistically rather than only through hard-coded signatures. A decade later, Lee, Stolfo, and Mok pushed the field toward explicit data-mining workflows for building intrusion detection models from audit data. The repository inherits both instincts. It exposes a lightweight learned profile, but it also retains the spirit of a benchmark-oriented model evaluation workflow through its classical and DNN training subsystems.",
        "NIST's SP 800-94 remains a useful operational anchor because it reminds us that IDS technology is not merely a classifier. The guidance treats understanding, designing, configuring, securing, monitoring, and maintaining IDPS as a lifecycle concern that spans network-based, wireless, behavior-analysis, and host-based perspectives. That framing is important here. IDS Sentinel Terminal is not an inline IPS. It is better understood as a defensive analyst console that borrows from network IDS thinking while also offering host-side adjuncts such as process listing, file hashing, IOC tracking, and port explanation. In NIST terms, it is a complementary defensive technology rather than a complete prevention appliance.",
        "SP 800-61 and SP 800-83 broaden that interpretation. Incident handling guidance emphasizes that effective response depends on preparation, analysis, and repeatable operational procedures. Malware handling guidance adds that response readiness is inseparable from preventive controls and rapid triage. Those documents help explain why the repository's non-model features matter. The CSV analyzer alone would be too narrow. The ability to hash files, hunt text across generated reports, inspect exposed ports, and organize indicators into a local IOC store gives the tool a more incident-centric shape, even if each feature remains deliberately lightweight.",
        "MITRE ATT&CK adds a contemporary vocabulary for talking about what the product can and cannot currently support. The landing page accessed during this study advertised ATT&CK v19 and describes ATT&CK as a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. That matters because analysts increasingly expect detection and hunt tooling to map findings to tactic and technique language. IDS Sentinel Terminal does not yet produce ATT&CK mappings directly, but several of its affordances align naturally with ATT&CK-style reasoning: brute-force indicators touch credential access, scan behavior touches discovery, file triage supports malware analysis, and IOC workflows support collection and correlation.",
        "Modern survey work also sharpens the evaluation standard. The 2019 survey by Liu and Lang shows how broad the ML and DL IDS literature has become, but it also reiterates recurring goals such as improved detection accuracy, reduced false alarms, and the ability to detect unknown attacks. More recent work, particularly Cantone et al. in 2024, undercuts the comfort of same-dataset evaluation by showing that cross-dataset generalization can collapse toward chance levels even when in-dataset scores look excellent. This single observation should shape how the repository's existing run artifacts are interpreted: good benchmark accuracy is evidence of local fit, not proof of field readiness.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(dataset_comparison_table(context))
    story.append(Paragraph("Table 1. Local benchmark assets versus two modern external datasets cited by the product.", s["Caption"]))


def append_chapter_datasets(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    train = context["status"]["datasets"]["train"]
    test = context["status"]["datasets"]["test"]
    story.append(Paragraph("3. Dataset Baseline and Threat Realism", s["Heading1"]))
    paragraphs = [
        f"The repository's built-in operating baseline is firmly centered on a KDD-derived connection dataset. The local training asset contains {train['rows']:,} rows with {train['columns']} columns and an attack share of {train['attack_share']:.2%}. The bundled test asset contains {test['rows']:,} rows with the same column count and an attack share of {test['attack_share']:.2%}. Those proportions matter. A benchmark in which attacks dominate more than eighty percent of rows creates a very different learning environment from an operational network where benign traffic overwhelmingly dominates and analyst attention is consumed by rare but meaningful anomalies.",
        "The feature schema is also historically revealing. KDD-style fields such as `count`, `srv_count`, `serror_rate`, and host-centric error rates embody an era in which connection-level aggregates were a pragmatic and powerful way to distinguish hostile behavior. The repository's own learned model confirms that this structure still separates the local binary labels strongly. Yet the same strength is also a warning sign: when the most discriminative dimensions are tightly coupled to the quirks of a benchmark, models can become excellent at recognizing the benchmark instead of the adversary.",
        "The external dataset catalog hard-coded in the product is therefore a sign of architectural maturity even before any download occurs. CIC-IDS2017 contributes modern attack categories, richer flow features, five days of scenario-specific traffic, and a cleaner bridge between PCAP and flow CSVs. UNSW-NB15 contributes a different feature design, a large labeled corpus, and explicit attack categories such as Fuzzers, Reconnaissance, Generic, and Shellcode. Their presence in the catalog signals that the repository's maintainers already understand the need to look beyond KDD-style assets.",
        "At the same time, the product has not yet operationalized that catalog into an end-to-end evaluation harness. It can import or download CSV material, but the core reportable training evidence in `automation/runs` is still tied to the bundled benchmark family. This is where the report's scientific critique becomes concrete rather than abstract. The repository is not wrong to start from KDD-derived data. It is incomplete if it treats that starting point as sufficient evidence of modern generalization.",
        "A second realism issue concerns labeling granularity. The bundled assets are binary normal-versus-attack datasets. The product's malware and behavior outputs therefore infer families such as `dos_flood`, `probe_scan`, or `credential_abuse` heuristically from numeric patterns rather than from native family labels. This is a reasonable product decision, but it should be described honestly. The tool is not learning named malware families from the bundled CSVs; it is translating benchmark-style traffic signals into analyst-friendly behavior categories.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    drawing = make_bar_chart(
        "Top learned indicator separations",
        [(item["feature"], float(item["separation"])) for item in context["attacks"]["model_indicators"][:8]],
        height=2.8 * inch,
    )
    story.append(drawing)
    story.append(Paragraph("Figure 2. The local Gaussian profile finds the strongest class separation in count-like and host-oriented connection statistics.", s["Caption"]))


def append_chapter_architecture(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("4. Repository Architecture and Product Shape", s["Heading1"]))
    paragraphs = [
        "From a software engineering perspective, the clearest structural fact is that `ids_app/product_terminal.py` is the system's gravitational center. It owns runtime bootstrap logic, data directory management, CSV parsing, model learning, scoring, reporting, IOC operations, a shell-like subsystem, network triage helpers, file triage helpers, command parsing, and the final entrypoint. Such concentration is not unusual in fast-moving internal tools, but it carries consequences. Change velocity is initially high because there is only one place to wire new commands. Over time, however, testability, onboarding, and change isolation all become harder because unrelated concerns share a single large surface.",
        "The surrounding modules partly offset that concentration. `product_gui.py` translates the command layer into a themed Tk application rather than duplicating business logic. `data.py`, `storage.py`, and `metrics.py` separate lower-level concerns. `classical.py` and `dnn.py` isolate heavier training logic. `api.py` exposes a web-service shape for run metadata. `scripts/build_python_package.py` and the release workflow complete the product story by making packaging an explicit part of the codebase rather than an afterthought. In other words, the repository is not architecturally flat. It is architecturally asymmetric: one large coordinator surrounded by smaller, better-scoped helpers.",
        "This asymmetry also explains why the product is pleasant to use in its successful paths. Because the GUI delegates into the CLI core, both surfaces share a consistent command vocabulary and output model. Because exports, runs, and caches live under stable automation directories, the product can present historical evidence instead of only ephemeral terminal prints. Because the packaged assets are copied into a writable runtime home when installed, the same user-facing commands can behave sensibly both inside the source tree and from a wheel installed elsewhere.",
        "However, the asymmetry creates maintenance pressure. Adding a new command often means editing parser logic, the dispatch routine, output formatting, caching behavior, and sometimes GUI wiring. The product remains coherent because one authorial style dominates the file, but it would become harder for multiple contributors to evolve safely without stronger modular boundaries. The report therefore interprets the monolith not as an immediate defect, but as the main architectural pressure point that future refactoring should address.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(module_overview_table(context))
    story.append(Paragraph("Table 2. Module inventory for the executable Python surfaces in the repository.", s["Caption"]))


def append_chapter_detection(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    model = context["status"]["model"]
    story.append(Paragraph("5. Detection and Analytics Pipeline", s["Heading1"]))
    paragraphs = [
        f"The pure-Python learned profile is one of the repository's most pragmatic design choices. According to the local status output, it is stored as a `{model['model_type']}` model and was created from {model['total_rows']:,} rows spanning bundled training data and generated analysis exports. In practice this means the product can deliver a useful minimum viable scoring path even when libraries such as numpy, scikit-learn, and TensorFlow are absent. This design decision is not just convenient; it materially improves the odds that a lightweight install will still be capable of analysis rather than failing immediately at import time.",
        "The learning process itself is intentionally transparent. The code builds per-label running statistics across numeric features, derives Gaussian-like parameters, computes class priors, and then uses those parameters at scoring time to estimate how well an incoming row fits the normal and attack profiles. A subsequent classification layer converts these numeric distinctions into categories that are easier for a human operator to act on. This is where the product becomes more than a benchmark wrapper. It does not merely emit a probability. It emits a risk narrative.",
        "That narrative layer is especially visible in `classify_behavior`. The function uses feature combinations to produce terms such as `dos_flood`, `probe_scan`, `credential_abuse`, `payload_or_exfiltration`, `privilege_escalation`, and `malware_like_activity`. A purist might object that such labels are heuristic and not statistically learned end-to-end. That objection is fair, but incomplete. In analyst tooling, heuristics are not a weakness by default. They become a weakness only when they are hidden, overclaimed, or impossible to inspect. In this repository they are inspectable and therefore auditable.",
        "The export path further strengthens the operational value of the pipeline. The scan routine produces CSV and JSON artifacts, caches summaries, and makes those exports discoverable through subsequent commands. This means that the product already supports a modest but meaningful analytic loop: ingest, score, export, revisit, and hunt across prior outputs. In a small defensive team or classroom environment, that loop is considerably more useful than a raw notebook cell that prints a confusion matrix and exits.",
        "The key caveat is that the pipeline's semantic richness exceeds the semantic richness of the source labels. The product speaks in attack behaviors, but the local benchmark remains binary. Accordingly, any operator or researcher using the tool should treat behavior names as structured hypotheses derived from connection patterns, not as irrefutable ground-truth families.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(RLImage(str(context["assets"]["status_terminal.png"]), width=6.8 * inch, height=4.4 * inch))
    story.append(Paragraph("Figure 3. Terminal-styled rendering of the live `status` command used as primary local evidence.", s["Caption"]))


def append_chapter_ml(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("6. Supervised Training Subsystems and Historical Results", s["Heading1"]))
    paragraphs = [
        "Although the primary packaged product surface now emphasizes the lightweight analyzer, the repository still carries a more conventional machine-learning subsystem. The classical suite assembles logistic regression, Gaussian Naive Bayes, decision tree, AdaBoost, random forest, and K-nearest neighbors under a consistent training-and-summary interface. The DNN suite does something similar for TensorFlow-backed architectures. Historical evidence in `automation/runs` confirms that these paths were executed previously and that structured summaries were persisted.",
        "The run artifacts are locally persuasive but scientifically limited. Several classical runs report best accuracies in the low 0.92 to 0.93 range, with random forest or AdaBoost usually emerging as the best classical model. The strongest recorded DNN run in the local artifacts reaches approximately 0.9215 accuracy for a three-layer network over a larger train/test sample pair. Those are competent benchmark numbers. They are also exactly the kind of same-dataset numbers that the broader literature warns can be misleading when generalized beyond a single data family.",
        "The engineering story is even more interesting than the metric story. In the current Python environment used for this report, the legacy terminal training path fails before it can even present help because `joblib` is missing. The API module imports FastAPI and Pydantic directly, and those packages are also absent. The DNN code requires TensorFlow and numpy, which are absent as well. This means that the repo contains valuable historical training evidence, but the installable product surface is only partially honest about the runtime stack required to reproduce that evidence from scratch.",
        "There is a deeper lesson here. By keeping the pure-Python analyzer separate from the heavier training paths, the repository has accidentally discovered a sensible product pattern: the everyday operational console can remain light, while the research-oriented training surfaces can become explicit extras. The problem is not that optional dependencies exist. The problem is that the current package metadata does not clearly express them.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(runs_table(context))
    story.append(Paragraph("Table 3. Historical run summaries recorded under `automation/runs`.", s["Caption"]))


def append_chapter_operations(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("7. Operational Tool Surface", s["Heading1"]))
    paragraphs = [
        "A notable strength of IDS Sentinel Terminal is that it does not confine itself to one analytic gesture. The command surface spans status dashboards, CSV analysis, dataset catalog inspection, IOC management, keyword hunting, hashing, file scanning, DNS resolution, local process listing, port explanations, port probing, and network connection parsing. That breadth is precisely what makes the tool feel closer to a compact analyst workbench than to a single-purpose benchmark harness.",
        "The GUI reinforces that interpretation. The live window captured for this report demonstrates a dark-mode, analyst-oriented design with a persistent sidebar, tabbed control plane, and a scrollable output console. Crucially, it does not invent a second logic layer. It calls into the same command routines as the terminal interface and color-tags the resulting output for readability. This is the correct kind of GUI for a tool at this maturity level: it adds operational affordance without forking the behavior model.",
        "The command set is also disciplined. Where many internal tools would expose raw shell execution or broad remote scanning, this product prefers bounded operations. The port probe is a TCP connect probe with a capped port list. The shell-like layer favors read-oriented operations such as `ls`, `cat`, `head`, `tail`, `find`, and `grep` style behaviors inside a controlled environment. The report interprets this as an implicit safety posture. Even where the code is informal, the operator affordances are not recklessly broad.",
        "The main operational weakness in this layer is platform realism. The netstat parsing routine clearly assumes Windows `netstat -ano` formatting and loads service names from the Windows services file path. The GUI itself is cross-platform in principle because Tkinter is standard, but the host-triage commands are not yet abstracted by platform. The current product should therefore be described as packaging-portable before it is described as operationally identical across macOS, Linux, and Windows.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(RLImage(str(context["assets"]["gui"]), width=6.85 * inch, height=4.42 * inch))
    story.append(Paragraph("Figure 4. Live window capture of the Tk-based GUI running the traffic workflow.", s["Caption"]))
    story.append(RLImage(str(context["assets"]["ports_terminal.png"]), width=6.8 * inch, height=4.2 * inch))
    story.append(Paragraph("Figure 5. Terminal-styled rendering of the local port inspection output.", s["Caption"]))


def append_chapter_distribution(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("8. Distribution Engineering and Release Posture", s["Heading1"]))
    paragraphs = [
        "Packaging is where this repository most clearly departs from the academic-project stereotype. The `pyproject.toml` file defines installable console scripts, a GUI script, package data for bundled assets, version metadata, and cross-platform classifiers. The release workflow builds wheel and source distributions, smoke-tests the built wheel, uploads artifacts, attaches them to GitHub releases, and then publishes to PyPI using trusted publishing through GitHub OIDC. In other words, the project already has the skeleton of a legitimate downloadable toolchain.",
        "The supporting documentation consulted for this report aligns well with the implementation direction. The Python `zipapp` documentation explains how self-contained Python applications can be distributed once dependencies are bundled. The tkinter documentation confirms the standard-library nature of the GUI foundation across Windows, macOS, and Unix-like systems. GitHub and PyPI documentation describe the exact OIDC-driven trusted publishing flow already encoded in the workflow file. On paper, therefore, the distribution strategy is technically coherent.",
        "The weakness is again one of truthfulness rather than ambition. The package metadata currently exposes a CLI and GUI but does not declare the broader dependency landscape required by the API module, the legacy terminal, or the training suites. A wheel built from this metadata is a working product shell, not a full scientific environment. That is still valuable, but it should be named explicitly. The package today is best described as a lightweight operational console with optional research subsystems, not as a single install that enables every path in the repository.",
        "This distinction matters even more because the product now aspires to `pipx`-style consumption. Users who install a CLI via `pipx` reasonably expect the declared metadata to be the source of truth. If critical dependencies are intentionally optional, they should be organized as extras and documented as such. If they are actually required for certain public commands, they belong in the dependency metadata.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(environment_table(context))
    story.append(Paragraph("Table 4. Dependency observations from the exact Python environment used to produce this report.", s["Caption"]))


def append_chapter_risks(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("9. Critical Findings, Bugs, and Optimization Priorities", s["Heading1"]))
    findings = [
        "Undeclared dependencies are the most important verified product issue. The installable metadata does not list joblib, numpy, fastapi, pydantic, scikit-learn, or tensorflow even though repository modules import them directly.",
        "The legacy terminal fails immediately in the observed environment with `ModuleNotFoundError: No module named 'joblib'`, proving that at least one public code path is not reproducible from the declared package surface alone.",
        "The API module imports FastAPI and Pydantic at module import time. Because these packages are absent, the API surface is also not reproducible from the package metadata.",
        "Network inspection behavior is Windows-centric. The code parses `netstat -ano` output and consults the Windows `services` file path, so the current implementation does not justify a claim of identical operational behavior on Linux and macOS.",
        "The core orchestration file is large and multi-concern. This is not an immediate runtime defect, but it is the principal maintainability risk and the most likely source of future regressions.",
        "There is still a naming mismatch between the repo's historical local folder name and the newer `IDS-Sentinel` branding. This is an operational/documentation mismatch more than a code defect, but it increases confusion for users following installation or publication instructions.",
        "The scientific evaluation story remains bound to KDD-style data for local evidence. Without integrated cross-dataset evaluation, the product cannot yet claim robust contemporary generalization.",
        "The release workflow's smoke test is modest. It proves wheel installability and basic CLI health but does not verify GUI launch, optional dependencies, or training reproducibility.",
    ]
    story.append(paragraph("The report's bug audit is intentionally conservative: only issues that were directly supported by local execution, code inspection, or authoritative documentation are listed as findings.", s["BodyText"]))
    for item in findings:
        story.append(bullet(item, s["BulletBody"]))
    story.append(Paragraph("Observed failure evidence", s["Heading2"]))
    story.append(
        Preformatted(
            textwrap.shorten(context["legacy_failure"], width=1200, placeholder=" ..."),
            ParagraphStyle(
                "FailureBlock",
                fontName=MONO,
                fontSize=7.6,
                leading=9.1,
                textColor=colors.HexColor("#7A1C1C"),
                backColor=colors.HexColor("#FFF2F2"),
                borderPadding=6,
                borderWidth=0.4,
                borderColor=colors.HexColor("#E3B9B9"),
            ),
        )
    )
    roadmaps = [
        "Refactor `product_terminal.py` into command modules grouped by concern: data, analytics, IOC, host triage, output, and parser wiring.",
        "Declare an explicit base dependency set for the operational console and separate extras such as `[api]`, `[ml]`, and `[dnn]` for optional surfaces.",
        "Add a platform abstraction for local host inspection instead of hard-coding Windows netstat assumptions.",
        "Build an integrated evaluation harness for CIC-IDS2017 and UNSW-NB15 so that the external catalog becomes actionable research infrastructure.",
        "Add contract tests for `status`, `scan`, export generation, cache listing, and parser behavior, plus smoke tests for GUI launch in CI.",
    ]
    story.append(Paragraph("Priority optimization roadmap", s["Heading2"]))
    for item in roadmaps:
        story.append(bullet(item, s["BulletBody"]))


def append_conclusion(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("10. Conclusion", s["Heading1"]))
    paragraphs = [
        "IDS Sentinel Terminal has crossed an important threshold. It is no longer just a collection of intrusion-detection experiments. It is a working defensive console with a coherent brand, a packageable CLI, a native GUI, reproducible export artifacts, and a lightweight scoring model that can operate in a constrained Python environment. Those are not trivial achievements, especially when compared with many security-analytics repositories that never move beyond notebooks and screenshots.",
        "Yet the report's central conclusion is deliberately balanced. The product is operationally ahead of its metadata and scientifically ahead of its benchmark story. Operationally, several public surfaces still depend on libraries that the package does not declare, and some host-oriented commands remain Windows-shaped. Scientifically, the bundled KDD-derived data supports local demonstrations but cannot carry a modern generalization claim on its own. These are solvable issues, but they are foundational issues rather than cosmetic ones.",
        "If the repository continues along its current trajectory, the most promising direction is not simply to add more commands. It is to stabilize the product contract. That means separating base and optional dependencies, modularizing the command core, and turning the external dataset catalog into a formal evaluation pipeline. With those changes, the codebase could legitimately position itself as a portable analyst tool that is anchored in both usability and research discipline. Without them, it remains a strong prototype whose best qualities are clarity of intent, pragmatic packaging work, and a surprisingly usable local analysis workflow.",
    ]
    for text in paragraphs:
        story.append(paragraph(text, s["BodyText"]))
    story.append(PageBreak())


def append_feature_glossary(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("Appendix A. Feature Glossary and Analytical Interpretation", s["Heading1"]))
    descriptions = context["feature_descriptions"]
    for name in product_terminal.FEATURE_NAMES:
        story.append(Paragraph(name, s["Heading2"]))
        base = descriptions.get(name, "No local description was supplied.")
        extra = (
            f"In this repository, the feature participates in a binary normal-versus-attack setting and may also feed higher-level behavior inference. "
            f"Analysts should therefore read it both as a raw benchmark field and as an ingredient in the product's narrative scoring pipeline."
        )
        story.append(paragraph(f"{base} {extra}", s["BodyText"]))


def append_command_reference(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("Appendix B. Command Reference", s["Heading1"]))
    descriptions = command_descriptions()
    for name, desc in context["subcommands"]:
        story.append(Paragraph(name, s["Heading2"]))
        story.append(paragraph(descriptions[name], s["BodyText"]))
        story.append(paragraph(f"Observed parser usage: {desc}", s["Small"]))


def append_module_appendix(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("Appendix C. Module-by-Module Symbol Inventory", s["Heading1"]))
    for module in context["modules"]:
        story.append(Paragraph(module.path, s["Heading2"]))
        intro = (
            f"This module contains {module.line_count:,} lines, {module.function_count} top-level function(s), and {module.class_count} top-level class(es). "
            f"The table below is generated directly from the Python AST and therefore reflects the actual structure of the checked-out code."
        )
        story.append(paragraph(intro, s["BodyText"]))
        rows = [["Symbol", "Kind", "Start", "End", "Approximate responsibility"]]
        for class_info in module.classes:
            rows.append([class_info.name, "class", class_info.start, class_info.end, "Encapsulates a focused behavior cluster within the module."])
        for func in module.functions:
            rows.append([func.name, "function", func.start, func.end, infer_function_role(func.name)])
        table = LongTable(rows, repeatRows=1, colWidths=[1.65 * inch, 0.65 * inch, 0.5 * inch, 0.5 * inch, 4.0 * inch])
        table.setStyle(table_style())
        story.append(table)
        story.append(Spacer(1, 0.1 * inch))


def infer_function_role(name: str) -> str:
    mapping = {
        "show": "Formats and presents operator-facing output.",
        "load": "Loads data or configuration from storage or the environment.",
        "read": "Reads a persisted artifact.",
        "write": "Writes a persisted artifact.",
        "parse": "Interprets text or user input into structured values.",
        "run": "Executes a workflow, command, or worker path.",
        "build": "Constructs a parser, model, or object graph.",
        "hash": "Computes a file digest for triage.",
        "scan": "Performs analysis over a file or dataset.",
        "learn": "Builds or refreshes a learned profile.",
        "classify": "Converts signals into a risk or behavior label.",
        "list": "Enumerates available artifacts or resources.",
        "probe": "Actively tests a local or remote endpoint.",
        "resolve": "Normalizes config or paths into concrete objects.",
    }
    for prefix, role in mapping.items():
        if name.startswith(prefix):
            return role
    return "Support routine in the module's local workflow."


def append_code_listings(story: list[Any], s: dict[str, ParagraphStyle], extra_chunks: int) -> None:
    story.append(Paragraph("Appendix D. Annotated Code Listings", s["Heading1"]))
    for spec in listing_specs():
        story.append(Paragraph(spec.title, s["Heading2"]))
        story.append(paragraph(spec.explanation, s["CodeCommentary"]))
        code = extract_code(spec.path, spec.start, spec.end)
        story.append(
            Preformatted(
                code,
                ParagraphStyle(
                    "Code",
                    fontName=MONO,
                    fontSize=7.3,
                    leading=8.7,
                    backColor=colors.HexColor("#F6F8FA"),
                    borderPadding=5,
                    borderColor=GRID,
                    borderWidth=0.35,
                ),
            )
        )
        story.append(Spacer(1, 0.1 * inch))

    if extra_chunks > 0:
        story.append(Paragraph("Appendix E. Extended Core Listings", s["Heading1"]))
        chunk_size = 72
        start_line = 1
        for chunk_index in range(extra_chunks):
            chunk_start = start_line + chunk_index * chunk_size
            chunk_end = chunk_start + chunk_size - 1
            story.append(Paragraph(f"Extended core chunk {chunk_index + 1}: `product_terminal.py` lines {chunk_start}-{chunk_end}", s["Heading2"]))
            story.append(
                paragraph(
                    "These extended chunks are included because the repository's primary orchestration logic is too central to summarize responsibly in only a few excerpts. "
                    "They allow a reader to inspect the surrounding implementation context directly.",
                    s["CodeCommentary"],
                )
            )
            code = extract_code("ids_app/product_terminal.py", chunk_start, chunk_end)
            story.append(
                Preformatted(
                    code,
                    ParagraphStyle(
                        "CodeExtended",
                        fontName=MONO,
                        fontSize=7.2,
                        leading=8.5,
                        backColor=colors.HexColor("#FBFBFB"),
                        borderPadding=5,
                        borderColor=GRID,
                        borderWidth=0.35,
                    ),
                )
            )


def append_output_appendix(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("Appendix F. Live Output Evidence", s["Heading1"]))
    figures = [
        ("Status command output", context["assets"]["status_terminal.png"]),
        ("Attacks command output", context["assets"]["attacks_terminal.png"]),
        ("Ports command output", context["assets"]["ports_terminal.png"]),
    ]
    for title, image_path in figures:
        story.append(Paragraph(title, s["Heading2"]))
        story.append(RLImage(str(image_path), width=6.8 * inch, height=4.15 * inch))
        story.append(Paragraph(f"Figure. {title} rendered from a live command invocation in the report environment.", s["Caption"]))


def numbered_text_block(text: str) -> str:
    lines = text.splitlines()
    width = len(str(len(lines) or 1))
    return "\n".join(f"{index:{width}d}: {line}" for index, line in enumerate(lines, start=1))


def append_raw_evidence(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("Appendix G. Primary JSON Evidence Dumps", s["Heading1"]))
    evidence = [
        ("status --json", json.dumps(context["status"], indent=2)),
        ("attacks --json", json.dumps(context["attacks"], indent=2)),
        ("datasets --json", json.dumps(context["datasets"], indent=2)),
        ("runs --json", json.dumps(context["runs"], indent=2)),
    ]
    style = ParagraphStyle(
        "EvidenceCode",
        fontName=MONO,
        fontSize=6.6,
        leading=7.8,
        backColor=colors.HexColor("#F8FAFC"),
        borderPadding=5,
        borderColor=GRID,
        borderWidth=0.35,
    )
    for title, payload in evidence:
        story.append(Paragraph(title, s["Heading2"]))
        story.append(
            paragraph(
                "This dump is included verbatim from a live command invocation so that readers can inspect the exact machine-readable structure behind the narrative summaries used earlier in the report.",
                s["CodeCommentary"],
            )
        )
        story.append(Preformatted(numbered_text_block(payload), style))


def append_bibliography(story: list[Any], s: dict[str, ParagraphStyle], context: dict[str, Any]) -> None:
    story.append(Paragraph("Appendix H. Annotated Bibliography", s["Heading1"]))
    for source in context["sources"]:
        story.append(Paragraph(f"[{source.source_id}] {source.title}", s["Heading2"]))
        entry = f"{source.authors}. {source.year}. {source.url}"
        story.append(paragraph(entry, s["Small"]))
        story.append(paragraph(f"{source.access_note} {source.relevance}", s["BodyText"]))


def build_story(context: dict[str, Any], extra_chunks: int) -> list[Any]:
    s = styles()
    story: list[Any] = []
    append_story_intro(story, s, context)
    append_abstract(story, s, context)
    append_chapter_introduction(story, s, context)
    append_chapter_foundations(story, s, context)
    append_chapter_datasets(story, s, context)
    append_chapter_architecture(story, s, context)
    append_chapter_detection(story, s, context)
    append_chapter_ml(story, s, context)
    append_chapter_operations(story, s, context)
    append_chapter_distribution(story, s, context)
    append_chapter_risks(story, s, context)
    append_conclusion(story, s, context)
    append_feature_glossary(story, s, context)
    append_command_reference(story, s, context)
    append_module_appendix(story, s, context)
    append_code_listings(story, s, extra_chunks)
    append_output_appendix(story, s, context)
    append_raw_evidence(story, s, context)
    append_bibliography(story, s, context)
    return story


def build_pdf(context: dict[str, Any], extra_chunks: int) -> int:
    doc = SimpleDocTemplate(
        str(REPORT_PATH),
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.8 * inch,
        title="IDS Sentinel Terminal Research Report",
        author="OpenAI Codex",
    )
    story = build_story(context, extra_chunks)
    doc.build(story, canvasmaker=NumberedCanvas)
    return NumberedCanvas.last_page_count


def choose_chunk_count(context: dict[str, Any], min_pages: int, max_pages: int) -> int:
    extra_chunks = 12
    for _ in range(6):
        page_count = build_pdf(context, extra_chunks)
        if min_pages <= page_count <= max_pages:
            return extra_chunks
        if page_count < min_pages:
            extra_chunks += max(1, math.ceil((min_pages - page_count) / 2))
        else:
            extra_chunks = max(0, extra_chunks - max(1, math.ceil((page_count - max_pages) / 2)))
    return extra_chunks


def build_report(min_pages: int, max_pages: int) -> tuple[Path, int]:
    context = build_context()
    extra_chunks = choose_chunk_count(context, min_pages, max_pages)
    page_count = build_pdf(context, extra_chunks)
    return REPORT_PATH, page_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the IDS Sentinel Terminal research report PDF.")
    parser.add_argument("--min-pages", type=int, default=130)
    parser.add_argument("--max-pages", type=int, default=150)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_dirs()
    report_path, page_count = build_report(args.min_pages, args.max_pages)
    print(report_path.relative_to(ROOT))
    print(f"pages={page_count}")
    if not (args.min_pages <= page_count <= args.max_pages):
        print(f"warning: page count is outside the requested range {args.min_pages}-{args.max_pages}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
