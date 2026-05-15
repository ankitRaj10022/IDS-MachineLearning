from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import ipaddress
import importlib.resources
import json
import math
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from . import __version__

PACKAGE_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_DIR.parent.resolve()
DEFAULT_HOME_DIR = Path.home() / ".ids-sentinel-terminal"
IS_SOURCE_CHECKOUT = (SOURCE_ROOT / ".git").exists() and (SOURCE_ROOT / "kddtrain.csv").exists() and (SOURCE_ROOT / "kddtest.csv").exists()
ENV_ROOT = os.environ.get("IDS_PRODUCT_HOME")
ROOT_DIR = Path(ENV_ROOT).expanduser().resolve() if ENV_ROOT else (SOURCE_ROOT if IS_SOURCE_CHECKOUT else DEFAULT_HOME_DIR.resolve())
RUNTIME_MODE = "override" if ENV_ROOT else ("source" if IS_SOURCE_CHECKOUT else "installed")
BUNDLED_SEED_FILES = {
    "kddtrain.csv": "kddtrain.csv",
    "kddtest.csv": "kddtest.csv",
    "automation/product/self_learning_model.json": "self_learning_model.json",
    "automation/product/iocs.json": "iocs.json",
}


def _copy_bundled_asset(asset_name: str, destination: Path) -> None:
    resource = importlib.resources.files("ids_app").joinpath("assets", asset_name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with importlib.resources.as_file(resource) as source_path:
        shutil.copy2(source_path, destination)


def bootstrap_runtime_home() -> None:
    if RUNTIME_MODE == "source":
        return
    ROOT_DIR.mkdir(parents=True, exist_ok=True)
    for relative_target, asset_name in BUNDLED_SEED_FILES.items():
        destination = ROOT_DIR / relative_target
        if destination.exists():
            continue
        _copy_bundled_asset(asset_name, destination)


bootstrap_runtime_home()

TRAIN_CSV = ROOT_DIR / "kddtrain.csv"
TEST_CSV = ROOT_DIR / "kddtest.csv"
PRODUCT_DIR = ROOT_DIR / "automation" / "product"
EXPORTS_DIR = PRODUCT_DIR / "exports"
IMPORTS_DIR = PRODUCT_DIR / "imports"
CACHE_DIR = PRODUCT_DIR / "cache"
INDEX_DIR = CACHE_DIR / "indexes"
COMMAND_CACHE_DIR = CACHE_DIR / "commands"
LEGACY_INDEX_DIR = PRODUCT_DIR / "indexes"
MODEL_PATH = PRODUCT_DIR / "self_learning_model.json"
IOC_PATH = PRODUCT_DIR / "iocs.json"

SHELL_STATE = {"cwd": ROOT_DIR, "history": []}

EXTERNAL_DATASETS = [
    {
        "id": "cicids2017",
        "name": "CIC-IDS2017",
        "source": "Canadian Institute for Cybersecurity, University of New Brunswick",
        "url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "format": "PCAP and CICFlowMeter CSV flow data",
        "notes": "Contains benign traffic plus FTP/SSH brute force, DoS, Heartbleed, web attacks, infiltration, botnet, DDoS, and port scan scenarios.",
    },
    {
        "id": "unsw-nb15",
        "name": "UNSW-NB15",
        "source": "UNSW Canberra Cyber Range Lab",
        "url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "format": "CSV network-flow features with binary and attack-category labels",
        "notes": "Contains normal traffic and Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.",
    },
    {
        "id": "unsw-nb15-hf",
        "name": "UNSW-NB15 Hugging Face mirror",
        "source": "Hugging Face community dataset mirror",
        "url": "https://huggingface.co/datasets/lacg030175/UNSW-NB15",
        "format": "Dataset hub train/test splits",
        "notes": "Useful when the Python datasets package is installed. This terminal can still import downloaded CSV files directly.",
    },
]

COMMON_PORT_RISKS = {
    20: "FTP data channel. Plaintext file transfer; watch for data exfiltration.",
    21: "FTP control. Plaintext credentials; common brute-force target.",
    22: "SSH. Remote admin service; watch for brute-force and unusual geos.",
    23: "Telnet. Plaintext remote shell; should usually be disabled.",
    25: "SMTP. Mail relay; watch for spam abuse and open relay exposure.",
    53: "DNS. Watch for tunneling, amplification, and suspicious resolver exposure.",
    80: "HTTP. Web service; inspect for web attacks and exposed admin panels.",
    110: "POP3. Plaintext mail retrieval unless wrapped; legacy exposure risk.",
    135: "MS RPC. Windows lateral-movement surface; restrict to trusted networks.",
    139: "NetBIOS. Legacy Windows file-sharing surface.",
    143: "IMAP. Mail retrieval; watch authentication abuse.",
    443: "HTTPS. Web service; inspect certificates and web attack logs.",
    445: "SMB. High-value Windows file-sharing target; restrict heavily.",
    1433: "Microsoft SQL Server. Database exposure risk.",
    1521: "Oracle database listener. Database exposure risk.",
    2049: "NFS. File-sharing service; restrict to trusted hosts.",
    2375: "Docker API without TLS. Critical exposure if reachable.",
    3306: "MySQL/MariaDB. Database exposure risk.",
    3389: "RDP. Common brute-force and ransomware entry point.",
    5432: "PostgreSQL. Database exposure risk.",
    5900: "VNC. Remote desktop; often weakly protected.",
    6379: "Redis. Critical if unauthenticated or internet-exposed.",
    8080: "Alternate HTTP/proxy/admin service.",
    9200: "Elasticsearch. Data exposure risk if unauthenticated.",
    11211: "Memcached. Amplification and data exposure risk.",
    27017: "MongoDB. Database exposure risk.",
}
COMMON_PROBE_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017]
TEXT_SEARCH_MAX_FILE_BYTES = 128 * 1024 * 1024
TEXT_SEARCH_SKIP_SUFFIXES = {
    ".7z",
    ".bin",
    ".dll",
    ".exe",
    ".gz",
    ".h5",
    ".joblib",
    ".jpg",
    ".jpeg",
    ".keras",
    ".pdf",
    ".png",
    ".pyc",
    ".tar",
    ".zip",
}

SUSPICIOUS_FILE_PATTERNS = [
    "powershell -enc",
    "powershell.exe -enc",
    "frombase64string",
    "invoke-expression",
    "downloadstring",
    "certutil -urlcache",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "wscript.shell",
    "mimikatz",
    "meterpreter",
    "cobalt strike",
    "reverse_tcp",
    "cmd.exe /c",
]

BINARY_LABELS = {"0": "normal", "1": "attack"}
CSV_FEATURE_PREFIX = "feature_"
FEATURE_NAMES = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


def ensure_product_dirs() -> None:
    for path in (PRODUCT_DIR, EXPORTS_DIR, IMPORTS_DIR, CACHE_DIR, INDEX_DIR, COMMAND_CACHE_DIR):
        path.mkdir(parents=True, exist_ok=True)
    if LEGACY_INDEX_DIR.exists() and LEGACY_INDEX_DIR.is_dir():
        for legacy_file in LEGACY_INDEX_DIR.glob("*.json"):
            target = INDEX_DIR / legacy_file.name
            if not target.exists():
                shutil.move(str(legacy_file), str(target))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def compact_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def relative_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def format_number(value: Any) -> str:
    if isinstance(value, float):
        if abs(value) >= 1000:
            return f"{value:,.0f}"
        return f"{value:.4f}"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def percent(part: int | float, total: int | float) -> str:
    if not total:
        return "0.00%"
    return f"{(float(part) / float(total)) * 100:.2f}%"


def table(headers: list[str], rows: list[list[Any]]) -> str:
    text_rows = [[format_number(cell) for cell in row] for row in rows]
    widths = [
        max(len(header), *(len(row[index]) for row in text_rows)) if text_rows else len(header)
        for index, header in enumerate(headers)
    ]
    header_line = "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    rule = "  ".join("-" * width for width in widths)
    body = ["  ".join(row[index].ljust(widths[index]) for index in range(len(headers))) for row in text_rows]
    return "\n".join([header_line, rule, *body])


def section(title: str) -> None:
    print(f"\n{title}")
    print("=" * len(title))


def print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=False))


def resolve_repo_path(path_text: str | None, default: Path = TEST_CSV) -> Path:
    if not path_text:
        return default
    path = Path(path_text)
    if not path.is_absolute():
        path = ROOT_DIR / path
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT_DIR)
    except ValueError:
        raise ValueError("path must stay inside the IDS Sentinel home directory")
    return resolved


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)


def cache_artifact(kind: str, payload: Any) -> Path:
    ensure_product_dirs()
    safe_kind = re.sub(r"[^A-Za-z0-9_.-]+", "_", kind).strip("_") or "artifact"
    path = COMMAND_CACHE_DIR / f"{compact_timestamp()}_{safe_kind}_{uuid4().hex[:8]}.json"
    write_json(path, {"created_at": utc_now(), "kind": kind, "payload": payload})
    prune_cache_artifacts()
    return path


def prune_cache_artifacts(max_files: int = 500) -> None:
    artifacts = sorted(COMMAND_CACHE_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    for stale in artifacts[max_files:]:
        stale.unlink(missing_ok=True)


def path_cache_key(path: Path) -> str:
    resolved = str(path.resolve()).lower()
    digest = hashlib.sha1(resolved.encode("utf-8")).hexdigest()[:16]
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)[:80]
    return f"{safe_name}.{digest}"


def file_signature(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def cached_json_path(path: Path, suffix: str) -> Path:
    return INDEX_DIR / f"{path_cache_key(path)}.{suffix}.json"


def is_cache_current(path: Path, payload: dict[str, Any] | None) -> bool:
    if not payload:
        return False
    return payload.get("signature") == file_signature(path)


def likely_header(row: list[str]) -> bool:
    if not row:
        return False
    numeric = 0
    for value in row:
        try:
            float(value)
            numeric += 1
        except ValueError:
            pass
    return numeric < max(1, len(row) // 2)


def all_csv_sources(include_exports: bool = True) -> list[Path]:
    sources = [TRAIN_CSV, TEST_CSV]
    if IMPORTS_DIR.exists():
        sources.extend(sorted(IMPORTS_DIR.glob("*.csv")))
    if include_exports and EXPORTS_DIR.exists():
        sources.extend(sorted(EXPORTS_DIR.glob("*.csv")))
    return [path for path in sources if path.exists()]


def resolve_any_product_path(path_text: str | None, default: Path = TEST_CSV) -> Path:
    if not path_text:
        return default
    path = Path(path_text)
    if not path.is_absolute():
        shell_cwd = Path(SHELL_STATE.get("cwd", ROOT_DIR))
        path = shell_cwd / path
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT_DIR)
    except ValueError:
        raise ValueError("path must stay inside the IDS Sentinel home directory")
    return resolved


def resolve_readable_path(path_text: str | None, default: Path | None = None, base: Path | None = None) -> Path:
    if not path_text:
        if default is None:
            raise ValueError("path is required")
        path = default
    else:
        path = Path(path_text)
        if not path.is_absolute():
            path = (base or ROOT_DIR) / path
    resolved = path.resolve()
    if not resolved.exists() or not resolved.is_file():
        raise ValueError(f"not a readable file: {path_text or default}")
    return resolved


def safe_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def iter_kdd_rows(path: Path, limit: int | None = None) -> Iterable[tuple[int, str, list[float]]]:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        emitted = 0
        for row_number, row in enumerate(reader, start=1):
            if len(row) < len(FEATURE_NAMES) + 1:
                continue
            features = [safe_float(value) for value in row[1 : len(FEATURE_NAMES) + 1]]
            yield row_number, row[0].strip(), features
            emitted += 1
            if limit is not None and emitted >= limit:
                return


def iter_generated_rows(path: Path, limit: int | None = None) -> Iterable[tuple[int, str, list[float]]]:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        emitted = 0
        for row_number, row in enumerate(reader, start=2):
            label = str(row.get("actual_label") or row.get("label") or "").strip()
            if label not in BINARY_LABELS:
                continue
            features = [safe_float(row.get(f"{CSV_FEATURE_PREFIX}{name}", "0")) for name in FEATURE_NAMES]
            yield row_number, label, features
            emitted += 1
            if limit is not None and emitted >= limit:
                return


@dataclass
class RunningStat:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    min_value: float = math.inf
    max_value: float = -math.inf

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        self.min_value = min(self.min_value, value)
        self.max_value = max(self.max_value, value)

    def to_json(self) -> dict[str, float | int]:
        variance = self.m2 / max(self.count - 1, 1)
        return {
            "count": self.count,
            "mean": round(self.mean, 8),
            "variance": round(max(variance, 1e-9), 8),
            "min": round(self.min_value if self.count else 0.0, 8),
            "max": round(self.max_value if self.count else 0.0, 8),
        }


def empty_label_stats() -> dict[str, list[RunningStat]]:
    return {label: [RunningStat() for _ in FEATURE_NAMES] for label in BINARY_LABELS}


def update_model_stats(stats: dict[str, list[RunningStat]], labels: Counter[str], label: str, features: list[float]) -> None:
    if label not in stats:
        return
    labels[label] += 1
    for index, value in enumerate(features):
        stats[label][index].update(value)


def generated_export_paths() -> list[Path]:
    if not EXPORTS_DIR.exists():
        return []
    return sorted(EXPORTS_DIR.glob("traffic_analysis_*.csv"))


def learn_model(
    *,
    limit: int | None = None,
    include_generated: bool = True,
    include_test: bool = False,
) -> dict[str, Any]:
    ensure_product_dirs()
    stats = empty_label_stats()
    labels: Counter[str] = Counter()
    sources: list[dict[str, Any]] = []

    source_paths = [TRAIN_CSV]
    if include_test:
        source_paths.append(TEST_CSV)

    for path in source_paths:
        rows_used = 0
        source_labels: Counter[str] = Counter()
        for _, label, features in iter_kdd_rows(path, limit):
            update_model_stats(stats, labels, label, features)
            source_labels[label] += 1
            rows_used += 1
        sources.append({"path": relative_path(path), "rows_used": rows_used, "label_counts": dict(source_labels)})

    if include_generated:
        for path in generated_export_paths():
            rows_used = 0
            source_labels = Counter()
            for _, label, features in iter_generated_rows(path, limit):
                update_model_stats(stats, labels, label, features)
                source_labels[label] += 1
                rows_used += 1
            if rows_used:
                sources.append({"path": relative_path(path), "rows_used": rows_used, "label_counts": dict(source_labels)})

    total_rows = sum(labels.values())
    if total_rows == 0 or labels["0"] == 0 or labels["1"] == 0:
        raise RuntimeError("not enough labeled normal and attack rows to build a model")

    label_payload: dict[str, Any] = {}
    for label in BINARY_LABELS:
        label_payload[label] = {
            "name": BINARY_LABELS[label],
            "count": labels[label],
            "prior": labels[label] / total_rows,
            "features": [item.to_json() for item in stats[label]],
        }

    top_indicators = rank_indicators(label_payload)
    model = {
        "version": 1,
        "created_at": utc_now(),
        "model_type": "streaming_gaussian_profile",
        "description": "Pure-Python self-learning profile built from labeled IDS CSV rows and terminal-generated analysis exports.",
        "features": FEATURE_NAMES,
        "labels": label_payload,
        "total_rows": total_rows,
        "sources": sources,
        "top_indicators": top_indicators[:12],
    }
    write_json(MODEL_PATH, model)
    cache_artifact("learn", {"model_path": relative_path(MODEL_PATH), "rows_learned": total_rows, "sources": sources})
    return model


def rank_indicators(label_payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    normal_stats = label_payload["0"]["features"]
    attack_stats = label_payload["1"]["features"]
    for index, name in enumerate(FEATURE_NAMES):
        normal = normal_stats[index]
        attack = attack_stats[index]
        pooled_std = math.sqrt((float(normal["variance"]) + float(attack["variance"])) / 2.0)
        score = abs(float(attack["mean"]) - float(normal["mean"])) / max(pooled_std, 1e-6)
        rows.append(
            {
                "feature": name,
                "separation": round(score, 6),
                "normal_mean": round(float(normal["mean"]), 6),
                "attack_mean": round(float(attack["mean"]), 6),
            }
        )
    rows.sort(key=lambda item: item["separation"], reverse=True)
    return rows


def load_or_learn_model(auto_learn: bool = True) -> dict[str, Any]:
    model = read_json(MODEL_PATH)
    if model:
        return model
    if not auto_learn:
        raise RuntimeError("model does not exist yet; run 'learn' first")
    return learn_model(limit=None)


def gaussian_log_probability(features: list[float], label_model: dict[str, Any], indicator_names: set[str] | None = None) -> float:
    logp = math.log(max(float(label_model["prior"]), 1e-12))
    for index, value in enumerate(features):
        name = FEATURE_NAMES[index]
        if indicator_names is not None and name not in indicator_names:
            continue
        stat = label_model["features"][index]
        mean = float(stat["mean"])
        variance = max(float(stat["variance"]), 1e-6)
        logp += -0.5 * math.log(2.0 * math.pi * variance)
        logp += -((value - mean) ** 2) / (2.0 * variance)
    return logp


def score_row(model: dict[str, Any], features: list[float]) -> dict[str, Any]:
    indicator_names = {item["feature"] for item in model.get("top_indicators", [])[:16]} or None
    normal_log = gaussian_log_probability(features, model["labels"]["0"], indicator_names)
    attack_log = gaussian_log_probability(features, model["labels"]["1"], indicator_names)
    delta = max(min(attack_log - normal_log, 60.0), -60.0)
    attack_probability = 1.0 / (1.0 + math.exp(-delta))
    predicted = "1" if attack_probability >= 0.5 else "0"
    confidence = abs(attack_probability - 0.5) * 2.0
    family, reasons = classify_behavior(features, attack_probability, model)
    return {
        "predicted_label": predicted,
        "predicted_name": BINARY_LABELS[predicted],
        "risk_score": round(attack_probability, 6),
        "confidence": round(confidence, 6),
        "risk_level": risk_level(attack_probability),
        "family": family,
        "reasons": reasons,
    }


def feature_map(features: list[float]) -> dict[str, float]:
    return dict(zip(FEATURE_NAMES, features))


def risk_level(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def classify_behavior(features: list[float], risk_score: float, model: dict[str, Any]) -> tuple[str, str]:
    values = feature_map(features)
    families: list[str] = []
    reasons: list[str] = []

    if values["count"] >= 80 or values["srv_count"] >= 80 or values["serror_rate"] >= 0.5 or values["srv_serror_rate"] >= 0.5:
        families.append("dos_flood")
        reasons.append("high connection or service-error rate")
    if values["diff_srv_rate"] >= 0.35 or values["srv_diff_host_rate"] >= 0.35 or values["dst_host_srv_diff_host_rate"] >= 0.35:
        families.append("probe_scan")
        reasons.append("high service or host diversity")
    if values["num_failed_logins"] > 0 or values["is_guest_login"] > 0 or values["logged_in"] == 0 and values["hot"] >= 2:
        families.append("credential_abuse")
        reasons.append("login or credential anomaly")
    if values["root_shell"] > 0 or values["su_attempted"] > 0 or values["num_compromised"] > 0 or values["num_root"] > 0:
        families.append("privilege_escalation")
        reasons.append("compromise or privilege signal")
    if values["num_file_creations"] > 0 or values["num_shells"] > 0 or values["num_access_files"] > 0:
        families.append("malware_like_activity")
        reasons.append("file, shell, or access-file behavior")
    if values["wrong_fragment"] > 0 or values["urgent"] > 0 or values["src_bytes"] > 100000 or values["dst_bytes"] > 100000:
        families.append("payload_or_exfiltration")
        reasons.append("fragment, urgent, or high byte volume")

    if risk_score < 0.55 and not families:
        return "normal", "close to learned normal profile"

    if not families:
        for item in model.get("top_indicators", [])[:4]:
            name = item["feature"]
            index = FEATURE_NAMES.index(name)
            value = features[index]
            normal_mean = float(item["normal_mean"])
            attack_mean = float(item["attack_mean"])
            if abs(value - attack_mean) < abs(value - normal_mean):
                direction = "high" if attack_mean > normal_mean else "low"
                reasons.append(f"{name} is {direction} versus normal profile")
        families.append("network_attack")

    return families[0], "; ".join(reasons[:4]) if reasons else "matches learned attack profile"


def summarize_dataset(path: Path, limit: int | None = None) -> dict[str, Any]:
    labels: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    flag_counts: Counter[str] = Counter()
    total_src_bytes = 0.0
    total_dst_bytes = 0.0
    rows = 0
    malformed = 0

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < len(FEATURE_NAMES) + 1:
                malformed += 1
                continue
            rows += 1
            labels[row[0].strip()] += 1
            protocol_counts[row[2].strip()] += 1
            service_counts[row[3].strip()] += 1
            flag_counts[row[4].strip()] += 1
            total_src_bytes += safe_float(row[5])
            total_dst_bytes += safe_float(row[6])
            if limit is not None and rows >= limit:
                break

    return {
        "path": relative_path(path),
        "rows": rows,
        "malformed_rows": malformed,
        "columns": len(FEATURE_NAMES) + 1,
        "size_mb": round(path.stat().st_size / (1024 * 1024), 2),
        "label_counts": dict(labels),
        "attack_share": round(labels["1"] / rows, 6) if rows else 0,
        "normal_share": round(labels["0"] / rows, 6) if rows else 0,
        "total_src_bytes": int(total_src_bytes),
        "total_dst_bytes": int(total_dst_bytes),
        "top_protocols": protocol_counts.most_common(5),
        "top_services": service_counts.most_common(8),
        "top_flags": flag_counts.most_common(8),
    }


def summarize_dataset_cached(path: Path) -> dict[str, Any]:
    cache_path = cached_json_path(path, "summary")
    cached = read_json(cache_path)
    if is_cache_current(path, cached):
        return cached["summary"]
    summary = summarize_dataset(path)
    write_json(
        cache_path,
        {
            "cached_at": utc_now(),
            "path": relative_path(path),
            "signature": file_signature(path),
            "summary": summary,
        },
    )
    return summary


def summarize_all_datasets() -> dict[str, Any]:
    return {"train": summarize_dataset_cached(TRAIN_CSV), "test": summarize_dataset_cached(TEST_CSV)}


def inspect_csv(path: Path, limit: int | None = 50000) -> dict[str, Any]:
    cache_path = cached_json_path(path, f"inspect-{limit or 'all'}")
    cached = read_json(cache_path)
    if limit is None and is_cache_current(path, cached):
        return cached["inspection"]

    rows = 0
    malformed = 0
    columns = 0
    first_row: list[str] | None = None
    header: list[str] | None = None
    label_counts: Counter[str] = Counter()
    column_counters: list[Counter[str]] = []

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        for raw_index, row in enumerate(reader):
            if not row:
                malformed += 1
                continue
            if first_row is None:
                first_row = row
                columns = len(row)
                header = row if likely_header(row) else None
                column_counters = [Counter() for _ in range(columns)]
                if header:
                    continue
            if columns and len(row) != columns:
                malformed += 1
            rows += 1
            if row:
                label_counts[row[0].strip()] += 1
            for index, value in enumerate(row[:columns]):
                if len(column_counters[index]) < 2000:
                    column_counters[index][value.strip()] += 1
            if limit is not None and rows >= limit:
                break

    field_names = header or [f"column_{index}" for index in range(columns)]
    top_values = []
    for index, counter in enumerate(column_counters[:20]):
        top_values.append(
            {
                "column": field_names[index] if index < len(field_names) else f"column_{index}",
                "top": counter.most_common(8),
            }
        )

    inspection = {
        "path": relative_path(path),
        "rows_scanned": rows,
        "scan_limit": limit,
        "columns": columns,
        "has_header": bool(header),
        "size_mb": round(path.stat().st_size / (1024 * 1024), 2),
        "malformed_rows": malformed,
        "label_counts_first_column": dict(label_counts),
        "top_values": top_values,
    }
    cache_artifact("index", inspection)
    if limit is None:
        write_json(
            cache_path,
            {
                "cached_at": utc_now(),
                "path": relative_path(path),
                "signature": file_signature(path),
                "inspection": inspection,
            },
        )
    return inspection


def analyze_csv(
    source: Path,
    *,
    limit: int | None = 5000,
    export: bool = True,
    model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_product_dirs()
    model = model or load_or_learn_model()
    analysis_id = f"scan-{compact_timestamp()}"
    export_csv_path = EXPORTS_DIR / f"traffic_analysis_{compact_timestamp()}.csv"
    export_json_path = export_csv_path.with_suffix(".json")

    total = 0
    malformed = 0
    actual_counts: Counter[str] = Counter()
    predicted_counts: Counter[str] = Counter()
    risk_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    flag_counts: Counter[str] = Counter()
    metrics = Counter()
    risk_sum = 0.0

    fieldnames = [
        "analysis_id",
        "analyzed_at",
        "source_file",
        "row_number",
        "actual_label",
        "actual_name",
        "predicted_label",
        "predicted_name",
        "risk_score",
        "confidence",
        "risk_level",
        "family",
        "reasons",
        *[f"{CSV_FEATURE_PREFIX}{name}" for name in FEATURE_NAMES],
    ]

    writer = None
    export_handle = None
    try:
        if export:
            export_handle = export_csv_path.open("w", encoding="utf-8", newline="")
            writer = csv.DictWriter(export_handle, fieldnames=fieldnames)
            writer.writeheader()

        with source.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            for row_number, row in enumerate(reader, start=1):
                if len(row) < len(FEATURE_NAMES) + 1:
                    malformed += 1
                    continue
                label = row[0].strip()
                features = [safe_float(value) for value in row[1 : len(FEATURE_NAMES) + 1]]
                result = score_row(model, features)
                total += 1
                actual_counts[label] += 1
                predicted_counts[result["predicted_label"]] += 1
                risk_counts[result["risk_level"]] += 1
                family_counts[result["family"]] += 1
                protocol_counts[row[2].strip()] += 1
                service_counts[row[3].strip()] += 1
                flag_counts[row[4].strip()] += 1
                risk_sum += float(result["risk_score"])

                if label in BINARY_LABELS:
                    actual_attack = label == "1"
                    predicted_attack = result["predicted_label"] == "1"
                    if actual_attack and predicted_attack:
                        metrics["tp"] += 1
                    elif actual_attack and not predicted_attack:
                        metrics["fn"] += 1
                    elif not actual_attack and predicted_attack:
                        metrics["fp"] += 1
                    else:
                        metrics["tn"] += 1

                if writer:
                    output_row = {
                        "analysis_id": analysis_id,
                        "analyzed_at": utc_now(),
                        "source_file": relative_path(source),
                        "row_number": row_number,
                        "actual_label": label,
                        "actual_name": BINARY_LABELS.get(label, "unknown"),
                        **result,
                    }
                    output_row["reasons"] = result["reasons"]
                    for index, name in enumerate(FEATURE_NAMES):
                        output_row[f"{CSV_FEATURE_PREFIX}{name}"] = features[index]
                    writer.writerow(output_row)

                if limit is not None and total >= limit:
                    break
    finally:
        if export_handle:
            export_handle.close()

    precision = metrics["tp"] / max(metrics["tp"] + metrics["fp"], 1)
    recall = metrics["tp"] / max(metrics["tp"] + metrics["fn"], 1)
    accuracy = (metrics["tp"] + metrics["tn"]) / max(sum(metrics.values()), 1)
    f1 = (2 * precision * recall) / max(precision + recall, 1e-12)
    summary = {
        "analysis_id": analysis_id,
        "created_at": utc_now(),
        "source_file": relative_path(source),
        "rows_analyzed": total,
        "malformed_rows": malformed,
        "limit": limit,
        "average_risk_score": round(risk_sum / total, 6) if total else 0,
        "actual_counts": dict(actual_counts),
        "predicted_counts": dict(predicted_counts),
        "risk_counts": dict(risk_counts),
        "family_counts": dict(family_counts),
        "top_protocols": protocol_counts.most_common(8),
        "top_services": service_counts.most_common(8),
        "top_flags": flag_counts.most_common(8),
        "metrics": {
            "accuracy": round(accuracy, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "tp": metrics["tp"],
            "tn": metrics["tn"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
        },
        "model_created_at": model.get("created_at"),
        "export_csv": relative_path(export_csv_path) if export else None,
        "export_json": relative_path(export_json_path) if export else None,
    }
    if export:
        write_json(export_json_path, summary)
    cache_artifact("scan", summary)
    return summary


def latest_export_summary() -> dict[str, Any] | None:
    if not EXPORTS_DIR.exists():
        return None
    summaries = sorted(EXPORTS_DIR.glob("traffic_analysis_*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not summaries:
        return None
    return read_json(summaries[0])


def list_reports(limit: int | None = 20) -> list[dict[str, Any]]:
    if not EXPORTS_DIR.exists():
        return []
    reports = []
    for path in sorted(EXPORTS_DIR.glob("*"), key=lambda item: item.stat().st_mtime, reverse=True):
        if not path.is_file():
            continue
        reports.append(
            {
                "name": path.name,
                "path": relative_path(path),
                "size_kb": round(path.stat().st_size / 1024, 2),
                "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
            }
        )
        if limit is not None and len(reports) >= limit:
            break
    return reports


def list_cache_artifacts(limit: int = 40) -> list[dict[str, Any]]:
    ensure_product_dirs()
    artifacts = []
    for path in sorted(COMMAND_CACHE_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        artifacts.append(
            {
                "name": path.name,
                "path": relative_path(path),
                "size_kb": round(path.stat().st_size / 1024, 2),
                "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
            }
        )
        if limit is not None and len(artifacts) >= limit:
            break
    return artifacts


def show_cache(json_output: bool = False, limit: int = 40) -> None:
    payload = {
        "cache_dir": relative_path(CACHE_DIR),
        "index_dir": relative_path(INDEX_DIR),
        "command_cache_dir": relative_path(COMMAND_CACHE_DIR),
        "artifacts": list_cache_artifacts(limit),
    }
    if json_output:
        print_json(payload)
        return
    section("IDS Sentinel Terminal Cache")
    print(f"Cache:   {payload['cache_dir']}")
    print(f"Indexes: {payload['index_dir']}")
    print(f"Runs:    {payload['command_cache_dir']}")
    if not payload["artifacts"]:
        print("No command cache artifacts yet.")
        return
    print()
    print(table(["Name", "Path", "Size KB", "Modified"], [
        [item["name"], item["path"], item["size_kb"], item["modified"]] for item in payload["artifacts"]
    ]))


def list_run_summaries(limit: int | None = 8) -> list[dict[str, Any]]:
    runs_dir = ROOT_DIR / "automation" / "runs"
    if not runs_dir.exists():
        return []
    rows = []
    for path in sorted(runs_dir.glob("*/summary.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        payload = read_json(path)
        if payload:
            rows.append(payload)
        if limit is not None and len(rows) >= limit:
            break
    return rows


def show_dataset_catalog(json_output: bool = False) -> None:
    payload = {
        "local_sources": [relative_path(path) for path in all_csv_sources(include_exports=False)],
        "external_catalog": EXTERNAL_DATASETS,
    }
    cache_artifact("datasets", payload)
    if json_output:
        print_json(payload)
        return
    section("Dataset Catalog")
    print(table(["ID", "Name", "Source", "Format"], [
        [item["id"], item["name"], item["source"], item["format"]] for item in EXTERNAL_DATASETS
    ]))
    print()
    print(table(["Local CSV", "Size MB"], [
        [relative_path(path), round(path.stat().st_size / (1024 * 1024), 2)] for path in all_csv_sources(include_exports=False)
    ]))


def import_csv(source: Path, name: str | None = None) -> Path:
    ensure_product_dirs()
    if not source.exists() or not source.is_file():
        raise ValueError(f"not a file: {source}")
    if source.suffix.lower() != ".csv":
        raise ValueError("only CSV imports are supported in IDS Sentinel Terminal")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name or source.name)
    if not safe_name.lower().endswith(".csv"):
        safe_name += ".csv"
    target = IMPORTS_DIR / safe_name
    if source.resolve() != target.resolve():
        shutil.copy2(source, target)
    inspect_csv(target, limit=None)
    cache_artifact("import", {"source": str(source), "target": relative_path(target), "bytes": target.stat().st_size})
    return target


def download_url(url: str, name: str | None = None, max_bytes: int = 2 * 1024 * 1024 * 1024) -> Path:
    ensure_product_dirs()
    parsed_name = name or Path(url.split("?", 1)[0]).name or f"download_{compact_timestamp()}"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", parsed_name)
    target = IMPORTS_DIR / safe_name
    try:
        with urllib.request.urlopen(url, timeout=60) as response, target.open("wb") as handle:
            copied = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > max_bytes:
                    raise RuntimeError("download exceeded the 2 GB safety limit")
                handle.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    cache_artifact("download", {"url": url, "path": relative_path(target), "bytes": target.stat().st_size})
    return target


def show_import(path: Path, json_output: bool = False) -> None:
    payload = {"imported_path": relative_path(path), "inspection": inspect_csv(path, limit=None)}
    if json_output:
        print_json(payload)
        return
    section("CSV Imported")
    print(f"Imported: {payload['imported_path']}")
    show_index(path, json_output=False)


def show_index(path: Path, json_output: bool = False, limit: int | None = 50000) -> None:
    payload = inspect_csv(path, limit=limit)
    if json_output:
        print_json(payload)
        return
    section("CSV Index")
    print(f"Path: {payload['path']}")
    print(f"Rows scanned: {payload['rows_scanned']:,} | columns: {payload['columns']} | size: {payload['size_mb']} MB")
    print(f"Header: {payload['has_header']} | malformed rows: {payload['malformed_rows']:,}")
    if payload["label_counts_first_column"]:
        print()
        print(table(["First Column Value", "Rows"], [
            [label, count] for label, count in sorted(payload["label_counts_first_column"].items(), key=lambda item: item[1], reverse=True)[:12]
        ]))
    print()
    print(table(["Column", "Top Values"], [
        [item["column"], ", ".join(f"{value}:{count}" for value, count in item["top"][:5])] for item in payload["top_values"][:12]
    ]))


def load_services() -> dict[int, str]:
    services: dict[int, str] = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",
        110: "pop3",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        1433: "ms-sql-s",
        3306: "mysql",
        3389: "ms-wbt-server",
        5432: "postgresql",
        6379: "redis",
        8080: "http-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }
    services_file = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "drivers" / "etc" / "services"
    if services_file.exists():
        with services_file.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2 or "/" not in parts[1]:
                    continue
                port_text, proto = parts[1].split("/", 1)
                if proto.lower() not in {"tcp", "udp"}:
                    continue
                try:
                    services.setdefault(int(port_text), parts[0])
                except ValueError:
                    continue
    return services


def parse_ports(text: str) -> list[int]:
    if text.lower() in {"common", "top"}:
        return COMMON_PROBE_PORTS
    ports: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if end < start:
                start, end = end, start
            for port in range(start, min(end, start + 127) + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
    if len(ports) > 128:
        raise ValueError("port list is capped at 128 ports per probe")
    return sorted(ports)


def split_host_port(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        host, port_text = value.rsplit(":", 1)
        return host.strip("[]"), int(port_text) if port_text.isdigit() else None
    if ":" in value and value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        return host, int(port_text) if port_text.isdigit() else None
    return value, None


def parse_netstat() -> list[dict[str, Any]]:
    try:
        completed = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15, check=False)
    except FileNotFoundError:
        return []
    rows = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] not in {"TCP", "UDP"}:
            continue
        proto = parts[0]
        if proto == "TCP" and len(parts) >= 5:
            local_host, local_port = split_host_port(parts[1])
            remote_host, remote_port = split_host_port(parts[2])
            rows.append(
                {
                    "proto": proto,
                    "local": parts[1],
                    "local_host": local_host,
                    "local_port": local_port,
                    "remote": parts[2],
                    "remote_host": remote_host,
                    "remote_port": remote_port,
                    "state": parts[3],
                    "pid": parts[4],
                }
            )
        elif proto == "UDP" and len(parts) >= 4:
            local_host, local_port = split_host_port(parts[1])
            rows.append(
                {
                    "proto": proto,
                    "local": parts[1],
                    "local_host": local_host,
                    "local_port": local_port,
                    "remote": parts[2],
                    "remote_host": "*",
                    "remote_port": None,
                    "state": "UDP",
                    "pid": parts[3],
                }
            )
    return rows


def show_netstat(json_output: bool = False, only_listening: bool = False, limit: int = 40) -> None:
    services = load_services()
    rows = parse_netstat()
    if only_listening:
        rows = [row for row in rows if row["state"] in {"LISTENING", "UDP"}]
    rows = sorted(rows, key=lambda item: (item.get("local_port") or 0, item["proto"], item["pid"]))
    payload = rows[:limit]
    cache_artifact("ports" if only_listening else "netstat", payload)
    if json_output:
        print_json(payload)
        return
    section("Network Connections")
    if not payload:
        print("No netstat rows found.")
        return
    print(table(["Proto", "Local", "Service", "Remote", "State", "PID"], [
        [
            row["proto"],
            row["local"],
            services.get(row.get("local_port") or -1, ""),
            row["remote"],
            row["state"],
            row["pid"],
        ]
        for row in payload
    ]))


def show_port(port: int, json_output: bool = False) -> None:
    services = load_services()
    payload = {
        "port": port,
        "service": services.get(port, "unknown"),
        "risk": COMMON_PORT_RISKS.get(port, "No specific built-in note. Validate whether this service should be exposed."),
        "local_matches": [row for row in parse_netstat() if row.get("local_port") == port],
    }
    cache_artifact("port", payload)
    if json_output:
        print_json(payload)
        return
    section(f"Port {port}")
    print(f"Service: {payload['service']}")
    print(f"Risk: {payload['risk']}")
    if payload["local_matches"]:
        print()
        print(table(["Proto", "Local", "Remote", "State", "PID"], [
            [row["proto"], row["local"], row["remote"], row["state"], row["pid"]] for row in payload["local_matches"]
        ]))


def probe_ports(host: str, ports: list[int], timeout_seconds: float = 0.2) -> list[dict[str, Any]]:
    results = []
    services = load_services()
    for port in ports:
        started = time.perf_counter()
        status = "closed"
        try:
            with socket.create_connection((host, port), timeout=timeout_seconds):
                status = "open"
        except (TimeoutError, OSError):
            status = "closed"
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        results.append({"host": host, "port": port, "service": services.get(port, ""), "status": status, "elapsed_ms": elapsed_ms})
    return results


def show_probe(host: str, ports_text: str, json_output: bool = False) -> None:
    ports = parse_ports(ports_text)
    payload = probe_ports(host, ports)
    cache_artifact("probe", payload)
    if json_output:
        print_json(payload)
        return
    section("Port Probe")
    print("Use only on systems and networks you own or are authorized to test.")
    print(table(["Host", "Port", "Service", "Status", "ms"], [
        [item["host"], item["port"], item["service"], item["status"], item["elapsed_ms"]] for item in payload
    ]))


def show_dns(host: str, json_output: bool = False) -> None:
    addresses: list[str] = []
    aliases: list[str] = []
    reverse: list[str] = []
    try:
        name, aliases, addresses = socket.gethostbyname_ex(host)
    except OSError as exc:
        payload = {"host": host, "error": str(exc)}
        if json_output:
            print_json(payload)
        else:
            print(f"DNS error: {exc}")
        return
    for address in addresses:
        try:
            reverse.append(socket.gethostbyaddr(address)[0])
        except OSError:
            pass
    payload = {"host": host, "canonical": name, "aliases": aliases, "addresses": addresses, "reverse": reverse}
    cache_artifact("dns", payload)
    if json_output:
        print_json(payload)
        return
    section("DNS")
    print_json(payload)


def show_processes(json_output: bool = False, limit: int = 40) -> None:
    rows: list[dict[str, Any]] = []
    try:
        completed = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True, text=True, timeout=15, check=False)
        reader = csv.DictReader(completed.stdout.splitlines())
        for row in reader:
            rows.append(row)
    except FileNotFoundError:
        rows = []
    cache_artifact("ps", rows[:limit])
    if json_output:
        print_json(rows[:limit])
        return
    section("Processes")
    if not rows:
        print("No process rows found.")
        return
    print(table(["Image", "PID", "Session", "Memory"], [
        [row.get("Image Name", ""), row.get("PID", ""), row.get("Session Name", ""), row.get("Mem Usage", "")]
        for row in rows[:limit]
    ]))


def hash_file(path: Path) -> dict[str, Any]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "path": relative_path(path),
        "size": path.stat().st_size,
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def show_hash(path: Path, json_output: bool = True) -> None:
    payload = hash_file(path)
    cache_artifact("hash", payload)
    if json_output:
        print_json(payload)
        return
    section("File Hashes")
    print(f"Path: {payload['path']}")
    print(f"Size: {payload['size']:,}")
    print(f"SHA256: {payload['sha256']}")
    print(f"SHA1:   {payload['sha1']}")
    print(f"MD5:    {payload['md5']}")


def scan_file(path: Path) -> dict[str, Any]:
    payload = hash_file(path)
    max_bytes = 5 * 1024 * 1024
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    lower = data.lower()
    ascii_text = lower.decode("latin-1", errors="ignore")
    findings = []
    if data.startswith(b"MZ"):
        findings.append("windows_pe_executable")
    if b"\x7fELF" in data[:4]:
        findings.append("linux_elf_executable")
    if b"PK\x03\x04" in data[:4]:
        findings.append("zip_or_office_container")
    for pattern in SUSPICIOUS_FILE_PATTERNS:
        if pattern in ascii_text:
            findings.append(f"suspicious_string:{pattern}")
    payload["findings"] = findings
    payload["triage"] = "suspicious" if findings else "no_builtin_findings"
    return payload


def show_file_scan(path: Path, json_output: bool = False) -> None:
    payload = scan_file(path)
    cache_artifact("filescan", payload)
    if json_output:
        print_json(payload)
        return
    section("File Triage")
    print(f"Path: {payload['path']}")
    print(f"Size: {payload['size']:,}")
    print(f"SHA256: {payload['sha256']}")
    print(f"SHA1:   {payload['sha1']}")
    print(f"MD5:    {payload['md5']}")
    print(f"Triage: {payload['triage']}")
    if payload["findings"]:
        print(table(["Finding"], [[item] for item in payload["findings"]]))


def read_iocs() -> list[dict[str, Any]]:
    payload = read_json(IOC_PATH, default={"iocs": []})
    return payload.get("iocs", [])


def write_iocs(iocs: list[dict[str, Any]]) -> None:
    write_json(IOC_PATH, {"updated_at": utc_now(), "iocs": iocs})


def classify_ioc(value: str, explicit_type: str | None = None) -> str:
    if explicit_type:
        return explicit_type
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.isdigit() and 1 <= int(value) <= 65535:
        return "port"
    lowered = value.lower()
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", lowered):
        return "hash"
    if "." in value and not any(char.isspace() for char in value):
        return "domain"
    return "string"


def add_ioc(value: str, ioc_type: str | None = None, note: str = "") -> dict[str, Any]:
    iocs = read_iocs()
    entry = {
        "id": hashlib.sha1(f"{value}|{utc_now()}".encode("utf-8")).hexdigest()[:10],
        "type": classify_ioc(value, ioc_type),
        "value": value,
        "note": note,
        "created_at": utc_now(),
    }
    iocs.append(entry)
    write_iocs(iocs)
    cache_artifact("ioc_add", entry)
    return entry


def remove_ioc(ioc_id: str) -> bool:
    iocs = read_iocs()
    kept = [item for item in iocs if item.get("id") != ioc_id]
    write_iocs(kept)
    removed = len(kept) != len(iocs)
    cache_artifact("ioc_remove", {"ioc_id": ioc_id, "removed": removed})
    return removed


def search_text_files(pattern: str, paths: list[Path], limit: int = 50) -> list[dict[str, Any]]:
    results = []
    lowered = pattern.lower()
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        try:
            if path.suffix.lower() in TEXT_SEARCH_SKIP_SUFFIXES:
                continue
            if path.stat().st_size > TEXT_SEARCH_MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if lowered in line.lower():
                        results.append({"path": relative_path(path), "line": line_number, "text": line.strip()[:240]})
                        if len(results) >= limit:
                            return results
        except OSError:
            continue
    return results


def show_hunt(pattern: str, path: Path | None = None, json_output: bool = False, limit: int = 50) -> None:
    paths = [path] if path else all_csv_sources(include_exports=True)
    payload = {"pattern": pattern, "matches": search_text_files(pattern, paths, limit=limit)}
    cache_artifact("hunt", payload)
    if json_output:
        print_json(payload)
        return
    section("Hunt")
    if not payload["matches"]:
        print("No matches.")
        return
    print(table(["Path", "Line", "Text"], [[item["path"], item["line"], item["text"]] for item in payload["matches"]]))


def show_ioc(args: list[str], json_output: bool = False) -> None:
    action = args[0].lower() if args else "list"
    if action == "list":
        payload = read_iocs()
        cache_artifact("ioc_list", payload)
        if json_output:
            print_json(payload)
            return
        section("IOCs")
        if not payload:
            print("No IOCs stored.")
            return
        print(table(["ID", "Type", "Value", "Note"], [[item["id"], item["type"], item["value"], item.get("note", "")] for item in payload]))
        return
    if action == "add":
        if len(args) < 2:
            raise ValueError("usage: ioc add <value> [type] [note]")
        value = args[1]
        ioc_type = args[2] if len(args) >= 3 and args[2] in {"ip", "domain", "hash", "port", "string", "malware"} else None
        note_start = 3 if ioc_type else 2
        payload = add_ioc(value, ioc_type, " ".join(args[note_start:]))
        if json_output:
            print_json(payload)
        else:
            print(f"Added IOC {payload['id']} ({payload['type']}): {payload['value']}")
        return
    if action in {"rm", "remove", "delete"}:
        if len(args) < 2:
            raise ValueError("usage: ioc remove <id>")
        removed = remove_ioc(args[1])
        print("removed" if removed else "not found")
        return
    if action == "hunt":
        iocs = read_iocs()
        matches = []
        for item in iocs:
            found = search_text_files(str(item["value"]), all_csv_sources(include_exports=True), limit=20)
            if found:
                matches.append({"ioc": item, "matches": found})
        cache_artifact("ioc_hunt", matches)
        if json_output:
            print_json(matches)
            return
        section("IOC Hunt")
        if not matches:
            print("No IOC matches.")
            return
        rows = []
        for bundle in matches:
            for match in bundle["matches"]:
                rows.append([bundle["ioc"]["value"], match["path"], match["line"], match["text"]])
        print(table(["IOC", "Path", "Line", "Text"], rows[:80]))
        return
    raise ValueError("ioc actions: list, add, remove, hunt")


def shell_path(path_text: str | None = None) -> Path:
    if not path_text:
        return Path(SHELL_STATE.get("cwd", ROOT_DIR))
    path = Path(path_text)
    if not path.is_absolute():
        path = Path(SHELL_STATE.get("cwd", ROOT_DIR)) / path
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT_DIR)
    except ValueError:
        raise ValueError("path must stay inside the IDS Sentinel home directory")
    return resolved


def shell_cd(path_text: str | None) -> None:
    path = shell_path(path_text or ".")
    if not path.exists() or not path.is_dir():
        raise ValueError(f"not a directory: {path_text}")
    SHELL_STATE["cwd"] = path
    print(relative_path(path) or ".")


def shell_ls(path_text: str | None = None, all_files: bool = False) -> None:
    path = shell_path(path_text or ".")
    if path.is_file():
        print(relative_path(path))
        return
    rows = []
    for child in sorted(path.iterdir(), key=lambda item: (item.is_file(), item.name.lower())):
        if not all_files and child.name.startswith("."):
            continue
        rows.append([
            child.name + ("/" if child.is_dir() else ""),
            "dir" if child.is_dir() else child.stat().st_size,
            datetime.fromtimestamp(child.stat().st_mtime).isoformat(timespec="seconds"),
        ])
    print(table(["Name", "Size", "Modified"], rows))


def shell_cat(path_text: str, limit_bytes: int = 1024 * 1024) -> None:
    path = shell_path(path_text)
    if not path.is_file():
        raise ValueError("cat requires a file")
    if path.stat().st_size > limit_bytes:
        raise ValueError("file is too large for cat; use head, tail, or grep")
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        print(handle.read())


def shell_head(path_text: str, lines: int = 20) -> None:
    path = shell_path(path_text)
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for index, line in enumerate(handle):
            if index >= lines:
                break
            print(line.rstrip())


def shell_tail(path_text: str, lines: int = 20) -> None:
    path = shell_path(path_text)
    buffer: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            buffer.append(line.rstrip())
            if len(buffer) > lines:
                buffer.pop(0)
    for line in buffer:
        print(line)


def shell_grep(pattern: str, path_text: str | None = None, limit: int = 50) -> None:
    path = shell_path(path_text or ".")
    paths = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
    matches = search_text_files(pattern, paths, limit=limit)
    if not matches:
        print("No matches.")
        return
    print(table(["Path", "Line", "Text"], [[item["path"], item["line"], item["text"]] for item in matches]))


def shell_find(pattern: str = "*", path_text: str | None = None, limit: int = 200) -> None:
    root = shell_path(path_text or ".")
    rows = []
    iterator = root.rglob("*") if root.is_dir() else [root]
    for item in iterator:
        if fnmatch.fnmatch(item.name.lower(), pattern.lower()):
            rows.append([relative_path(item), "dir" if item.is_dir() else item.stat().st_size])
            if len(rows) >= limit:
                break
    print(table(["Path", "Size"], rows))


def shell_wc(path_text: str) -> None:
    path = shell_path(path_text)
    lines = words = chars = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            lines += 1
            words += len(line.split())
            chars += len(line)
    print(table(["Lines", "Words", "Chars", "Path"], [[lines, words, chars, relative_path(path)]]))


def shell_du(path_text: str | None = None) -> None:
    path = shell_path(path_text or ".")
    if path.is_file():
        size = path.stat().st_size
    else:
        size = sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
    print(table(["Path", "Bytes", "MB"], [[relative_path(path) or ".", size, round(size / (1024 * 1024), 2)]]))


def shell_stat(path_text: str) -> None:
    path = shell_path(path_text)
    stat = path.stat()
    print_json(
        {
            "path": relative_path(path),
            "type": "directory" if path.is_dir() else "file",
            "bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(timespec="seconds"),
        }
    )


def show_status(json_output: bool = False) -> None:
    payload = {
        "installation": {
            "version": __version__,
            "runtime_mode": RUNTIME_MODE,
            "home_dir": str(ROOT_DIR),
            "env_override": bool(ENV_ROOT),
        },
        "datasets": summarize_all_datasets(),
        "model": read_json(MODEL_PATH),
        "latest_export": latest_export_summary(),
        "recent_runs": list_run_summaries(),
    }
    cache_artifact("status", payload)
    if json_output:
        print_json(payload)
        return

    section("IDS Sentinel Terminal Status")
    print(
        f"Version: {payload['installation']['version']} | mode: {payload['installation']['runtime_mode']} | "
        f"home: {payload['installation']['home_dir']}"
    )
    print()
    dataset_rows = []
    for name, item in payload["datasets"].items():
        dataset_rows.append(
            [
                name,
                item["path"],
                item["rows"],
                f"{item['size_mb']} MB",
                item["label_counts"].get("0", 0),
                item["label_counts"].get("1", 0),
                percent(item["label_counts"].get("1", 0), item["rows"]),
            ]
        )
    print(table(["Set", "Path", "Rows", "Size", "Normal", "Attack", "Attack Share"], dataset_rows))

    section("Self-Learning Model")
    model = payload["model"]
    if not model:
        print("No model yet. Run: learn")
    else:
        print(f"Model: {model['model_type']} | rows learned: {model['total_rows']:,} | created: {model['created_at']}")
        print(table(["Indicator", "Separation", "Normal Mean", "Attack Mean"], [
            [item["feature"], item["separation"], item["normal_mean"], item["attack_mean"]]
            for item in model.get("top_indicators", [])[:6]
        ]))

    latest = payload["latest_export"]
    section("Latest Downloadable Analysis")
    if latest:
        print(f"CSV:  {latest['export_csv']}")
        print(f"JSON: {latest['export_json']}")
        print(f"Rows: {latest['rows_analyzed']:,} | average risk: {latest['average_risk_score']:.4f}")
    else:
        print("No analysis export yet. Run: scan")


def show_traffic(json_output: bool = False) -> None:
    payload = summarize_all_datasets()
    cache_artifact("traffic", payload)
    if json_output:
        print_json(payload)
        return

    section("Traffic Data")
    rows = []
    for name, item in payload.items():
        rows.append(
            [
                name,
                item["rows"],
                f"{item['size_mb']} MB",
                item["total_src_bytes"],
                item["total_dst_bytes"],
                ", ".join(f"{value}:{count}" for value, count in item["top_protocols"][:3]),
            ]
        )
    print(table(["Set", "Rows", "Size", "Source Bytes", "Dest Bytes", "Top Encoded Protocols"], rows))

    section("Top Encoded Services And Flags")
    rows = []
    for name, item in payload.items():
        rows.append(
            [
                name,
                ", ".join(f"{value}:{count}" for value, count in item["top_services"][:5]),
                ", ".join(f"{value}:{count}" for value, count in item["top_flags"][:5]),
            ]
        )
    print(table(["Set", "Services", "Flags"], rows))
    print("\nProtocol, service, and flag values are encoded IDs in these CSV files.")


def show_attacks(json_output: bool = False) -> None:
    datasets = summarize_all_datasets()
    model = read_json(MODEL_PATH)
    payload = {"datasets": datasets, "model_indicators": model.get("top_indicators", []) if model else []}
    cache_artifact("attacks", payload)
    if json_output:
        print_json(payload)
        return

    section("Attack Distribution")
    rows = []
    for name, item in datasets.items():
        total = item["rows"]
        rows.append([name, "normal", item["label_counts"].get("0", 0), percent(item["label_counts"].get("0", 0), total)])
        rows.append([name, "attack", item["label_counts"].get("1", 0), percent(item["label_counts"].get("1", 0), total)])
    print(table(["Set", "Label", "Rows", "Share"], rows))

    section("Learned Attack Indicators")
    if not model:
        print("No learned model yet. Run: learn")
        return
    print(table(["Feature", "Separation", "Normal Mean", "Attack Mean"], [
        [item["feature"], item["separation"], item["normal_mean"], item["attack_mean"]]
        for item in model.get("top_indicators", [])[:10]
    ]))


def show_malware(json_output: bool = False, limit: int = 5000) -> None:
    model = load_or_learn_model()
    summary = analyze_csv(TEST_CSV, limit=limit, export=False, model=model)
    malware_like = summary["family_counts"].get("malware_like_activity", 0)
    privilege = summary["family_counts"].get("privilege_escalation", 0)
    payload = {
        "note": "The bundled CSVs have binary normal/attack labels, not named malware-family labels. These are behavior indicators inferred from IDS features.",
        "rows_analyzed": summary["rows_analyzed"],
        "malware_like_activity": malware_like,
        "privilege_escalation": privilege,
        "family_counts": summary["family_counts"],
    }
    cache_artifact("malware", payload)
    if json_output:
        print_json(payload)
        return

    section("Malware-Like Behavior")
    print(payload["note"])
    print(table(["Indicator", "Rows", "Share"], [
        ["malware_like_activity", malware_like, percent(malware_like, summary["rows_analyzed"])],
        ["privilege_escalation", privilege, percent(privilege, summary["rows_analyzed"])],
    ]))
    print(table(["Family", "Rows"], [[name, count] for name, count in sorted(summary["family_counts"].items())]))


def show_learn(model: dict[str, Any], json_output: bool = False) -> None:
    if json_output:
        print_json(model)
        return
    section("Self-Learning Complete")
    print(f"Model: {relative_path(MODEL_PATH)}")
    print(f"Rows learned: {model['total_rows']:,}")
    print(f"Created: {model['created_at']}")
    print(table(["Source", "Rows", "Labels"], [
        [item["path"], item["rows_used"], ", ".join(f"{label}:{count}" for label, count in item["label_counts"].items())]
        for item in model["sources"]
    ]))
    print()
    print(table(["Top Indicator", "Separation", "Normal Mean", "Attack Mean"], [
        [item["feature"], item["separation"], item["normal_mean"], item["attack_mean"]]
        for item in model["top_indicators"][:8]
    ]))


def show_scan(summary: dict[str, Any], json_output: bool = False) -> None:
    if json_output:
        print_json(summary)
        return
    section("Traffic Analysis")
    print(f"Source: {summary['source_file']}")
    print(f"Rows analyzed: {summary['rows_analyzed']:,}")
    print(f"Average risk: {summary['average_risk_score']:.4f}")
    print(table(["Prediction", "Rows", "Share"], [
        [BINARY_LABELS.get(label, label), count, percent(count, summary["rows_analyzed"])]
        for label, count in sorted(summary["predicted_counts"].items())
    ]))
    print(table(["Risk", "Rows"], [[name, count] for name, count in sorted(summary["risk_counts"].items())]))
    print(table(["Family", "Rows"], [[name, count] for name, count in sorted(summary["family_counts"].items())]))
    print()
    print(table(["Accuracy", "Precision", "Recall", "F1", "TP", "TN", "FP", "FN"], [[
        summary["metrics"]["accuracy"],
        summary["metrics"]["precision"],
        summary["metrics"]["recall"],
        summary["metrics"]["f1"],
        summary["metrics"]["tp"],
        summary["metrics"]["tn"],
        summary["metrics"]["fp"],
        summary["metrics"]["fn"],
    ]]))
    if summary.get("export_csv"):
        print()
        print(f"Downloadable CSV:  {summary['export_csv']}")
        print(f"Summary JSON:       {summary['export_json']}")


def show_reports(json_output: bool = False, limit: int | None = 20) -> None:
    reports = list_reports(limit)
    cache_artifact("reports", reports)
    if json_output:
        print_json(reports)
        return
    section("Downloadable Reports")
    if not reports:
        print("No product reports yet. Run: scan")
        return
    print(table(["Name", "Path", "Size KB", "Modified"], [
        [item["name"], item["path"], item["size_kb"], item["modified"]] for item in reports
    ]))


def show_runs(json_output: bool = False, limit: int | None = 10) -> None:
    runs = list_run_summaries(limit)
    cache_artifact("runs", runs)
    if json_output:
        print_json(runs)
        return
    section("ML Training Runs")
    if not runs:
        print("No training runs found.")
        return
    rows = []
    for run in runs:
        best = (run.get("results") or [{}])[0]
        metrics = best.get("metrics", {})
        rows.append(
            [
                run.get("run_id", "n/a"),
                run.get("kind", "n/a"),
                best.get("label", "n/a"),
                metrics.get("accuracy", 0),
                metrics.get("f1", 0),
            ]
        )
    print(table(["Run", "Kind", "Best Model", "Accuracy", "F1"], rows))


def print_shell_help() -> None:
    section("Commands")
    print(table(["Command", "Action"], [
        ["status", "product dashboard: datasets, model, latest export"],
        ["traffic", "summarize traffic volumes, services, protocols, flags"],
        ["attacks", "attack distribution and learned attack indicators"],
        ["malware [limit]", "show malware-like and privilege behavior indicators"],
        ["learn [full|quick]", "build/update the self-learning profile"],
        ["scan [path] [limit|all]", "analyze traffic and write downloadable CSV/JSON"],
        ["export [path] [limit|all]", "same as scan; defaults to all rows"],
        ["datasets", "show local and external IDS dataset catalog"],
        ["import <csv> [name]", "copy a CSV into automation/product/imports and index it"],
        ["download <url> [name]", "download a public dataset/file into imports"],
        ["index [csv] [limit|all]", "inspect columns, labels, and top values"],
        ["hunt <term> [path] [limit]", "search datasets, imports, and exported reports"],
        ["ioc list|add|remove|hunt", "store and hunt indicators of compromise"],
        ["ports [limit]", "show listening local ports and services"],
        ["netstat [limit]", "show local network connections"],
        ["port <number>", "explain a port and show local matches"],
        ["probe <host> <ports>", "authorized TCP connect probe, e.g. probe 127.0.0.1 22,80,443"],
        ["dns <host>", "resolve DNS and reverse names"],
        ["ps [limit]", "list local processes"],
        ["hash <file>", "calculate SHA256/SHA1/MD5"],
        ["filescan <file>", "hash and check built-in suspicious file strings"],
        ["pwd | cd | ls", "basic project filesystem navigation"],
        ["cat | head | tail | grep", "text inspection commands"],
        ["find | wc | du | stat", "file discovery and measurement commands"],
        ["cache [limit]", "list cached command artifacts"],
        ["reports [limit]", "list downloadable CSV/JSON reports"],
        ["runs [limit]", "list previous ML training runs"],
        ["clear", "clear the terminal"],
        ["exit", "quit"],
    ]))


def parse_limit(value: str | None, default: int | None) -> int | None:
    if value is None:
        return default
    if value.lower() == "all":
        return None
    parsed = int(value)
    if parsed < 0:
        raise ValueError("limit must be zero or greater")
    return parsed


def command_shell() -> None:
    ensure_product_dirs()
    print("IDS Sentinel Terminal. Type 'help' for commands, 'exit' to quit.")
    while True:
        try:
            raw = input("ids-sentinel> ").strip()
        except EOFError:
            print()
            return
        if not raw:
            continue
        try:
            if run_shell_command(raw):
                return
        except Exception as exc:
            print(f"error: {exc}")


def split_shell_command(raw: str) -> list[str]:
    if os.name == "nt":
        raw = raw.replace("\\", "/")
    return shlex.split(raw)


def run_shell_command(raw: str) -> bool:
    SHELL_STATE["history"].append(raw)
    parts = split_shell_command(raw)
    if not parts:
        return False
    command, *args = parts
    command = command.lower()

    if command in {"exit", "quit", "q"}:
        return True
    if command == "help":
        print_shell_help()
    elif command == "clear":
        os.system("cls" if os.name == "nt" else "clear")
    elif command == "history":
        print(table(["#", "Command"], [[index + 1, value] for index, value in enumerate(SHELL_STATE["history"][-50:])]))
    elif command == "pwd":
        print(relative_path(Path(SHELL_STATE.get("cwd", ROOT_DIR))) or ".")
    elif command == "cd":
        shell_cd(args[0] if args else ".")
    elif command == "ls":
        all_files = "-a" in args
        path_args = [arg for arg in args if arg != "-a"]
        shell_ls(path_args[0] if path_args else ".", all_files=all_files)
    elif command == "cat":
        if not args:
            print("usage: cat <file>")
        else:
            shell_cat(args[0])
    elif command == "head":
        if not args:
            print("usage: head <file> [lines]")
        else:
            shell_head(args[0], int(args[1]) if len(args) > 1 else 20)
    elif command == "tail":
        if not args:
            print("usage: tail <file> [lines]")
        else:
            shell_tail(args[0], int(args[1]) if len(args) > 1 else 20)
    elif command == "grep":
        if not args:
            print("usage: grep <pattern> [path] [limit]")
        else:
            shell_grep(args[0], args[1] if len(args) > 1 else ".", int(args[2]) if len(args) > 2 else 50)
    elif command == "find":
        shell_find(args[0] if args else "*", args[1] if len(args) > 1 else ".", int(args[2]) if len(args) > 2 else 200)
    elif command == "wc":
        if not args:
            print("usage: wc <file>")
        else:
            shell_wc(args[0])
    elif command == "du":
        shell_du(args[0] if args else ".")
    elif command == "stat":
        if not args:
            print("usage: stat <path>")
        else:
            shell_stat(args[0])
    elif command in {"status", "overview", "dashboard"}:
        show_status()
    elif command in {"traffic", "data"}:
        show_traffic()
    elif command in {"attack", "attacks"}:
        show_attacks()
    elif command in {"malware", "malwares"}:
        show_malware(limit=parse_limit(args[0], 5000) if args else 5000)
    elif command == "learn":
        mode = args[0].lower() if args else "full"
        limit = 20000 if mode == "quick" else None
        show_learn(learn_model(limit=limit, include_generated=True))
    elif command in {"scan", "analyze"}:
        path = resolve_readable_path(args[0] if args else None, default=TEST_CSV, base=Path(SHELL_STATE.get("cwd", ROOT_DIR)))
        limit = parse_limit(args[1], 5000) if len(args) > 1 else 5000
        show_scan(analyze_csv(path, limit=limit, export=True))
    elif command == "export":
        path = resolve_readable_path(args[0] if args else None, default=TEST_CSV, base=Path(SHELL_STATE.get("cwd", ROOT_DIR)))
        limit = parse_limit(args[1], None) if len(args) > 1 else None
        show_scan(analyze_csv(path, limit=limit, export=True))
    elif command in {"datasets", "catalog"}:
        show_dataset_catalog()
    elif command == "import":
        if not args:
            print("usage: import <csv-path> [name]")
        else:
            show_import(import_csv(resolve_readable_path(args[0], base=Path(SHELL_STATE.get("cwd", ROOT_DIR))), args[1] if len(args) > 1 else None))
    elif command == "download":
        if not args:
            print("usage: download <url> [name]")
        else:
            downloaded = download_url(args[0], args[1] if len(args) > 1 else None)
            print(f"Downloaded: {relative_path(downloaded)}")
    elif command == "index":
        path = resolve_readable_path(args[0] if args else None, default=TEST_CSV, base=Path(SHELL_STATE.get("cwd", ROOT_DIR)))
        limit = parse_limit(args[1], 50000) if len(args) > 1 else 50000
        show_index(path, limit=limit)
    elif command == "hunt":
        if not args:
            print("usage: hunt <term> [path] [limit]")
        else:
            show_hunt(args[0], resolve_readable_path(args[1], base=Path(SHELL_STATE.get("cwd", ROOT_DIR))) if len(args) > 1 else None, limit=parse_limit(args[2], 50) if len(args) > 2 else 50)
    elif command == "ioc":
        show_ioc(args)
    elif command in {"ports", "listeners"}:
        show_netstat(only_listening=True, limit=parse_limit(args[0], 40) if args else 40)
    elif command in {"netstat", "connections"}:
        show_netstat(only_listening=False, limit=parse_limit(args[0], 40) if args else 40)
    elif command == "port":
        if not args:
            print("usage: port <number>")
        else:
            show_port(int(args[0]))
    elif command == "probe":
        if len(args) < 2:
            print("usage: probe <host> <ports>")
        else:
            show_probe(args[0], args[1])
    elif command == "dns":
        if not args:
            print("usage: dns <host>")
        else:
            show_dns(args[0])
    elif command == "ps":
        show_processes(limit=parse_limit(args[0], 40) if args else 40)
    elif command == "hash":
        if not args:
            print("usage: hash <file>")
        else:
            show_hash(resolve_readable_path(args[0], base=Path(SHELL_STATE.get("cwd", ROOT_DIR))), json_output=False)
    elif command in {"filescan", "scanfile"}:
        if not args:
            print("usage: filescan <file>")
        else:
            show_file_scan(resolve_readable_path(args[0], base=Path(SHELL_STATE.get("cwd", ROOT_DIR))))
    elif command in {"reports", "downloads"}:
        show_reports(limit=parse_limit(args[0], 20) if args else 20)
    elif command == "cache":
        show_cache(limit=parse_limit(args[0], 40) if args else 40)
    elif command == "runs":
        show_runs(limit=parse_limit(args[0], 10) if args else 10)
    else:
        print(f"Unknown command: {command}. Type 'help'.")
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IDS Sentinel Terminal for defensive CSV traffic analysis and local triage.")
    parser.add_argument("--json", action="store_true", help="Print JSON for commands that support it.")
    parser.add_argument("--version", action="version", version=f"IDS Sentinel Terminal {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("shell", help="Open IDS Sentinel Terminal interactive mode.")
    subparsers.add_parser("gui", help="Open the graphical product console.")
    subparsers.add_parser("status", help="Show product status.")
    subparsers.add_parser("traffic", help="Show traffic data.")
    subparsers.add_parser("attacks", help="Show attacks and learned indicators.")
    subparsers.add_parser("datasets", help="Show local and external IDS dataset catalog.")

    malware_parser = subparsers.add_parser("malware", help="Show malware-like behavior indicators.")
    malware_parser.add_argument("--limit", type=int, default=5000)

    learn_parser = subparsers.add_parser("learn", help="Build/update the self-learning model.")
    learn_parser.add_argument("--quick", action="store_true", help="Use a 20,000-row sample instead of all rows.")
    learn_parser.add_argument("--full", action="store_true", help="Use all source rows. This is the default.")
    learn_parser.add_argument("--include-test", action="store_true", help="Also learn from kddtest.csv labels.")
    learn_parser.add_argument("--skip-generated", action="store_true", help="Do not learn from terminal-generated CSV exports.")

    scan_parser = subparsers.add_parser("scan", help="Analyze a CSV and export CSV/JSON results.")
    scan_parser.add_argument("path", nargs="?", default=None)
    scan_parser.add_argument("--limit", type=int, default=5000)
    scan_parser.add_argument("--all", action="store_true", help="Analyze all rows.")
    scan_parser.add_argument("--no-export", action="store_true", help="Only print summary; do not write downloadable files.")

    export_parser = subparsers.add_parser("export", help="Analyze and export all rows by default.")
    export_parser.add_argument("path", nargs="?", default=None)
    export_parser.add_argument("--limit", type=int)

    import_parser = subparsers.add_parser("import", help="Copy a CSV into product imports and index it.")
    import_parser.add_argument("path")
    import_parser.add_argument("--name")

    download_parser = subparsers.add_parser("download", help="Download a public URL into product imports.")
    download_parser.add_argument("url")
    download_parser.add_argument("--name")

    index_parser = subparsers.add_parser("index", help="Inspect a CSV file.")
    index_parser.add_argument("path", nargs="?", default=None)
    index_parser.add_argument("--limit", type=int, default=50000)
    index_parser.add_argument("--all", action="store_true")

    hunt_parser = subparsers.add_parser("hunt", help="Search datasets, imports, and reports for text.")
    hunt_parser.add_argument("pattern")
    hunt_parser.add_argument("--path")
    hunt_parser.add_argument("--limit", type=int, default=50)

    ioc_parser = subparsers.add_parser("ioc", help="Manage and hunt indicators of compromise.")
    ioc_parser.add_argument("ioc_args", nargs="*")

    netstat_parser = subparsers.add_parser("netstat", help="Show local network connections.")
    netstat_parser.add_argument("--limit", type=int, default=40)
    netstat_parser.add_argument("--listening", action="store_true")

    ports_parser = subparsers.add_parser("ports", help="Show local listening ports.")
    ports_parser.add_argument("--limit", type=int, default=40)

    port_parser = subparsers.add_parser("port", help="Explain a port and show local matches.")
    port_parser.add_argument("number", type=int)

    probe_parser = subparsers.add_parser("probe", help="Authorized TCP connect probe.")
    probe_parser.add_argument("host")
    probe_parser.add_argument("ports")

    dns_parser = subparsers.add_parser("dns", help="Resolve a host.")
    dns_parser.add_argument("host")

    ps_parser = subparsers.add_parser("ps", help="List local processes.")
    ps_parser.add_argument("--limit", type=int, default=40)

    hash_parser = subparsers.add_parser("hash", help="Hash a file.")
    hash_parser.add_argument("path")

    filescan_parser = subparsers.add_parser("filescan", help="Hash and triage a file.")
    filescan_parser.add_argument("path")

    reports_parser = subparsers.add_parser("reports", help="List generated downloadable reports.")
    reports_parser.add_argument("--limit", type=int, default=20)

    runs_parser = subparsers.add_parser("runs", help="List existing ML training runs.")
    runs_parser.add_argument("--limit", type=int, default=10)

    cache_parser = subparsers.add_parser("cache", help="List cached command artifacts.")
    cache_parser.add_argument("--limit", type=int, default=40)
    return parser


def normalize_global_args(argv: list[str] | None) -> list[str] | None:
    if argv is None:
        return None
    normalized = list(argv)
    if "--json" in normalized:
        normalized = [value for value in normalized if value != "--json"]
        normalized.insert(0, "--json")
    return normalized


def main(argv: list[str] | None = None) -> int:
    ensure_product_dirs()
    parser = build_parser()
    args = parser.parse_args(normalize_global_args(argv))

    try:
        if args.command is None or args.command == "shell":
            command_shell()
        elif args.command == "gui":
            from .product_gui import main as gui_main

            return gui_main([])
        elif args.command == "status":
            show_status(args.json)
        elif args.command == "traffic":
            show_traffic(args.json)
        elif args.command == "attacks":
            show_attacks(args.json)
        elif args.command == "datasets":
            show_dataset_catalog(args.json)
        elif args.command == "malware":
            show_malware(args.json, args.limit)
        elif args.command == "learn":
            model = learn_model(
                limit=20000 if args.quick else None,
                include_generated=not args.skip_generated,
                include_test=args.include_test,
            )
            show_learn(model, args.json)
        elif args.command == "scan":
            source = resolve_readable_path(args.path, default=TEST_CSV)
            summary = analyze_csv(source, limit=None if args.all else args.limit, export=not args.no_export)
            show_scan(summary, args.json)
        elif args.command == "export":
            source = resolve_readable_path(args.path, default=TEST_CSV)
            summary = analyze_csv(source, limit=args.limit, export=True)
            show_scan(summary, args.json)
        elif args.command == "import":
            show_import(import_csv(resolve_readable_path(args.path), args.name), args.json)
        elif args.command == "download":
            downloaded = download_url(args.url, args.name)
            payload = {"downloaded": relative_path(downloaded)}
            print_json(payload) if args.json else print(f"Downloaded: {payload['downloaded']}")
        elif args.command == "index":
            show_index(resolve_readable_path(args.path, default=TEST_CSV), args.json, limit=None if args.all else args.limit)
        elif args.command == "hunt":
            show_hunt(args.pattern, resolve_readable_path(args.path) if args.path else None, args.json, args.limit)
        elif args.command == "ioc":
            show_ioc(args.ioc_args, args.json)
        elif args.command == "netstat":
            show_netstat(args.json, only_listening=args.listening, limit=args.limit)
        elif args.command == "ports":
            show_netstat(args.json, only_listening=True, limit=args.limit)
        elif args.command == "port":
            show_port(args.number, args.json)
        elif args.command == "probe":
            show_probe(args.host, args.ports, args.json)
        elif args.command == "dns":
            show_dns(args.host, args.json)
        elif args.command == "ps":
            show_processes(args.json, args.limit)
        elif args.command == "hash":
            show_hash(resolve_readable_path(args.path), args.json)
        elif args.command == "filescan":
            show_file_scan(resolve_readable_path(args.path), args.json)
        elif args.command == "reports":
            show_reports(args.json, args.limit)
        elif args.command == "runs":
            show_runs(args.json, args.limit)
        elif args.command == "cache":
            show_cache(args.json, args.limit)
        else:
            parser.error(f"Unknown command: {args.command}")
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
