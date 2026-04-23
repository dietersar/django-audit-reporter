#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import shutil
import smtplib
import socket
import subprocess
import sys
import urllib.request
from collections import Counter
from datetime import datetime
from email.message import EmailMessage
from html import escape
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Django dependency audit")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    parser.add_argument("--dry-run", action="store_true", help="Generate reports but do not send email")
    return parser.parse_args()


def load_config(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_config(config):
    errors = []

    if not isinstance(config, dict):
        return ["Config root must be a JSON object."]

    mail = config.get("mail")
    if not isinstance(mail, dict):
        errors.append("Missing 'mail' section.")
    else:
        for key in ("to", "from_template", "subject_template", "smtp_host", "smtp_port"):
            if key not in mail or str(mail[key]).strip() == "":
                errors.append(f"mail.{key} is missing or empty")

    reports = config.get("reports")
    if not isinstance(reports, dict):
        errors.append("Missing 'reports' section.")
    elif not reports.get("report_dir"):
        errors.append("reports.report_dir is missing or empty")

    projects = config.get("projects")
    if not isinstance(projects, list) or not projects:
        errors.append("Config must contain at least one project in 'projects'.")
    else:
        for idx, project in enumerate(projects, start=1):
            prefix = f"projects[{idx}]"
            if not isinstance(project, dict):
                errors.append(f"{prefix} must be an object")
                continue
            for key in ("name", "dir"):
                if key not in project or not str(project[key]).strip():
                    errors.append(f"{prefix}.{key} is missing or empty")
            if "requirements" not in project:
                errors.append(f"{prefix}.requirements is missing")
            elif not isinstance(project["requirements"], list):
                errors.append(f"{prefix}.requirements must be a list")

    return errors


ARGS = parse_args()
CONFIG_PATH = Path(ARGS.config).resolve()
CONFIG = load_config(CONFIG_PATH)
CONFIG_ERRORS = validate_config(CONFIG)
if CONFIG_ERRORS:
    print("Configuration errors found:", file=sys.stderr)
    for err in CONFIG_ERRORS:
        print(f" - {err}", file=sys.stderr)
    sys.exit(2)

BASE_DIR = Path(os.environ.get("BASE_DIR", "/home/dieter/djangodev"))
SCRIPT_DIR = CONFIG_PATH.parent
AUDIT_VENV = Path(os.environ.get("AUDIT_VENV", str(SCRIPT_DIR / ".audit-venv")))
AUDIT_PYTHON = Path(os.environ.get("AUDIT_PYTHON", str(AUDIT_VENV / "bin" / "python")))

NOW = datetime.now()
HOSTNAME_FQDN = socket.getfqdn() or socket.gethostname()

REPORT_DIR = Path(CONFIG["reports"]["report_dir"])
if not REPORT_DIR.is_absolute():
    REPORT_DIR = (BASE_DIR / REPORT_DIR).resolve()
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MAIL_TO = CONFIG["mail"]["to"]
MAIL_FROM = CONFIG["mail"]["from_template"].format(hostname=HOSTNAME_FQDN)
SUBJECT = CONFIG["mail"]["subject_template"].format(hostname=HOSTNAME_FQDN)
SMTP_HOST = CONFIG["mail"]["smtp_host"]
SMTP_PORT = int(CONFIG["mail"]["smtp_port"])

TEXT_REPORT = REPORT_DIR / f"django_audit_{NOW.strftime('%Y%m%d_%H%M%S')}.txt"
HTML_REPORT = REPORT_DIR / f"django_audit_{NOW.strftime('%Y%m%d_%H%M%S')}.html"

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "MODERATE": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}

SEVERITY_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "MODERATE": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#0f766e",
    "UNKNOWN": "#475569",
}

SEVERITY_BG = {
    "CRITICAL": "#fee2e2",
    "HIGH": "#fee2e2",
    "MEDIUM": "#fef3c7",
    "MODERATE": "#fef9c3",
    "LOW": "#dbeafe",
    "INFO": "#ccfbf1",
    "UNKNOWN": "#e2e8f0",
}


def resolve_path(value):
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    return (BASE_DIR / path).resolve()


def load_projects():
    projects = []
    for item in CONFIG.get("projects", []):
        project = {
            "name": item["name"],
            "dir": resolve_path(item["dir"]),
            "requirements": [resolve_path(x) for x in item.get("requirements", [])],
            "django_dir": resolve_path(item.get("django_dir", item["dir"])),
        }
        if item.get("frontend_dir"):
            project["frontend_dir"] = resolve_path(item["frontend_dir"])
        projects.append(project)
    return projects


PROJECTS = load_projects()


def validate_project_paths(projects):
    warnings = []
    for project in projects:
        if not project["dir"].exists():
            warnings.append(f"Project directory does not exist: {project['dir']}")
        if not project["django_dir"].exists():
            warnings.append(f"Django directory does not exist: {project['django_dir']}")
        for req in project["requirements"]:
            if not req.exists():
                warnings.append(f"Requirements file does not exist: {req}")
        if project.get("frontend_dir") and not Path(project["frontend_dir"]).exists():
            warnings.append(f"Frontend directory does not exist: {project['frontend_dir']}")
    return warnings


for warning in validate_project_paths(PROJECTS):
    print(f"Warning: {warning}", file=sys.stderr)


def build_runtime_env(extra_path_entries=None):
    env = os.environ.copy()
    path_parts = []

    for item in (extra_path_entries or []):
        if item:
            path_parts.append(str(item))

    current_path = env.get("PATH", "")
    if current_path:
        path_parts.append(current_path)

    env["PATH"] = ":".join([p for p in path_parts if p])
    return env


def run_command(cmd, cwd=None, timeout=300, env=None):
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return {
            "cmd": " ".join(shlex.quote(str(x)) for x in cmd),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except Exception as exc:
        return {
            "cmd": " ".join(shlex.quote(str(x)) for x in cmd),
            "returncode": 999,
            "stdout": "",
            "stderr": str(exc),
        }


def ensure_pip_audit():
    res = run_command([str(AUDIT_PYTHON), "-m", "pip_audit", "--version"])
    if res["returncode"] != 0:
        print("pip-audit is not installed in the audit virtualenv.", file=sys.stderr)
        print(f"Expected interpreter: {AUDIT_PYTHON}", file=sys.stderr)
        sys.exit(3)


def detect_project_python(project_dir: Path) -> Path:
    venv_python = project_dir / ".venv" / "bin" / "python"
    if venv_python.exists() and os.access(venv_python, os.X_OK):
        return venv_python
    return Path(sys.executable)


def detect_site_packages(project_dir: Path):
    lib_dir = project_dir / ".venv" / "lib"
    if not lib_dir.exists():
        return None
    for child in sorted(lib_dir.glob("python*")):
        site_packages = child / "site-packages"
        if site_packages.is_dir():
            return site_packages
    return None


def parse_pip_audit_json(raw: str):
    try:
        data = json.loads(raw)
    except Exception:
        return []

    if isinstance(data, dict):
        deps = data.get("dependencies", [])
    elif isinstance(data, list):
        deps = data
    else:
        deps = []

    normalized = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name")
        version = dep.get("version") or ""
        vulns = dep.get("vulns") or dep.get("vulnerabilities") or []
        if not name or not vulns:
            continue
        normalized.append({"name": name, "version": version, "vulns": vulns})
    return normalized


def run_pip_audit_requirements(req_file: Path):
    if not req_file.exists():
        return {"ok": False, "missing": True, "items": [], "raw": "", "stderr": f"Missing: {req_file}", "returncode": None}

    res = run_command([str(AUDIT_PYTHON), "-m", "pip_audit", "-r", str(req_file), "--format", "json"])
    items = parse_pip_audit_json(res["stdout"])
    return {
        "ok": res["returncode"] in (0, 1),
        "missing": False,
        "items": items,
        "raw": res["stdout"],
        "stderr": res["stderr"],
        "returncode": res["returncode"],
    }


def run_pip_audit_environment(project_dir: Path):
    site_packages = detect_site_packages(project_dir)
    if not site_packages:
        return {
            "ok": False,
            "missing": True,
            "items": [],
            "raw": "",
            "stderr": f"No site-packages found under {project_dir / '.venv'}",
            "returncode": None,
        }

    res = run_command([str(AUDIT_PYTHON), "-m", "pip_audit", "--path", str(site_packages), "--format", "json"])
    items = parse_pip_audit_json(res["stdout"])
    return {
        "ok": res["returncode"] in (0, 1),
        "missing": False,
        "items": items,
        "raw": res["stdout"],
        "stderr": res["stderr"],
        "returncode": res["returncode"],
    }


def run_outdated(project_python: Path):
    res = run_command([str(project_python), "-m", "pip", "list", "--outdated", "--format=json"])
    try:
        data = json.loads(res["stdout"]) if res["stdout"].strip() else []
    except Exception:
        data = []
    items = []
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict) and row.get("name"):
                items.append(
                    {
                        "name": row.get("name"),
                        "version": row.get("version", ""),
                        "latest_version": row.get("latest_version", ""),
                        "latest_filetype": row.get("latest_filetype", ""),
                    }
                )
    return {"ok": res["returncode"] == 0, "items": items, "stderr": res["stderr"]}


def get_python_interpreter_version(project_python: Path):
    res = run_command([str(project_python), "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}')"])
    if res["returncode"] == 0 and res["stdout"].strip():
        return res["stdout"].strip()
    return ""


def version_tuple(version_text: str):
    if not version_text:
        return ()
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_text)
    if not m:
        return ()
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def version_cycle(version_text: str):
    vt = version_tuple(version_text)
    if len(vt) >= 2:
        return f"{vt[0]}.{vt[1]}"
    return ""


def compare_versions(left: str, right: str):
    lt = version_tuple(left)
    rt = version_tuple(right)
    if not lt or not rt:
        return 0
    return -1 if lt < rt else (1 if lt > rt else 0)


def status_label(status: str):
    status = (status or "unknown").lower()
    return {
        "feature": "feature",
        "bugfix": "bugfix",
        "security": "security-only",
        "end-of-life": "end-of-life",
        "planned": "planned",
        "unknown": "unknown",
    }.get(status, status)

# -----------------------------------------------------------------------------
# Additional helpers for Python runtime analysis and presentation
#
# These functions implement a more compact and consolidated view of Python
# version declarations across multiple sources. They compute the recommended
# Python release, group sources that resolve to the same effective version
# and lifecycle state, and generate badges and notes for display in the
# reports. See the README for details.

def supported_python_cycles(catalog):
    """
    Return a list of supported Python release cycles sorted by version.
    A cycle is considered supported if its status is bugfix or security.
    """
    items = []
    today = NOW.strftime("%Y-%m-%d")
    for row in catalog.get("items", []):
        cycle = row.get("cycle")
        if not cycle:
            continue
        eol = row.get("eol")
        support = row.get("support")
        status = "unknown"
        if isinstance(eol, str) and eol and eol < today:
            status = "end-of-life"
        elif isinstance(support, str) and support:
            status = "security" if support < today else "bugfix"
        elif support is False:
            status = "end-of-life"
        if status in {"bugfix", "security"}:
            item = dict(row)
            item["status"] = status
            items.append(item)
    return sorted(items, key=lambda x: version_tuple(x.get("cycle", "")))


def recommended_python_release(catalog):
    """
    Determine the recommended Python release.
    Prefer the most recent bugfix release; if none, fall back to the most
    recent supported release.
    """
    supported = supported_python_cycles(catalog)
    bugfix = [x for x in supported if x.get("status") == "bugfix"]
    if bugfix:
        return sorted(bugfix, key=lambda x: version_tuple(x.get("cycle", "")))[-1]
    return supported[-1] if supported else None


def compact_runtime_notes(src_row):
    """
    Produce a list of short notes for a runtime source row based on its issues and
    status. These notes are used for the compact text and badge display.
    """
    notes = []
    issues = src_row.get("issues") or []
    # note for patch availability
    if "patch update available" in issues:
        notes.append("Patch update available")
    else:
        # note for being current in branch
        if src_row.get("status") in {"bugfix", "security"} and src_row.get("normalized") and src_row.get("latest"):
            if compare_versions(src_row["normalized"], src_row["latest"]) == 0:
                branch = src_row.get("cycle", "-")
                notes.append(f"Current in {branch} branch")
    # note for upgrade suggestion
    if any("newer supported branch available" in issue for issue in issues):
        rec = src_row.get("recommended_latest") or src_row.get("recommended_cycle") or ""
        if rec:
            notes.append(f"Upgrade available to {rec}")
    # include original note
    if src_row.get("note"):
        notes.append(src_row["note"])
    return notes


def group_python_runtime_sources(sources):
    """
    Group Python runtime source entries by their declared value and effective
    status. This merges multiple sources (e.g., interpreter and .python-version)
    that resolve to the same version and lifecycle state. Notes are aggregated
    but not used to differentiate groups, so identical versions consolidate
    even if their notes differ.
    """
    grouped = {}
    for src in sources:
        lifecycle = status_label(src.get("status"))
        recommended_display = src.get("recommended_latest") or src.get("recommended_cycle") or "-"
        key = (
            src.get("value") or "",
            lifecycle,
            recommended_display,
            tuple(sorted(src.get("issues") or [])),
        )
        # compute notes for this individual row (but do not include in key)
        row_notes = compact_runtime_notes(src)
        row = grouped.setdefault(
            key,
            {
                "sources": [],
                "paths": [],
                "declared": src.get("value") or "-",
                "lifecycle": lifecycle,
                "recommended": recommended_display,
                "issues": list(src.get("issues") or []),
                "notes": set(),
            },
        )
        row["sources"].append(src.get("source") or "-")
        row["paths"].append(src.get("path") or "-")
        # merge notes across grouped items
        for note in row_notes:
            row["notes"].add(note)
    result = []
    for row in grouped.values():
        result.append(
            {
                "sources": row["sources"],
                "paths": row["paths"],
                "declared": row["declared"],
                "lifecycle": row["lifecycle"],
                "recommended": row["recommended"],
                "issues": row["issues"],
                "notes": sorted(row["notes"]),
            }
        )
    result.sort(key=lambda x: (x["declared"], ", ".join(x["sources"])))
    return result


def lifecycle_badge(lifecycle):
    """
    Generate a colored badge for a lifecycle status.
    """
    lifecycle_lower = (lifecycle or "unknown").lower()
    if lifecycle_lower == "bugfix":
        return style_badge("Fully supported", "ok")
    if lifecycle_lower == "security-only":
        return style_badge("Security-only", "warn")
    if lifecycle_lower == "end-of-life":
        return style_badge("End-of-life", "bad")
    return style_badge(lifecycle or "unknown", "info")


def runtime_note_badges(notes):
    """
    Convert a list of runtime notes into styled badges. Returns a hyphen if
    there are no notes.
    """
    if not notes:
        return "-"
    badges = []
    for note in notes:
        kind = "info"
        lower = note.lower()
        if "current in" in lower:
            kind = "ok"
        elif "upgrade available" in lower or "patch update" in lower:
            kind = "warn"
        badges.append(style_badge(note, kind))
    return "".join(badges)


def fetch_python_release_catalog():
    url = CONFIG.get("python_release_catalog_url", "https://endoflife.date/api/python.json")
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            payload = response.read().decode("utf-8", errors="replace")
        data = json.loads(payload)
    except Exception as exc:
        return {"ok": False, "items": [], "error": str(exc)}

    items = []
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict) and row.get("cycle"):
                items.append(row)
    return {"ok": True, "items": items, "error": ""}


def python_release_info(catalog, cycle: str):
    for row in catalog.get("items", []):
        if row.get("cycle") == cycle:
            support = row.get("support")
            eol = row.get("eol")
            today = NOW.strftime("%Y-%m-%d")
            status = "unknown"
            if isinstance(eol, str) and eol and eol < today:
                status = "end-of-life"
            elif isinstance(support, str) and support:
                status = "security" if support < today else "bugfix"
            elif support is False:
                status = "end-of-life"
            item = dict(row)
            item["status"] = status
            return item
    return None


def parse_python_value(raw_value: str):
    raw_value = (raw_value or "").strip()
    if not raw_value:
        return {"raw": "", "normalized": "", "cycle": "", "is_exact": False, "kind": "missing"}

    cleaned = raw_value.strip().strip('"\'')
    cleaned = cleaned.replace("python-", "") if cleaned.lower().startswith("python-") else cleaned
    cleaned = cleaned.replace("cpython-", "") if cleaned.lower().startswith("cpython-") else cleaned
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", cleaned)
    normalized = m.group(1) if m else ""
    exact = bool(re.fullmatch(r"\d+\.\d+\.\d+", normalized))
    cycle = version_cycle(normalized)
    kind = "exact" if exact else ("minor" if cycle else "constraint")
    return {"raw": raw_value, "normalized": normalized, "cycle": cycle, "is_exact": exact, "kind": kind}


def detect_python_runtime_sources(project_dir: Path, project_python: Path, catalog):
    """
    Examine all declared Python version sources for a project and determine their
    lifecycle status, patch currency, and recommended upgrade path. The result
    includes both raw source rows and grouped/merged rows for display.
    """
    sources = []

    def add_source(path: Path, label: str, value: str, note: str = ""):
        parsed = parse_python_value(value)
        cycle = parsed["cycle"]
        release = python_release_info(catalog, cycle) if cycle else None
        latest_branch = release.get("latest", "") if release else ""
        status = release.get("status", "unknown") if release else "unknown"
        recommended = recommended_python_release(catalog)
        recommended_cycle = recommended.get("cycle", "") if recommended else ""
        recommended_latest = recommended.get("latest", "") if recommended else ""
        issues = []
        # warn if a newer patch is available for this branch
        if parsed["is_exact"] and latest_branch and compare_versions(parsed["normalized"], latest_branch) < 0:
            issues.append("patch update available")
        # warn on unsupported or security branches
        if status == "end-of-life":
            issues.append("unsupported Python branch")
        elif status == "security":
            issues.append("security-fixes-only branch")
        # suggest upgrade if the declared cycle is older than recommended
        if cycle and recommended_cycle and version_tuple(cycle) < version_tuple(recommended_cycle):
            issues.append("newer supported branch available")
        sources.append(
            {
                "source": label,
                "path": str(path),
                "value": value.strip(),
                "normalized": parsed["normalized"],
                "cycle": cycle,
                "kind": parsed["kind"],
                "is_exact": parsed["is_exact"],
                "latest": latest_branch,
                "recommended_cycle": recommended_cycle,
                "recommended_latest": recommended_latest,
                "status": status,
                "issues": issues,
                "note": note,
            }
        )

    # interpreter version from the project's Python
    interpreter_note = ""
    actual_version = get_python_interpreter_version(project_python)
    if actual_version:
        # record the interpreter note separately; do not include it in grouping
        interpreter_note = f"Python version used is from {project_python}"
        add_source(project_python, "interpreter", actual_version, "")

    # parse version declarations in common files
    simple_files = [
        (project_dir / ".python-version", ".python-version"),
        (project_dir / ".tool-versions", ".tool-versions"),
        (project_dir / "runtime.txt", "runtime.txt"),
        (project_dir / "Pipfile", "Pipfile"),
        (project_dir / "pyproject.toml", "pyproject.toml"),
        (project_dir / "tox.ini", "tox.ini"),
        (project_dir / "setup.cfg", "setup.cfg"),
        (project_dir / "Dockerfile", "Dockerfile"),
    ]
    for path, label in simple_files:
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        value = ""
        note = ""
        if label == ".python-version":
            value = (text.splitlines() or [""])[0].strip()
        elif label == ".tool-versions":
            m = re.search(r"(?m)^\s*python\s+([^\s#]+)", text)
            if m:
                value = m.group(1).strip()
        elif label == "runtime.txt":
            value = (text.splitlines() or [""])[0].strip()
        elif label == "Pipfile":
            m = re.search(r'(?m)^\s*python_full_version\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                value = m.group(1).strip()
            else:
                m = re.search(r'(?m)^\s*python_version\s*=\s*["\']([^"\']+)["\']', text)
                if m:
                    value = m.group(1).strip()
        elif label == "pyproject.toml":
            m = re.search(r'(?m)^\s*requires-python\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                value = m.group(1).strip()
                note = "Constraint from project metadata"
            else:
                m = re.search(r'(?m)^\s*python\s*=\s*["\']([^"\']+)["\']', text)
                if m:
                    value = m.group(1).strip()
                    note = "Poetry or tool-specific Python constraint"
        elif label == "tox.ini":
            m = re.search(r'(?m)^\s*basepython\s*=\s*([^\s#]+)', text)
            if m:
                value = m.group(1).strip().replace("python", "")
        elif label == "setup.cfg":
            m = re.search(r'(?m)^\s*python_requires\s*=\s*([^\n#]+)', text)
            if m:
                value = m.group(1).strip()
                note = "Constraint from setup.cfg"
        elif label == "Dockerfile":
            m = re.search(r'(?mi)^\s*FROM\s+python:([^\s]+)', text)
            if m:
                value = m.group(1).strip()
                note = "Base image tag"
            else:
                m = re.search(r'(?mi)^\s*ARG\s+PYTHON_VERSION=([^\s]+)', text)
                if m:
                    value = m.group(1).strip()
                    note = "Docker ARG"
        if value:
            add_source(path, label, value, note)

    # extract python-version from GitHub Actions workflows
    workflows_dir = project_dir / ".github" / "workflows"
    if workflows_dir.exists():
        for workflow in sorted(workflows_dir.glob("*.y*ml")):
            try:
                text = workflow.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in re.finditer(r'(?mi)python-version\s*:\s*["\']?([^"\'\n]+)', text):
                value = m.group(1).strip()
                if value:
                    add_source(workflow, f"workflow:{workflow.name}", value, "GitHub Actions python-version")
                    break

    # top-level issues across sources
    exact_cycles = sorted({s["cycle"] for s in sources if s.get("cycle")})
    exact_versions = sorted({s["normalized"] for s in sources if s.get("normalized") and s.get("is_exact")}, key=version_tuple)
    issues = []
    if len(exact_cycles) > 1:
        issues.append("multiple Python minor versions declared across files")
    if len(exact_versions) > 1:
        issues.append("multiple exact Python patch versions declared across files")
    if not sources:
        issues.append("no Python version declaration files found")

    # compute highest risk across all sources
    highest_risk = "ok"
    for src in sources:
        if "unsupported Python branch" in src["issues"]:
            highest_risk = "bad"
            break
        if src["issues"] and highest_risk != "bad":
            highest_risk = "warn"
    if issues and highest_risk == "ok":
        highest_risk = "warn"

    # group sources for presentation
    grouped = group_python_runtime_sources(sources)
    return {
        "catalog_ok": catalog.get("ok", False),
        "catalog_error": catalog.get("error", ""),
        "sources": sources,
        "grouped_sources": grouped,
        "issues": issues,
        "highest_risk": highest_risk,
        "interpreter_note": interpreter_note,
    }


def find_nvm_bin_dirs():
    results = []
    candidate_roots = []

    nvm_dir_env = os.environ.get("NVM_DIR")
    if nvm_dir_env:
        candidate_roots.append(Path(nvm_dir_env) / "versions" / "node")

    candidate_roots.append(Path.home() / ".nvm" / "versions" / "node")

    seen = set()
    for root in candidate_roots:
        if root in seen:
            continue
        seen.add(root)
        if not root.exists():
            continue
        try:
            node_dirs = sorted(root.iterdir(), reverse=True)
        except Exception:
            continue
        for node_dir in node_dirs:
            bin_dir = node_dir / "bin"
            if bin_dir.is_dir():
                results.append(bin_dir)

    return results


def detect_node_tool(frontend_dir: Path, tool_name: str):
    local_tool = frontend_dir / "node_modules" / ".bin" / tool_name
    if local_tool.exists() and os.access(local_tool, os.X_OK):
        return str(local_tool)

    which_tool = shutil.which(tool_name)
    if which_tool:
        return which_tool

    for bin_dir in find_nvm_bin_dirs():
        candidate = bin_dir / tool_name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)

    return None


def build_node_env(frontend_dir: Path, npm_cmd: str):
    extra_path = []
    local_bin = frontend_dir / "node_modules" / ".bin"
    if local_bin.is_dir():
        extra_path.append(local_bin)

    npm_path = Path(npm_cmd)
    if npm_path.exists():
        extra_path.append(npm_path.parent)

    extra_path.extend(find_nvm_bin_dirs())
    return build_runtime_env(extra_path)


def normalize_npm_severity(sev):
    if not isinstance(sev, str):
        return "UNKNOWN"
    sev = sev.strip().upper()
    if sev == "MODERATE":
        return "MODERATE"
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return sev
    return "UNKNOWN"


def infer_vuln_type(vuln):
    text_parts = []
    for key in ("description", "summary", "details", "title", "overview", "url"):
        value = vuln.get(key)
        if isinstance(value, str) and value.strip():
            text_parts.append(value.lower())

    for alias in vuln.get("aliases", []) or []:
        if isinstance(alias, str):
            text_parts.append(alias.lower())

    text = " ".join(text_parts)
    patterns = [
        ("Remote Code Execution", ["remote code execution", " rce", "rce ", "arbitrary code execution"]),
        ("SQL Injection", ["sql injection", "sqli"]),
        ("Cross-Site Scripting", ["cross-site scripting", " xss", "xss ", "stored xss", "reflected xss"]),
        ("Cross-Site Request Forgery", ["cross-site request forgery", " csrf", "csrf "]),
        ("Server-Side Request Forgery", ["server-side request forgery", " ssrf", "ssrf "]),
        ("Path Traversal", ["path traversal", "directory traversal", "zip slip", "traversal"]),
        ("Command Injection", ["command injection", "shell injection", "os command"]),
        ("Deserialization", ["deserialization", "insecure deserialization", "pickle"]),
        ("Authentication Bypass", ["authentication bypass", "auth bypass"]),
        ("Authorization Issue", ["authorization", "privilege escalation", "access control bypass"]),
        ("Information Disclosure", ["information disclosure", "sensitive information", "data leak", "exposure"]),
        ("Denial of Service", ["denial of service", " dos", "dos ", "redos", "resource exhaustion"]),
        ("Open Redirect", ["open redirect"]),
        ("XML External Entity", ["xxe", "xml external entity"]),
        ("Prototype Pollution", ["prototype pollution"]),
        ("Memory Corruption", ["heap overflow", "buffer overflow", "use-after-free", "memory corruption"]),
        ("Improper Input Validation", ["input validation", "improper validation", "validation bypass"]),
        ("Cryptographic Issue", ["cryptographic", "cipher", "weak randomness", "predictable random"]),
    ]
    for label, needles in patterns:
        if any(n in text for n in needles):
            return label
    return "Unclassified"


def parse_npm_audit_json(raw: str):
    try:
        data = json.loads(raw)
    except Exception:
        return []

    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulnerabilities, dict):
        return []

    items = []
    for name, vuln in vulnerabilities.items():
        if not isinstance(vuln, dict):
            continue

        via = vuln.get("via") or []
        advisories = []
        aliases = set()
        fix_versions = set()
        descriptions = []
        severities = set()
        types = set()

        top_severity = normalize_npm_severity(vuln.get("severity"))
        if top_severity:
            severities.add(top_severity)

        fix_available = vuln.get("fixAvailable")
        if isinstance(fix_available, dict):
            version = fix_available.get("version")
            if version:
                fix_versions.add(str(version))
        elif isinstance(fix_available, bool):
            if not fix_available:
                fix_versions.add("No automatic fix available")
        elif isinstance(fix_available, str) and fix_available.strip():
            fix_versions.add(fix_available.strip())

        for entry in via:
            if isinstance(entry, str):
                aliases.add(entry)
                continue
            if not isinstance(entry, dict):
                continue
            source = entry.get("source")
            url = entry.get("url")
            title = entry.get("title") or entry.get("name") or entry.get("overview") or entry.get("url") or ""
            severity = normalize_npm_severity(entry.get("severity") or vuln.get("severity"))
            if severity:
                severities.add(severity)
            if source:
                advisories.append(str(source))
            if title:
                descriptions.append(str(title))
            if url:
                aliases.add(str(url))
            cwe = entry.get("cwe")
            if isinstance(cwe, list):
                for value in cwe:
                    aliases.add(str(value))
            elif cwe:
                aliases.add(str(cwe))
            if entry.get("range"):
                fix_versions.add(str(entry["range"]))
            types.add(infer_vuln_type(entry))

        effects = vuln.get("effects") or []
        for effect in effects:
            if effect:
                aliases.add(str(effect))

        if not types:
            types.add("Unclassified")
        if not severities:
            severities.add("UNKNOWN")

        sorted_severities = sorted(severities, key=lambda s: SEVERITY_ORDER.get(s, 0), reverse=True)
        items.append(
            {
                "name": name,
                "version": "",
                "current": "",
                "sources": ["frontend-npm-audit"],
                "ids": sorted({x for x in advisories if x}),
                "aliases": sorted(aliases),
                "fix_versions": sorted(fix_versions),
                "description": descriptions[0] if descriptions else "",
                "severities": sorted_severities,
                "highest_severity": sorted_severities[0],
                "types": sorted(types),
                "primary_type": sorted(types)[0],
                "nodes": vuln.get("nodes") or [],
                "effects": effects,
                "is_frontend": True,
            }
        )

    items.sort(key=lambda x: (-SEVERITY_ORDER.get(x["highest_severity"], 0), x["name"].lower()))
    return items


def run_npm_audit(frontend_dir: Path):
    package_json = frontend_dir / "package.json"
    if not package_json.exists():
        return {"ran": False, "missing": True, "items": [], "stderr": f"Missing: {package_json}", "returncode": None, "cmd": ""}

    npm_cmd = detect_node_tool(frontend_dir, "npm")
    if not npm_cmd:
        return {"ran": False, "missing": False, "items": [], "stderr": "npm not found in node_modules/.bin, PATH, or ~/.nvm", "returncode": 127, "cmd": "npm audit --json"}

    env = build_node_env(frontend_dir, npm_cmd)
    res = run_command([npm_cmd, "audit", "--json"], cwd=frontend_dir, timeout=600, env=env)
    items = parse_npm_audit_json(res["stdout"])
    return {"ran": True, "missing": False, "ok": res["returncode"] in (0, 1), "items": items, "stderr": res["stderr"], "returncode": res["returncode"], "cmd": res["cmd"]}


def run_npm_outdated(frontend_dir: Path):
    package_json = frontend_dir / "package.json"
    if not package_json.exists():
        return {"ran": False, "missing": True, "items": [], "stderr": f"Missing: {package_json}", "returncode": None, "cmd": ""}

    npm_cmd = detect_node_tool(frontend_dir, "npm")
    if not npm_cmd:
        return {"ran": False, "missing": False, "items": [], "stderr": "npm not found in node_modules/.bin, PATH, or ~/.nvm", "returncode": 127, "cmd": "npm outdated --json"}

    env = build_node_env(frontend_dir, npm_cmd)
    res = run_command([npm_cmd, "outdated", "--json"], cwd=frontend_dir, timeout=600, env=env)
    stdout = (res["stdout"] or "").strip()
    items = []
    try:
        data = json.loads(stdout) if stdout else {}
    except Exception:
        data = {}

    if isinstance(data, dict):
        for name, row in data.items():
            if not isinstance(row, dict):
                continue
            items.append(
                {
                    "name": name,
                    "current": row.get("current", ""),
                    "wanted": row.get("wanted", ""),
                    "latest": row.get("latest", ""),
                    "location": row.get("location", ""),
                    "depended_by": row.get("dependedBy", ""),
                    "package_type": row.get("type", ""),
                }
            )

    return {"ran": True, "missing": False, "ok": res["returncode"] in (0, 1), "items": sorted(items, key=lambda x: x["name"].lower()), "stderr": res["stderr"], "returncode": res["returncode"], "cmd": res["cmd"]}


def run_django_check(django_dir: Path, project_python: Path):
    manage_py = django_dir / "manage.py"
    if not manage_py.exists():
        return {"ran": False, "ok": None, "stdout": "", "stderr": f"No manage.py found in {django_dir}", "returncode": None}

    res = run_command([str(project_python), "manage.py", "check"], cwd=django_dir)
    return {"ran": True, "ok": res["returncode"] == 0, "stdout": res["stdout"], "stderr": res["stderr"], "returncode": res["returncode"]}


def normalize_fix_versions(vuln):
    fixes = vuln.get("fix_versions") or vuln.get("fixed_versions") or []
    return [str(x) for x in fixes if str(x).strip()] if isinstance(fixes, list) else []


def numeric_cvss_to_rating(score: float):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def cvss_vector_to_rating(_vector: str):
    return "UNKNOWN"


def extract_severity(vuln):
    sev = vuln.get("severity")
    if isinstance(sev, str) and sev.strip():
        return sev.strip().upper()

    sev_list = vuln.get("severity")
    if isinstance(sev_list, list):
        for entry in sev_list:
            if isinstance(entry, dict):
                score = entry.get("score")
                if isinstance(score, str) and score.strip():
                    cvss_text = score.strip().upper()
                    if "CVSS:3.1/AV" in cvss_text or "CVSS:3.0/AV" in cvss_text:
                        return cvss_vector_to_rating(cvss_text)

    for key in ("cvss", "database_specific", "ecosystem_specific"):
        block = vuln.get(key)
        if isinstance(block, dict):
            severity = block.get("severity")
            if isinstance(severity, str) and severity.strip():
                return severity.strip().upper()
            score = block.get("score")
            if isinstance(score, str) and score.strip():
                maybe = score.strip().upper()
                if maybe.startswith("CVSS:"):
                    return cvss_vector_to_rating(maybe)
                try:
                    return numeric_cvss_to_rating(float(maybe))
                except Exception:
                    pass

    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity.strip():
            return severity.strip().upper()
        cvss = database_specific.get("cvss")
        if isinstance(cvss, dict):
            score = cvss.get("score")
            if isinstance(score, (int, float)):
                return numeric_cvss_to_rating(float(score))
            if isinstance(score, str) and score.strip():
                try:
                    return numeric_cvss_to_rating(float(score.strip()))
                except Exception:
                    pass

    return "UNKNOWN"


def consolidate_vulns(req_items, env_items, outdated_items=None):
    combined = {}
    outdated_map = {item["name"].lower(): item for item in (outdated_items or []) if isinstance(item, dict) and item.get("name")}

    def upsert(source, item):
        pkg = item["name"].lower()
        row = combined.setdefault(
            pkg,
            {
                "name": item["name"],
                "version": item.get("version", ""),
                "latest_version": "",
                "latest_filetype": "",
                "sources": set(),
                "ids": set(),
                "aliases": set(),
                "fix_versions": set(),
                "descriptions": [],
                "severities": set(),
                "types": set(),
            },
        )
        if item.get("version") and not row["version"]:
            row["version"] = item["version"]
        row["sources"].add(source)

        outdated = outdated_map.get(pkg)
        if outdated:
            if outdated.get("latest_version"):
                row["latest_version"] = outdated.get("latest_version", "")
            if outdated.get("latest_filetype"):
                row["latest_filetype"] = outdated.get("latest_filetype", "")

        for vuln in item.get("vulns", []):
            vid = vuln.get("id") or vuln.get("alias") or "UNKNOWN"
            row["ids"].add(str(vid))
            for alias in vuln.get("aliases", []) or []:
                row["aliases"].add(str(alias))
            for fixv in normalize_fix_versions(vuln):
                row["fix_versions"].add(fixv)
            desc = (vuln.get("description") or vuln.get("summary") or "").strip()
            if desc and desc not in row["descriptions"]:
                row["descriptions"].append(desc)
            row["severities"].add(extract_severity(vuln))
            row["types"].add(infer_vuln_type(vuln))

    for item in req_items:
        upsert("requirements", item)
    for item in env_items:
        upsert(".venv", item)

    result = []
    for pkg in sorted(combined):
        row = combined[pkg]
        severities = sorted(row["severities"], key=lambda s: SEVERITY_ORDER.get(s, 0), reverse=True)
        types_sorted = sorted(t for t in row["types"] if t)
        result.append(
            {
                "name": row["name"],
                "version": row["version"],
                "latest_version": row["latest_version"],
                "latest_filetype": row["latest_filetype"],
                "sources": sorted(row["sources"]),
                "ids": sorted(row["ids"]),
                "aliases": sorted(row["aliases"]),
                "fix_versions": sorted(row["fix_versions"]),
                "description": row["descriptions"][0] if row["descriptions"] else "",
                "severities": severities,
                "highest_severity": severities[0] if severities else "UNKNOWN",
                "types": types_sorted if types_sorted else ["Unclassified"],
                "primary_type": types_sorted[0] if types_sorted else "Unclassified",
            }
        )

    result.sort(key=lambda x: (-SEVERITY_ORDER.get(x["highest_severity"], 0), x["name"].lower()))
    return result


def style_badge(label, kind):
    colors = {"ok": "#e8f5e9", "warn": "#fff8e1", "bad": "#ffebee", "info": "#e3f2fd"}
    border = {"ok": "#2e7d32", "warn": "#f9a825", "bad": "#c62828", "info": "#1565c0"}
    return (
        f'<span style="display:inline-block;padding:4px 10px;border-radius:999px;background:{colors[kind]};color:{border[kind]};font-weight:600;border:1px solid {border[kind]};font-size:12px;">{escape(label)}</span>'
    )


def severity_badge(severity):
    sev = severity if severity in SEVERITY_COLOR else "UNKNOWN"
    return (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:999px;background:{SEVERITY_BG[sev]};color:{SEVERITY_COLOR[sev]};font-weight:700;border:1px solid {SEVERITY_COLOR[sev]};font-size:12px;">{escape(sev)}</span>'
    )


ensure_pip_audit()
results = []
all_vuln_count = 0
all_apps_with_vulns = 0
global_severity_counter = Counter()
global_frontend_vuln_count = 0
global_frontend_outdated_count = 0
global_python_runtime_issue_count = 0
python_release_catalog = fetch_python_release_catalog()

for project in PROJECTS:
    project_dir = project["dir"]
    django_dir = project.get("django_dir", project_dir)
    project_python = detect_project_python(project_dir)

    req_audit_items = []
    req_notes = []
    for req_file in project["requirements"]:
        if req_file.exists():
            req_res = run_pip_audit_requirements(req_file)
            req_audit_items.extend(req_res["items"])
            if req_res["stderr"].strip():
                req_notes.append(req_res["stderr"].strip())
        else:
            req_notes.append(f"Missing requirements file: {req_file}")

    env_res = run_pip_audit_environment(project_dir)
    env_items = env_res["items"]
    outdated_res = run_outdated(project_python)
    django_res = run_django_check(django_dir, project_python)
    python_runtime = detect_python_runtime_sources(project_dir, project_python, python_release_catalog)
    consolidated = consolidate_vulns(req_audit_items, env_items, outdated_res["items"])

    app_severity_counter = Counter()
    type_counter = Counter()
    for row in consolidated:
        sev = row.get("highest_severity", "UNKNOWN")
        app_severity_counter[sev] += 1
        global_severity_counter[sev] += 1
        type_counter[row.get("primary_type", "Unclassified")] += 1

    frontend_summary = {
        "enabled": bool(project.get("frontend_dir")),
        "dir": str(project.get("frontend_dir")) if project.get("frontend_dir") else "",
        "audit": {"ran": False, "items": [], "stderr": "", "cmd": "", "returncode": None},
        "outdated": {"ran": False, "items": [], "stderr": "", "cmd": "", "returncode": None},
        "vuln_count": 0,
        "outdated_other_count": 0,
    }

    if project.get("frontend_dir"):
        frontend_dir = Path(project["frontend_dir"])
        npm_audit_res = run_npm_audit(frontend_dir)
        npm_outdated_res = run_npm_outdated(frontend_dir)

        outdated_map = {x["name"].lower(): x for x in npm_outdated_res["items"] if x.get("name")}
        for vuln in npm_audit_res["items"]:
            outdated = outdated_map.get(vuln["name"].lower())
            if outdated:
                vuln["version"] = outdated.get("current", "")
                vuln["current"] = outdated.get("current", "")
                vuln["wanted_version"] = outdated.get("wanted", "")
                vuln["latest_version"] = outdated.get("latest", "")
            else:
                vuln["current"] = vuln.get("version", "")
                vuln["wanted_version"] = ""
                vuln["latest_version"] = ""

        vuln_names = {x["name"].lower() for x in npm_audit_res["items"] if x.get("name")}
        frontend_summary = {
            "enabled": True,
            "dir": str(frontend_dir),
            "audit": npm_audit_res,
            "outdated": npm_outdated_res,
            "vuln_count": len(npm_audit_res["items"]),
            "outdated_other_count": len([x for x in npm_outdated_res["items"] if x["name"].lower() not in vuln_names]),
        }
        global_frontend_vuln_count += frontend_summary["vuln_count"]
        global_frontend_outdated_count += frontend_summary["outdated_other_count"]

    if consolidated:
        all_apps_with_vulns += 1
        all_vuln_count += len(consolidated)
    if python_runtime["issues"] or any(x.get("issues") for x in python_runtime["sources"]):
        global_python_runtime_issue_count += 1

    results.append(
        {
            "name": project["name"],
            "dir": str(project_dir),
            "django_dir": str(django_dir),
            "python": str(project_python),
            "requirements": [str(x) for x in project["requirements"]],
            "vulnerabilities": consolidated,
            "outdated_other_count": len([x for x in outdated_res["items"] if x["name"].lower() not in {v["name"].lower() for v in consolidated}]),
            "outdated_items": outdated_res["items"],
            "django_check": django_res,
            "env_note": env_res["stderr"].strip() if env_res.get("stderr") else "",
            "req_notes": req_notes,
            "severity_counts": app_severity_counter,
            "type_counts": type_counter,
            "frontend": frontend_summary,
            "python_runtime": python_runtime,
        }
    )

summary_status = "Issues found" if (all_vuln_count or global_frontend_vuln_count) else "No known vulnerable packages found"

text_lines = []
text_lines.append("Django / Python dependency audit")
text_lines.append(f"Generated: {NOW.strftime('%Y-%m-%d %H:%M:%S')}")
text_lines.append(f"Host: {HOSTNAME_FQDN}")
text_lines.append(f"Status: {summary_status}")
text_lines.append(f"Apps checked: {len(results)}")
text_lines.append(f"Apps with Python vulnerabilities: {all_apps_with_vulns}")
text_lines.append(f"Python vulnerable packages: {all_vuln_count}")
text_lines.append(f"Frontend vulnerable packages: {global_frontend_vuln_count}")
text_lines.append(f"Frontend outdated non-vulnerable packages: {global_frontend_outdated_count}")
text_lines.append(f"Apps with Python runtime/version issues: {global_python_runtime_issue_count}")
if all_vuln_count:
    sev_summary = ", ".join(
        f"{sev}={global_severity_counter.get(sev, 0)}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFO", "UNKNOWN")
        if global_severity_counter.get(sev, 0)
    )
    text_lines.append(f"Python severity summary: {sev_summary}")
text_lines.append("")

for app in results:
    text_lines.append("=" * 78)
    text_lines.append(f"App: {app['name']}")
    text_lines.append("=" * 78)
    text_lines.append(f"Repository: {app['dir']}")
    text_lines.append(f"Django dir: {app['django_dir']}")
    text_lines.append(f"Python: {app['python']}")
    text_lines.append("Requirements:")
    for req in app["requirements"]:
        text_lines.append(f"  - {req}")

    runtime = app["python_runtime"]
    text_lines.append("")
    text_lines.append("Python runtime/version sources:")
    # use grouped sources when available for a concise view
    if runtime.get("grouped_sources"):
        for row in runtime["grouped_sources"]:
            sources_label = ", ".join(row["sources"])
            notes_text = "; ".join(row["notes"]) if row["notes"] else "-"
            text_lines.append(
                f"  - {sources_label}: declared={row['declared']} | lifecycle={row['lifecycle']} | recommended={row['recommended']} | notes={notes_text}"
            )
    elif runtime["sources"]:
        for src_row in runtime["sources"]:
            latest = src_row.get("latest") or "-"
            status = status_label(src_row.get("status"))
            issues = ", ".join(src_row.get("issues") or []) or "-"
            normalized = src_row.get("normalized") or "-"
            text_lines.append(
                f"  - {src_row['source']}: {src_row['value']} | normalized: {normalized} | latest: {latest} | status: {status} | issues: {issues}"
            )
            if src_row.get("note"):
                text_lines.append(f"      note: {src_row['note']}")
    else:
        text_lines.append("  - No Python version sources detected")
    # include summary-level runtime issues or catalog errors
    if runtime.get("issues"):
        text_lines.append("Python runtime issues:")
        for issue in runtime["issues"]:
            text_lines.append(f"  - {issue}")
    elif runtime.get("catalog_error"):
        text_lines.append(f"Python runtime note: release catalog lookup failed: {runtime['catalog_error']}")

    # add note about interpreter origin if present
    if runtime.get("interpreter_note"):
        text_lines.append(runtime["interpreter_note"])

    if app["vulnerabilities"]:
        sev_summary = ", ".join(
            f"{sev}={app['severity_counts'].get(sev, 0)}"
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFO", "UNKNOWN")
            if app["severity_counts"].get(sev, 0)
        )
        text_lines.append("")
        text_lines.append(f"Packages needing update because of vulnerabilities: {len(app['vulnerabilities'])}")
        text_lines.append(f"Severity summary: {sev_summary}")
        if app["type_counts"]:
            type_summary = ", ".join(f"{k}={v}" for k, v in app["type_counts"].most_common())
            text_lines.append(f"Type summary: {type_summary}")
        text_lines.append("")
        for row in app["vulnerabilities"]:
            fixes = ", ".join(row["fix_versions"]) if row["fix_versions"] else "no fixed version listed"
            ids = ", ".join(row["ids"]) if row["ids"] else "-"
            sources = ", ".join(row["sources"]) if row["sources"] else "-"
            vtypes = ", ".join(row["types"]) if row["types"] else "Unclassified"
            severity = row.get("highest_severity", "UNKNOWN")
            desc = row.get("description", "").strip()
            latest = row.get("latest_version") or "not listed by pip outdated"
            text_lines.append(
                f"  - {row['name']} ({row['version'] or '-'}) | latest: {latest} | severity: {severity} | type: {vtypes} | fixes: {fixes} | advisories: {ids} | found in: {sources}"
            )
            if desc:
                text_lines.append(f"      summary: {desc[:300]}")
    else:
        text_lines.append("")
        text_lines.append("No vulnerable Python packages found.")

    dj = app["django_check"]
    if dj["ran"]:
        text_lines.append(f"Django check: {'OK' if dj['ok'] else 'FAILED'}")
        if not dj["ok"]:
            err = (dj["stdout"] + "\n" + dj["stderr"]).strip()
            if err:
                text_lines.append(err[:2000])
    else:
        text_lines.append("Django check: not run")
        if dj["stderr"]:
            text_lines.append(dj["stderr"])

    frontend = app["frontend"]
    if frontend["enabled"]:
        text_lines.append("")
        text_lines.append(f"Frontend directory: {frontend['dir']}")
        if frontend["audit"]["ran"]:
            text_lines.append(f"Frontend vulnerable npm packages: {frontend['vuln_count']}")
            if frontend["audit"]["items"]:
                for row in frontend["audit"]["items"]:
                    fixes = ", ".join(row.get("fix_versions") or []) or "no fix information"
                    ids = ", ".join(row.get("ids") or []) or "-"
                    severity = row.get("highest_severity", "UNKNOWN")
                    vtypes = ", ".join(row.get("types") or ["Unclassified"])
                    current = row.get("current") or row.get("version") or "-"
                    wanted = row.get("wanted_version") or "-"
                    latest = row.get("latest_version") or "-"
                    text_lines.append(
                        f"  - npm:{row['name']} ({current}) | wanted: {wanted} | latest: {latest} | severity: {severity} | type: {vtypes} | fixes: {fixes} | advisories: {ids}"
                    )
                    if row.get("description"):
                        text_lines.append(f"      summary: {row['description'][:300]}")
            else:
                text_lines.append("  No vulnerable npm packages found.")
        else:
            text_lines.append("Frontend audit: not run")
            if frontend["audit"].get("stderr"):
                text_lines.append(frontend["audit"]["stderr"])

        if frontend["outdated"]["ran"]:
            text_lines.append(f"Frontend other outdated packages (non-vulnerable): {frontend['outdated_other_count']}")
            frontend_other_outdated = [
                x for x in frontend["outdated"]["items"]
                if x["name"].lower() not in {y["name"].lower() for y in frontend["audit"]["items"] if y.get("name")}
            ]
            if frontend_other_outdated:
                for row in frontend_other_outdated:
                    current = row.get("current") or "-"
                    wanted = row.get("wanted") or "-"
                    latest = row.get("latest") or "-"
                    pkg_type = row.get("package_type") or "-"
                    text_lines.append(f"  - npm:{row['name']} ({current}) | wanted: {wanted} | latest: {latest} | type: {pkg_type}")
        else:
            text_lines.append("Frontend outdated check: not run")
            if frontend["outdated"].get("stderr"):
                text_lines.append(frontend["outdated"]["stderr"])

    if app["req_notes"]:
        text_lines.append("Notes:")
        for note in app["req_notes"]:
            if note:
                text_lines.append(f"  - {note}")

    if app["env_note"]:
        text_lines.append(f"Environment note: {app['env_note']}")

    text_lines.append(f"Other outdated Python packages (non-vulnerable): {app['outdated_other_count']}")
    other_outdated_python = [x for x in app["outdated_items"] if x["name"].lower() not in {v["name"].lower() for v in app["vulnerabilities"]}]
    if other_outdated_python:
        for row in other_outdated_python:
            current = row.get("version") or "-"
            latest = row.get("latest_version") or "-"
            filetype = row.get("latest_filetype") or "-"
            text_lines.append(f"  - {row['name']} ({current}) | latest: {latest} | filetype: {filetype}")
    text_lines.append("")

TEXT_REPORT.write_text("\n".join(text_lines), encoding="utf-8")

html = []
html.append("<html><body style='font-family:Arial,Helvetica,sans-serif;background:#f5f7fb;color:#1f2937;'>")
html.append("<div style='max-width:1200px;margin:20px auto;padding:0 12px;'>")
html.append("<div style='background:#1e293b;color:white;padding:24px;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,0.12);'>")
html.append("<div style='font-size:28px;font-weight:700;margin-bottom:6px;'>Django Dependency Audit</div>")
html.append(f"<div style='font-size:15px;opacity:0.95;'>Host: {escape(HOSTNAME_FQDN)}</div>")
html.append(f"<div style='font-size:15px;opacity:0.95;'>Generated: {escape(NOW.strftime('%Y-%m-%d %H:%M:%S'))}</div>")
html.append("</div>")

html.append("<div style='display:flex;gap:16px;flex-wrap:wrap;margin:18px 0 18px 0;'>")
cards = [
    ("Apps checked", str(len(results)), "#e3f2fd", "#1565c0"),
    ("Python apps with vulnerabilities", str(all_apps_with_vulns), "#ffebee", "#c62828" if all_apps_with_vulns else "#2e7d32"),
    ("Python vulnerable packages", str(all_vuln_count), "#fff8e1", "#f9a825" if all_vuln_count else "#2e7d32"),
    ("Frontend vulnerable packages", str(global_frontend_vuln_count), "#fff8e1", "#f9a825" if global_frontend_vuln_count else "#2e7d32"),
    ("Apps with Python runtime issues", str(global_python_runtime_issue_count), "#fff8e1", "#f9a825" if global_python_runtime_issue_count else "#2e7d32"),
    ("Overall", summary_status, "#e8f5e9" if not (all_vuln_count or global_frontend_vuln_count or global_python_runtime_issue_count) else "#ffebee", "#2e7d32" if not (all_vuln_count or global_frontend_vuln_count or global_python_runtime_issue_count) else "#c62828"),
]
for title, value, bg, fg in cards:
    html.append(
        f"<div style='background:{bg};border-radius:14px;padding:16px 18px;min-width:220px;box-shadow:0 2px 8px rgba(0,0,0,0.06);'>"
        f"<div style='font-size:13px;color:#475569;margin-bottom:6px;'>{escape(title)}</div>"
        f"<div style='font-size:24px;font-weight:700;color:{fg};'>{escape(value)}</div>"
        "</div>"
    )
html.append("</div>")

if all_vuln_count:
    html.append("<div style='background:white;border-radius:16px;padding:18px;margin-bottom:20px;box-shadow:0 4px 16px rgba(0,0,0,0.07);'>")
    html.append("<div style='font-size:18px;font-weight:700;margin-bottom:12px;'>Python severity overview</div>")
    html.append("<div style='display:flex;gap:10px;flex-wrap:wrap;'>")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFO", "UNKNOWN"):
        count = global_severity_counter.get(sev, 0)
        if count:
            html.append(
                f"<div style='padding:10px 14px;border-radius:12px;background:{SEVERITY_BG[sev]};border:1px solid {SEVERITY_COLOR[sev]};color:{SEVERITY_COLOR[sev]};font-weight:700;'>"
                f"{escape(sev)}: {count}</div>"
            )
    html.append("</div></div>")

for app in results:
    vulns = app["vulnerabilities"]
    dj = app["django_check"]
    frontend = app["frontend"]
    runtime = app["python_runtime"]

    html.append("<div style='background:white;border-radius:16px;padding:20px;margin-bottom:20px;box-shadow:0 4px 16px rgba(0,0,0,0.07);'>")
    html.append("<div style='display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;'>")
    html.append("<div>")
    html.append(f"<div style='font-size:24px;font-weight:700;margin-bottom:6px;'>{escape(app['name'])}</div>")
    html.append(f"<div style='font-size:13px;color:#64748b;margin-bottom:4px;'>Repository: {escape(app['dir'])}</div>")
    html.append(f"<div style='font-size:13px;color:#64748b;margin-bottom:4px;'>Django dir: {escape(app['django_dir'])}</div>")
    html.append(f"<div style='font-size:13px;color:#64748b;'>Python: {escape(app['python'])}</div>")
    if frontend["enabled"]:
        html.append(f"<div style='font-size:13px;color:#64748b;'>Frontend: {escape(frontend['dir'])}</div>")
    html.append("</div>")

    badges = []
    badges.append(style_badge(f"{len(vulns)} vulnerable Python package(s)" if vulns else "No vulnerable Python packages", "bad" if vulns else "ok"))
    if dj["ran"]:
        badges.append(style_badge("Django check OK" if dj["ok"] else "Django check failed", "ok" if dj["ok"] else "bad"))
    else:
        badges.append(style_badge("No manage.py", "info"))

    runtime_issue_count = len(runtime.get("issues") or []) + sum(1 for x in runtime.get("sources", []) if x.get("issues"))
    # when no other outdated packages, use "ok" instead of "info" to show success
    badges.append(style_badge(f"{app['outdated_other_count']} other outdated Python", "warn" if app["outdated_other_count"] else "ok"))
    badges.append(style_badge(f"{runtime_issue_count} Python runtime issues", "warn" if runtime_issue_count else "ok"))
    if frontend["enabled"]:
        badges.append(style_badge(f"{frontend['vuln_count']} vulnerable npm" if frontend["vuln_count"] else "No vulnerable npm packages", "bad" if frontend["vuln_count"] else "ok"))
        # similarly switch to "ok" when zero outdated npm packages
        badges.append(style_badge(f"{frontend['outdated_other_count']} other outdated npm", "warn" if frontend["outdated_other_count"] else "ok"))

    html.append("<div style='display:flex;gap:8px;flex-wrap:wrap;'>" + "".join(badges) + "</div>")
    html.append("</div>")

    html.append("<div style='margin-top:14px;font-size:14px;'><b>Requirements files</b><ul style='margin-top:8px;'>")
    for req in app["requirements"]:
        html.append(f"<li><code>{escape(req)}</code></li>")
    html.append("</ul></div>")

    html.append("<div style='margin-top:18px;'><div style='font-size:16px;font-weight:700;margin-bottom:10px;color:#1d4ed8;'>Python runtime / version files</div>")
    # prepare rows using grouped sources for a compact table
    runtime_rows = runtime.get("grouped_sources") or []
    if runtime_rows:
        html.append(
            "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
            "<thead><tr style='background:#f8fafc;'>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Sources</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Declared</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Lifecycle</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Recommended upgrade</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Notes</th>"
            "</tr></thead><tbody>"
        )
        for row in runtime_rows:
            # assemble source lines with path information
            source_lines = []
            for idx, source_name in enumerate(row["sources"]):
                path_text = row["paths"][idx] if idx < len(row["paths"]) else ""
                source_lines.append(
                    f"<div style='margin-bottom:6px;'><b>{escape(source_name)}</b>"
                    + (f"<div style='font-size:12px;color:#64748b;margin-top:2px;'>{escape(path_text)}</div>" if path_text else "")
                    + "</div>"
                )
            lifecycle_html = lifecycle_badge(row["lifecycle"])
            notes_html = runtime_note_badges(row["notes"])
            html.append(
                "<tr>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{''.join(source_lines)}</td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(row['declared'] or '-')}</code></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{lifecycle_html}</td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(row['recommended'] or '-')}</code></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;display:flex;gap:6px;flex-wrap:wrap;'>{notes_html}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")
        # explanatory note for grouped table
        html.append(
            "<div style='margin-top:10px;padding:12px 14px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;color:#1e40af;font-size:13px;'>"
            "Declared Python sources with the same effective version state are grouped together."
            "</div>"
        )
        # optional note about interpreter source; displayed outside table for clarity
        if runtime.get("interpreter_note"):
            html.append(
                f"<div style='margin-top:6px;font-size:13px;color:#374151;'>{escape(runtime['interpreter_note'])}</div>"
            )
    else:
        html.append("<div style='padding:12px 14px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;color:#1d4ed8;'>No Python version declaration files detected.</div>")
        # show interpreter note even when no version files were detected
        if runtime.get("interpreter_note"):
            html.append(
                f"<div style='margin-top:6px;font-size:13px;color:#374151;'>{escape(runtime['interpreter_note'])}</div>"
            )
    # display high-level runtime issues or catalog errors
    if runtime.get("issues"):
        html.append("<ul style='margin:12px 0 0 20px;padding:0;'>")
        for issue in runtime["issues"]:
            html.append(f"<li style='margin-bottom:6px;color:#92400e;'>{escape(issue)}</li>")
        html.append("</ul>")
    elif runtime.get("catalog_error"):
        html.append(f"<div style='margin-top:10px;font-size:13px;color:#92400e;'>Python release lookup failed: {escape(runtime['catalog_error'])}</div>")
    html.append("</div>")

    if vulns:
        html.append("<div style='margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;'>")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFO", "UNKNOWN"):
            count = app["severity_counts"].get(sev, 0)
            if count:
                html.append(
                    f"<div style='padding:8px 12px;border-radius:12px;background:{SEVERITY_BG[sev]};border:1px solid {SEVERITY_COLOR[sev]};color:{SEVERITY_COLOR[sev]};font-weight:700;font-size:13px;'>"
                    f"{escape(sev)}: {count}</div>"
                )
        html.append("</div>")

        if app["type_counts"]:
            html.append("<div style='margin-top:12px;font-size:14px;color:#334155;'><b>Top Python vuln types:</b> ")
            html.append(escape(", ".join(f"{k}={v}" for k, v in app["type_counts"].most_common())))
            html.append("</div>")

        html.append(
            "<div style='margin-top:14px;'>"
            "<div style='font-size:16px;font-weight:700;margin-bottom:10px;color:#991b1b;'>Python packages needing update because of vulnerabilities</div>"
            "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
            "<thead><tr style='background:#f8fafc;'>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Package</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Current</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Latest</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Severity</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Type</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Update to</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Advisories</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Found in</th>"
            "</tr></thead><tbody>"
        )
        for row in vulns:
            fixes = ", ".join(row["fix_versions"]) if row["fix_versions"] else "No fixed version listed"
            ids = ", ".join(row["ids"]) if row["ids"] else "-"
            sources = ", ".join(row["sources"]) if row["sources"] else "-"
            vtype = ", ".join(row["types"]) if row["types"] else "Unclassified"
            severity = row.get("highest_severity", "UNKNOWN")
            latest = row.get("latest_version") or "-"
            html.append(
                "<tr>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><b>{escape(row['name'])}</b></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(row['version'] or '-')}</code></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(latest)}</code></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{severity_badge(severity)}</td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{escape(vtype)}</td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(fixes)}</code></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{escape(ids)}</td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{escape(sources)}</td>"
                "</tr>"
            )
            if row.get("description"):
                html.append(
                    "<tr><td colspan='8' style='padding:8px 10px 12px 10px;border-bottom:1px solid #eef2f7;font-size:13px;color:#475569;'>"
                    f"<b>Summary:</b> {escape(row['description'][:500])}</td></tr>"
                )
        html.append("</tbody></table></div>")
    else:
        html.append("<div style='margin-top:14px;padding:12px 14px;background:#ecfdf5;border:1px solid #bbf7d0;border-radius:12px;color:#166534;'>No known vulnerable Python packages found for this app.</div>")

    other_outdated_python = [x for x in app["outdated_items"] if x["name"].lower() not in {v["name"].lower() for v in app["vulnerabilities"]}]
    if other_outdated_python:
        html.append(
            "<div style='margin-top:18px;'>"
            "<div style='font-size:16px;font-weight:700;margin-bottom:10px;color:#92400e;'>Other outdated Python packages</div>"
            "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
            "<thead><tr style='background:#f8fafc;'>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Package</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Current</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Latest</th>"
            "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>File type</th>"
            "</tr></thead><tbody>"
        )
        for row in other_outdated_python:
            current = row.get("version") or "-"
            latest = row.get("latest_version") or "-"
            filetype = row.get("latest_filetype") or "-"
            html.append(
                "<tr>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><b>{escape(row['name'])}</b></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(current)}</code></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(latest)}</code></td>"
                f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(filetype)}</code></td>"
                "</tr>"
            )
        html.append("</tbody></table></div>")

    if frontend["enabled"]:
        if frontend["audit"]["ran"] and frontend["audit"]["items"]:
            html.append(
                "<div style='margin-top:18px;'>"
                "<div style='font-size:16px;font-weight:700;margin-bottom:10px;color:#991b1b;'>Frontend npm packages needing update because of vulnerabilities</div>"
                "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
                "<thead><tr style='background:#f8fafc;'>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Package</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Current</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Wanted</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Latest</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Severity</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Type</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Fix info</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Advisories</th>"
                "</tr></thead><tbody>"
            )
            for row in frontend["audit"]["items"]:
                fixes = ", ".join(row.get("fix_versions") or []) or "No fix information"
                ids = ", ".join(row.get("ids") or []) or "-"
                vtype = ", ".join(row.get("types") or ["Unclassified"])
                severity = row.get("highest_severity", "UNKNOWN")
                current = row.get("current") or row.get("version") or "-"
                wanted = row.get("wanted_version") or "-"
                latest = row.get("latest_version") or "-"
                html.append(
                    "<tr>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><b>{escape(row['name'])}</b></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(current)}</code></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(wanted)}</code></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(latest)}</code></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{severity_badge(severity)}</td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{escape(vtype)}</td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(fixes)}</code></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'>{escape(ids)}</td>"
                    "</tr>"
                )
                if row.get("description"):
                    html.append(
                        "<tr><td colspan='8' style='padding:8px 10px 12px 10px;border-bottom:1px solid #eef2f7;font-size:13px;color:#475569;'>"
                        f"<b>Summary:</b> {escape(row['description'][:500])}</td></tr>"
                    )
            html.append("</tbody></table></div>")
        else:
            html.append("<div style='margin-top:14px;padding:12px 14px;background:#ecfdf5;border:1px solid #bbf7d0;border-radius:12px;color:#166534;'>No known vulnerable npm packages found for this app frontend.</div>")

        frontend_other_outdated = [x for x in frontend["outdated"]["items"] if x["name"].lower() not in {y["name"].lower() for y in frontend["audit"]["items"] if y.get("name")}]
        if frontend_other_outdated:
            html.append(
                "<div style='margin-top:18px;'>"
                "<div style='font-size:16px;font-weight:700;margin-bottom:10px;color:#92400e;'>Other outdated frontend npm packages</div>"
                "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
                "<thead><tr style='background:#f8fafc;'>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Package</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Current</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Wanted</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Latest</th>"
                "<th style='text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;'>Type</th>"
                "</tr></thead><tbody>"
            )
            for row in frontend_other_outdated:
                current = row.get("current") or "-"
                wanted = row.get("wanted") or "-"
                latest = row.get("latest") or "-"
                pkg_type = row.get("package_type") or "-"
                html.append(
                    "<tr>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><b>{escape(row['name'])}</b></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(current)}</code></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(wanted)}</code></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(latest)}</code></td>"
                    f"<td style='padding:10px;border-bottom:1px solid #eef2f7;vertical-align:top;'><code>{escape(pkg_type)}</code></td>"
                    "</tr>"
                )
            html.append("</tbody></table></div>")

    if dj["ran"] and not dj["ok"]:
        err = (dj["stdout"] + "\n" + dj["stderr"]).strip()[:3000]
        html.append(
            "<div style='margin-top:14px;'>"
            "<div style='font-size:16px;font-weight:700;margin-bottom:8px;color:#991b1b;'>Django check output</div>"
            f"<pre style='white-space:pre-wrap;background:#0f172a;color:#e2e8f0;padding:14px;border-radius:12px;overflow:auto;font-size:12px;'>{escape(err)}</pre>"
            "</div>"
        )

    notes = []
    notes.extend([x for x in app["req_notes"] if x])
    if app["env_note"]:
        notes.append(app["env_note"])
    if frontend["enabled"]:
        if frontend["audit"].get("stderr"):
            notes.append(f"frontend npm audit ({frontend['audit'].get('cmd', 'npm audit --json')}): {frontend['audit']['stderr'].strip()}")
        if frontend["outdated"].get("stderr"):
            notes.append(f"frontend npm outdated ({frontend['outdated'].get('cmd', 'npm outdated --json')}): {frontend['outdated']['stderr'].strip()}")

    if notes:
        html.append("<div style='margin-top:14px;'><div style='font-size:15px;font-weight:700;margin-bottom:8px;'>Notes</div><ul style='margin:0;padding-left:20px;'>")
        for note in notes:
            html.append(f"<li style='margin-bottom:6px;'>{escape(note)}</li>")
        html.append("</ul></div>")

    html.append("</div>")

html.append(
    "<div style='font-size:12px;color:#64748b;margin-top:18px;padding:12px;'>"
    "This report consolidates requirement-file and .venv vulnerability findings per app so Python packages are not shown twice. "
    "For Python vulnerabilities, the latest column comes from pip list --outdated when available. "
    "For frontend vulnerabilities, current/wanted/latest versions are joined from npm outdated when the vulnerable package is also outdated. "
    "Python runtime/version status is looked up from endoflife.date when reachable; status falls back gracefully when the catalog cannot be fetched. "
    "Vulnerability type is inferred from advisory text when no explicit category is present, so treat the type field as a best-effort classification. "
    "Severity depends on advisory metadata and may appear as UNKNOWN when the source does not provide enough detail."
    "</div>"
)
html.append("</div></body></html>")
HTML_REPORT.write_text("".join(html), encoding="utf-8")

msg = EmailMessage()
msg["From"] = MAIL_FROM
msg["To"] = MAIL_TO
msg["Subject"] = SUBJECT
msg.set_content(TEXT_REPORT.read_text(encoding="utf-8"))
msg.add_alternative(HTML_REPORT.read_text(encoding="utf-8"), subtype="html")

if ARGS.dry_run:
    print("Dry run enabled, reports generated but not emailed.")
    print(f"TXT report:  {TEXT_REPORT}")
    print(f"HTML report: {HTML_REPORT}")
    sys.exit(0)

try:
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.send_message(msg)
except Exception as exc:
    print("Report created but mail sending failed.", file=sys.stderr)
    print(f"TXT: {TEXT_REPORT}", file=sys.stderr)
    print(f"HTML: {HTML_REPORT}", file=sys.stderr)
    print(f"SMTP error: {exc}", file=sys.stderr)
    sys.exit(1)

print(f"Report sent to {MAIL_TO} via {SMTP_HOST}:{SMTP_PORT}")
print(f"TXT report:  {TEXT_REPORT}")
print(f"HTML report: {HTML_REPORT}")
