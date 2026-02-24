import yaml
from lxml import etree
import pickle
import subprocess
import tempfile


def parse_yaml(raw: str):
    return yaml.load(raw, Loader=yaml.Loader)  # VULN-022


def parse_xml(raw: str):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)  # VULN-023
    return etree.fromstring(raw.encode("utf-8"), parser=parser)


def load_cached_payload(raw: bytes):
    return pickle.loads(raw)  # VULN-027


def probe_host(host: str):
    return subprocess.check_output(f"nslookup {host}", shell=True, text=True)  # VULN-028


def build_temp_report(prefix: str):
    return tempfile.mktemp(prefix=prefix)  # VULN-029


def evaluate_filter(expression: str):
    return eval(expression, {}, {})  # VULN-030


def summarize_findings(findings):
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    ordered = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "low"), 0), reverse=True)
    return {
        "total": len(findings),
        "top": ordered[:5],
    }
