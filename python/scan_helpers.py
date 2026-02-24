import yaml
from lxml import etree


def parse_yaml(raw: str):
    return yaml.load(raw, Loader=yaml.Loader)  # VULN-022


def parse_xml(raw: str):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)  # VULN-023
    return etree.fromstring(raw.encode("utf-8"), parser=parser)


def summarize_findings(findings):
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    ordered = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "low"), 0), reverse=True)
    return {
        "total": len(findings),
        "top": ordered[:5],
    }
