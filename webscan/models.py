from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    check: str
    title: str
    severity: str  # HIGH, MEDIUM, LOW, INFO
    description: str
    recommendation: str
    evidence: str = ""

    def to_dict(self):
        return asdict(self)
