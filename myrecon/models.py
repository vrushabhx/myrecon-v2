import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ModuleStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    module: str
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    target: str = ""
    evidence: str = ""
    raw_output: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ModuleResult(BaseModel):
    name: str
    status: ModuleStatus = ModuleStatus.PENDING
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    findings_count: int = 0
    output_files: list[str] = Field(default_factory=list)
    error: Optional[str] = None


class ScanRequest(BaseModel):
    domain: str
    modules: list[str] = Field(default_factory=list)
    excluded_subdomains: list[str] = Field(default_factory=list)
    wordlist: str = ""
    blind_xss: str = ""
    ssrf_url: str = ""
    notify: bool = True


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    domain: str
    status: ScanStatus = ScanStatus.QUEUED
    modules_requested: list[str] = Field(default_factory=list)
    module_results: dict[str, ModuleResult] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    live_hosts: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    scan_dir: str = ""
    config: dict = Field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def set_module_status(self, module: str, status: ModuleStatus, error: str = None):
        if module not in self.module_results:
            self.module_results[module] = ModuleResult(name=module)
        self.module_results[module].status = status
        if error:
            self.module_results[module].error = error
        if status == ModuleStatus.RUNNING:
            self.module_results[module].started_at = datetime.utcnow().isoformat()
        elif status in (ModuleStatus.COMPLETED, ModuleStatus.FAILED):
            self.module_results[module].finished_at = datetime.utcnow().isoformat()
