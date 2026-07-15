from myrecon.modules.subdomain import SubdomainModule
from myrecon.modules.probing import ProbingModule
from myrecon.modules.portscan import PortscanModule
from myrecon.modules.screenshot import ScreenshotModule
from myrecon.modules.dirbrute import DirbruteModule
from myrecon.modules.cloud_enum import CloudEnumModule
from myrecon.modules.js_discovery import JsDiscoveryModule
from myrecon.modules.url_collection import UrlCollectionModule
from myrecon.modules.vuln_scan import VulnScanModule
from myrecon.modules.github_recon import GithubReconModule

ALL_MODULES = {
    "subdomain": SubdomainModule,
    "probing": ProbingModule,
    "portscan": PortscanModule,
    "screenshot": ScreenshotModule,
    "dirbrute": DirbruteModule,
    "cloud_enum": CloudEnumModule,
    "js_discovery": JsDiscoveryModule,
    "url_collection": UrlCollectionModule,
    "vuln_scan": VulnScanModule,
    "github_recon": GithubReconModule,
}
