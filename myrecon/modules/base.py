import logging
from abc import ABC, abstractmethod
from myrecon.models import Scan, Finding

logger = logging.getLogger("myrecon")


class BaseModule(ABC):
    name: str = ""
    description: str = ""
    dependencies: list[str] = []

    def __init__(self):
        if not self.name:
            self.name = self.__class__.__name__.lower().replace("module", "")

    @abstractmethod
    async def run(self, scan: Scan) -> list[Finding]:
        pass

    def make_finding(self, **kwargs) -> Finding:
        kwargs.setdefault("module", self.name)
        return Finding(**kwargs)
