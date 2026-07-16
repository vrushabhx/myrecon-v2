import logging
from abc import ABC, abstractmethod
from typing import Callable, Optional
from myrecon.models import Scan, Finding

logger = logging.getLogger("myrecon")


class BaseModule(ABC):
    name: str = ""
    description: str = ""
    dependencies: list[str] = []
    _progress_callback: Optional[Callable] = None

    def __init__(self):
        if not self.name:
            self.name = self.__class__.__name__.lower().replace("module", "")

    @abstractmethod
    async def run(self, scan: Scan) -> list[Finding]:
        pass

    async def progress(self, message: str):
        logger.info(f"[{self.name}] {message}")
        if self._progress_callback:
            try:
                await self._progress_callback(message)
            except Exception:
                pass

    def make_finding(self, **kwargs) -> Finding:
        kwargs.setdefault("module", self.name)
        return Finding(**kwargs)
