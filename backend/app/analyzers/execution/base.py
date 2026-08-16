from abc import ABC, abstractmethod
from typing import List, Tuple
from app.models.findings import Finding

class BaseAnalyzerRunner(ABC):
    """
    Abstract interface for static analyzer execution (Local host vs Isolated Docker container).
    """

    @property
    @abstractmethod
    def execution_mode(self) -> str:
        """Return execution mode identifier ('local' | 'docker')."""
        pass

    @abstractmethod
    def run_bandit(self, code: str, filename: str = "input.py") -> Tuple[List[Finding], bool, str]:
        """
        Execute Bandit static analysis.
        Returns Tuple[List[Finding], success_flag: bool, error_message: str].
        """
        pass

    @abstractmethod
    def run_semgrep(self, code: str, filename: str = "input.py") -> Tuple[List[Finding], bool, str]:
        """
        Execute Semgrep static analysis.
        Returns Tuple[List[Finding], success_flag: bool, error_message: str].
        """
        pass
