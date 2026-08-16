import logging
from typing import List, Tuple
from app.models.findings import Finding
from app.analyzers.execution.base import BaseAnalyzerRunner
from app.analyzers.bandit_analyzer import run_bandit_analysis
from app.analyzers.semgrep_analyzer import run_semgrep_analysis

logger = logging.getLogger(__name__)

class LocalAnalyzerRunner(BaseAnalyzerRunner):
    """
    Local host execution runner for Bandit and Semgrep static analysis engines.
    """

    @property
    def execution_mode(self) -> str:
        return "local"

    def run_bandit(self, code: str, filename: str = "input.py") -> Tuple[List[Finding], bool, str]:
        try:
            findings = run_bandit_analysis(code, filename)
            return findings, True, ""
        except Exception as err:
            logger.error(f"Local Bandit execution failed: {err}")
            return [], False, str(err)

    def run_semgrep(self, code: str, filename: str = "input.py") -> Tuple[List[Finding], bool, str]:
        try:
            findings = run_semgrep_analysis(code, filename)
            return findings, True, ""
        except Exception as err:
            logger.error(f"Local Semgrep execution failed: {err}")
            return [], False, str(err)
