from typing import Optional
from app.config import ANALYZER_MODE
from app.analyzers.execution.base import BaseAnalyzerRunner
from app.analyzers.execution.local_runner import LocalAnalyzerRunner
from app.analyzers.execution.docker_runner import DockerAnalyzerRunner

def get_analyzer_runner(mode: Optional[str] = None) -> BaseAnalyzerRunner:
    """
    Factory function to instantiate the configured Analyzer Runner.
    Supported modes: 'local' (default) | 'docker'.
    """
    target_mode = (mode or ANALYZER_MODE).lower().strip()

    if target_mode == "docker":
        return DockerAnalyzerRunner()
    else:
        return LocalAnalyzerRunner()
