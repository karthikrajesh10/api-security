from abc import ABC, abstractmethod
from typing import Optional

class BaseModelProvider(ABC):
    """
    Abstract interface for all ML/LLM providers.
    Any provider (Ollama, OpenAI, HuggingFace, etc.)
    must implement these three methods.
    """

    @abstractmethod
    async def embed(self, text: str) -> list[float]:
        """
        Convert text into a vector embedding.
        Used for: traffic log similarity, anomaly detection.
        """
        pass

    @abstractmethod
    async def complete(self, prompt: str, system: Optional[str] = None) -> str:
        """
        Generate a text completion.
        Used for: analysis summaries, remediation suggestions.
        """
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """
        Health check — is this provider reachable?
        """
        pass