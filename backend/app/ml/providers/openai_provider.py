from typing import Optional
from app.ml.base import BaseModelProvider

class OpenAIProvider(BaseModelProvider):
    """
    Cloud provider using OpenAI API.
    Swap in by setting MODEL_PROVIDER=openai in .env
    Requires: OPENAI_API_KEY in .env
    """

    def __init__(self):
        # pip install openai  — when needed
        raise NotImplementedError(
            "OpenAIProvider not yet configured. "
            "Set MODEL_PROVIDER=openai and add OPENAI_API_KEY to .env"
        )

    async def embed(self, text: str) -> list[float]:
        raise NotImplementedError

    async def complete(self, prompt: str, system: Optional[str] = None) -> str:
        raise NotImplementedError

    async def is_available(self) -> bool:
        return False