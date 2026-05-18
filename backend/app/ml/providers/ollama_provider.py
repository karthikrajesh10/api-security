import ollama
import httpx
from typing import Optional
from app.ml.base import BaseModelProvider
from app.core.config import settings

class OllamaProvider(BaseModelProvider):
    """
    Local model provider using Ollama.
    Models run entirely on your machine — no data leaves.
    """

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.embed_model = settings.OLLAMA_EMBED_MODEL
        self.llm_model = settings.OLLAMA_LLM_MODEL
        self.client = ollama.AsyncClient(host=self.base_url)

    async def embed(self, text: str) -> list[float]:
        try:
            response = await self.client.embeddings(
                model=self.embed_model,
                prompt=text
            )
            return response["embedding"]
        except Exception as e:
            raise RuntimeError(f"Ollama embed failed: {e}")

    async def complete(self, prompt: str, system: Optional[str] = None) -> str:
        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            response = await self.client.chat(
                model=self.llm_model,
                messages=messages
            )
            return response["message"]["content"]
        except Exception as e:
            raise RuntimeError(f"Ollama completion failed: {e}")

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(f"{self.base_url}/api/tags", timeout=3)
                return r.status_code == 200
        except Exception:
            return False