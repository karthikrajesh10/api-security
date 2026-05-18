from app.ml.base import BaseModelProvider
from app.core.config import settings

def get_model_provider() -> BaseModelProvider:
    """
    Returns the correct provider based on MODEL_PROVIDER in .env
    
    To switch providers:
      1. Change MODEL_PROVIDER in .env
      2. Add any required API keys to .env
      3. Restart the server — that's it.
    """
    provider = settings.MODEL_PROVIDER.lower()

    if provider == "ollama":
        from app.ml.providers.ollama_provider import OllamaProvider
        return OllamaProvider()

    elif provider == "openai":
        from app.ml.providers.openai_provider import OpenAIProvider
        return OpenAIProvider()

    else:
        raise ValueError(
            f"Unknown MODEL_PROVIDER: '{provider}'. "
            f"Valid options: ollama, openai"
        )

# Singleton instance — imported everywhere in the app
model_provider: BaseModelProvider = get_model_provider()