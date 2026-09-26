"""OpenAI provider - ChatOpenAI client with JSON output."""
from langchain_openai import ChatOpenAI
from typing import Optional

from ...config.settings import LLM_TEMPERATURE, LLM_SEED


def create_openai_client(model_name: str, api_key: Optional[str] = None) -> ChatOpenAI:
    """
    Create an OpenAI ChatOpenAI client.
    
    Args:
        model_name: Name of the model to use
        api_key: OpenAI API key (optional, can use env var)
        
    Returns:
        ChatOpenAI instance configured for JSON output
    """
    return ChatOpenAI(
        model=model_name,
        model_kwargs={"response_format": {"type": "json_object"}},
        api_key=api_key,
        temperature=LLM_TEMPERATURE,
        seed=LLM_SEED
    )

