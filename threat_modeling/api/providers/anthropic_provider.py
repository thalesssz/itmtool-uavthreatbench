"""Anthropic provider - ChatAnthropic client for Claude models."""
from langchain_anthropic import ChatAnthropic
from typing import Optional

from ...config.settings import LLM_TEMPERATURE


def create_anthropic_client(model_name: str, api_key: Optional[str] = None) -> ChatAnthropic:
    """
    Create an Anthropic ChatAnthropic client.
    
    Args:
        model_name: Name of the model to use
        api_key: Anthropic API key (optional, can use env var)
        
    Returns:
        ChatAnthropic instance configured for JSON output
    """
    # ChatAnthropic has no seed parameter; temperature alone is the best available.
    return ChatAnthropic(
        model=model_name,
        api_key=api_key,
        temperature=LLM_TEMPERATURE
    )

