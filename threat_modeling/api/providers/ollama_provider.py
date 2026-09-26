"""Ollama provider - ChatOllama client for local models (JSON format)."""
from langchain_ollama import ChatOllama
from typing import Optional

from ...config.settings import LLM_TEMPERATURE, LLM_SEED


def create_ollama_client(model_name: str, server_ip: Optional[str] = None) -> ChatOllama:
    """
    Create an Ollama ChatOllama client.
    
    Args:
        model_name: Name of the model to use
        server_ip: Base URL for Ollama server (optional, can use env var)
        
    Returns:
        ChatOllama instance configured for JSON output
    """
    # Callers (routes.py, analysis_service.py) pass server_ip=None, and
    # ChatOllama then defaults to http://localhost:11434. Inside a container
    # that resolves to the container itself, so the call fails with
    # "[Errno 111] Connection refused" even with Ollama running on the host.
    # Falling back to OLLAMA_URL is what the docstring already promised.
    import os

    base_url = server_ip or os.getenv("OLLAMA_URL") or "http://localhost:11434"

    return ChatOllama(
        model=model_name,
        base_url=base_url,
        format="json",
        temperature=LLM_TEMPERATURE,
        seed=LLM_SEED
    )

