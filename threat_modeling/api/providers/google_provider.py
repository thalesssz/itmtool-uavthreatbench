"""Google provider - ChatGoogleGenerativeAI client with optional structured output."""
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel
from typing import Optional

from ...config.settings import LLM_TEMPERATURE, LLM_SEED


class Threat(BaseModel):
    """Single threat entry for Google structured output (ThreatModel)."""
    Category: str
    Description: str
    Justification: str
    Potential_Impact: str
    NIST_800_53_Controls: list[str]


class ThreatModel(BaseModel):
    """Wrapper for a list of Threat entries (Google structured output)."""
    threat_model: list[Threat]


def create_google_client(model_name: str, api_key: Optional[str] = None, with_structure: bool = True) -> ChatGoogleGenerativeAI:
    """
    Create a Google ChatGoogleGenerativeAI client.
    
    Args:
        model_name: Name of the model to use
        api_key: Google API key (optional, can use env var)
        with_structure: If True, apply structured output with ThreatModel (default: True)
        
    Returns:
        ChatGoogleGenerativeAI instance, optionally with structured output
    """
    llm = ChatGoogleGenerativeAI(
        model=model_name,
        api_key=api_key,
        temperature=LLM_TEMPERATURE,
        seed=LLM_SEED
    )
    if with_structure:
        return llm.with_structured_output(ThreatModel)
    return llm

