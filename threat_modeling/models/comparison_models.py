"""Pydantic models for threat comparison responses (TMT vs AI)."""
from pydantic import BaseModel, Field
from typing import Optional


class ThreatComparisonResponse(BaseModel):
    """
    Structured LLM response when comparing two threat descriptions (similarity + explanation).

    Used with invoke_with_structure for consistent comparison output across providers.
    """
    is_similar: bool = Field(
        ...,
        description="Whether the two threat descriptions are similar (True) or different (False)"
    )
    similarity_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Similarity score between 0.0 (completely different) and 1.0 (identical)"
    )
    explanation: str = Field(
        ...,
        description="Explanation of why the threats are considered similar or different"
    )

    # No json_schema_extra example here: the schema can reach the model through
    # structured output, and a literal example score (it used to be 0.85) is
    # exactly the value small models were returning for every pair.

