"""Configuration settings for the Threat Modeling Tool (env-based)."""
import os


# API Keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

# Provider Configuration
# Options: "OPENAI", "GOOGLE", "OLLAMA"
DEFAULT_PROVIDER = "OLLAMA"

# Available Models
MODELS = [
    # lower medium class
    "gemma3:27b",
    "qwen3:30b",
    "gpt-oss:20b",
    # lower class
    "gemma3:12b",
    "qwen3:8b",
    "mistral:7b",
]

DEFAULT_MODEL = MODELS[4]  # qwen3:8b

# Sampling
# Comparing prompt versions needs reproducible runs. With the provider default
# temperature (usually 0.7-0.8) the same prompt on the same interaction returns
# different threats from one run to the next. LLM_TEMPERATURE="" falls back to
# the provider default (some reasoning models only accept 1); LLM_SEED="" sends
# no seed. Providers that do not support a seed simply do not receive it.
def _optional_number(name: str, default: str, cast):
    value = os.getenv(name, default).strip()
    return cast(value) if value else None


LLM_TEMPERATURE = _optional_number("LLM_TEMPERATURE", "0", float)
LLM_SEED = _optional_number("LLM_SEED", "42", int)

# RAG Configuration
RAG_CHROMA_HOST = os.getenv("RAG_CHROMA_HOST", "localhost")
RAG_CHROMA_PORT = int(os.getenv("RAG_CHROMA_PORT", "8000"))
RAG_CHROMA_SSL = os.getenv("RAG_CHROMA_SSL", "false").lower() == "true"
RAG_COLLECTION_NAME = os.getenv("RAG_COLLECTION_NAME", "nist_controls_summarized")
RAG_EMBEDDING_PROVIDER = os.getenv("RAG_EMBEDDING_PROVIDER", "OLLAMA")  # Options: "OLLAMA", "OPENAI", "GOOGLE"
RAG_EMBEDDING_MODEL = os.getenv("RAG_EMBEDDING_MODEL", "qwen3-embedding:4b")

# Data paths
DATA_DIR = "./data"
BLOCKS_DIR = "./blocks"



# Paid model used by the "run with the paid model" buttons. The key stays on the
# server, so nobody has to paste it into the screen during a demo, and a free
# local run can be compared with a paid one side by side.
PAID_PROVIDER = os.getenv("PAID_PROVIDER", "OPENAI")
PAID_API_KEY = os.getenv("PAID_API_KEY") or OPENAI_API_KEY

# In paid mode the analyst and the judge are different models, so no model
# grades its own output. A reasoning model is worth it for the few analysis
# calls but too expensive as a judge, which runs hundreds of short calls.
PAID_ANALYST_MODEL = os.getenv("PAID_ANALYST_MODEL", "openai/gpt-5")
PAID_JUDGE_MODEL = os.getenv("PAID_JUDGE_MODEL", "google/gemini-2.5-flash")
