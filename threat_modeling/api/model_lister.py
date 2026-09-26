"""Model Lister - List available models from OpenAI, Google, and Anthropic APIs."""
from typing import List, Dict, Optional
import openai
from google import genai
from anthropic import Anthropic


def list_openai_models(api_key: Optional[str] = None) -> List[Dict[str, str]]:
    """
    List available OpenAI models.
    
    Args:
        api_key: OpenAI API key
        
    Returns:
        List of dictionaries with 'id' and 'name' keys
    """
    try:
        client = openai.OpenAI(api_key=api_key) if api_key else openai.OpenAI()
        models = client.models.list()

        # The gpt-/o1-/o3- prefix filter only makes sense against OpenAI itself.
        # When OPENAI_BASE_URL points at an OpenAI-compatible provider (OpenRouter,
        # Groq, GitHub Models...), model ids look like "vendor/model:free" and the
        # filter would drop every one of them, leaving the dropdown empty.
        base_url = str(getattr(client, "base_url", "") or "")
        is_openai = "api.openai.com" in base_url or not base_url

        if is_openai:
            chat_models = [
                {'id': model.id, 'name': model.id}
                for model in models.data
                if model.id.startswith('gpt-') or model.id.startswith('o1-') or model.id.startswith('o3-')
            ]
        else:
            chat_models = [{'id': model.id, 'name': model.id} for model in models.data]

        return sorted(chat_models, key=lambda x: x['id'])
    except Exception as e:
        raise Exception(f"Error listing OpenAI models: {str(e)}")


def list_ollama_models(server_url: Optional[str] = None) -> List[Dict[str, str]]:
    """
    List models available on a local/remote Ollama server.

    LLMClient already supports the "OLLAMA" provider, but there was no lister
    for it, so the UI had no way to populate the model dropdown.

    Args:
        server_url: Ollama base URL; defaults to OLLAMA_URL from settings.

    Returns:
        List of dictionaries with 'id' and 'name' keys
    """
    import json
    import os
    import urllib.request

    base = (server_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=10) as response:
            data = json.loads(response.read())
        models = [
            {'id': m['name'], 'name': m['name']}
            for m in data.get('models', [])
            if m.get('name')
        ]
        return sorted(models, key=lambda x: x['id'])
    except Exception as e:
        raise Exception(f"Error listing Ollama models at {base}: {str(e)}")


def list_google_models(api_key: Optional[str] = None) -> List[Dict[str, str]]:
    """
    List available Google models.
    
    Args:
        api_key: Google API key
        
    Returns:
        List of dictionaries with 'id' and 'name' keys
    """
    try:
        client = genai.Client(api_key=api_key) if api_key else genai.Client()
        
        # List base models
        models_pager = client.models.list(config={'query_base': True})
        models_list = []
        
        for model in models_pager:
            # Extract model name from full path (e.g., "publishers/google/models/gemini-2.0-flash-exp" -> "gemini-2.0-flash-exp")
            model_name = model.name.split('/')[-1] if '/' in model.name else model.name
            models_list.append({
                'id': model_name,
                'name': model.display_name or model_name
            })
        
        return sorted(models_list, key=lambda x: x['id'])
    except Exception as e:
        raise Exception(f"Error listing Google models: {str(e)}")


def list_anthropic_models(api_key: Optional[str] = None) -> List[Dict[str, str]]:
    """
    List available Anthropic models.
    
    Args:
        api_key: Anthropic API key (used for validation if provided)
        
    Returns:
        List of dictionaries with 'id' and 'name' keys
    """
    # Anthropic doesn't have a direct list models API, so we return known models
    # These are the current Claude models available
    known_models = [
        {'id': 'claude-3-5-sonnet-20241022', 'name': 'Claude 3.5 Sonnet'},
        {'id': 'claude-3-5-sonnet-20240620', 'name': 'Claude 3.5 Sonnet (June)'},
        {'id': 'claude-3-opus-20240229', 'name': 'Claude 3 Opus'},
        {'id': 'claude-3-sonnet-20240229', 'name': 'Claude 3 Sonnet'},
        {'id': 'claude-3-haiku-20240307', 'name': 'Claude 3 Haiku'},
    ]
    
    # If API key is provided, validate it (optional)
    if api_key:
        try:
            client = Anthropic(api_key=api_key)
            # Just validate the client can be created, don't make unnecessary API calls
            # The actual model validation will happen when the user tries to use it
        except Exception as e:
            # If API key is invalid, still return models but they might not work
            pass
    
    return known_models

