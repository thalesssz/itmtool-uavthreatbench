# ITA Threat Modeling Tool — Architecture

## Overview

The **ITA Threat Modeling Tool (ITA TMT)** is a web application for automated threat analysis. It uses AI (LLMs) to process threat models from the Microsoft Threat Modeling Tool (.tm7 files) and produces structured security analyses with STRIDE classification and NIST 800-53 control suggestions. The application is built with **Flask** and supports multiple LLM providers (OpenAI, Google, Anthropic, Ollama) and optional RAG enhancement via ChromaDB.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                            │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │         Flask Web Application (threat_modeling.web)         │   │
│  │  • File upload (.tm7)                                        │   │
│  │  • System description                                        │   │
│  │  • Diagram selection (if multiple)                          │   │
│  │  • Analysis configuration (provider, model, prompts)       │   │
│  │  • Results view, comparison, RAG enhance, download          │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                           │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ ThreatModel  │  │  Analysis    │  │  Comparison  │          │
│  │   Service    │  │   Service    │  │   Service    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐                                                │
│  │ RAG Service  │  (NIST controls retrieval + LLM)              │
│  └──────────────┘                                                │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  API: LLMClient, message_builder, model_lister             │   │
│  │  Models: TM7Parser, threat_model (dataclasses), Pydantic   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     EXTERNAL SERVICES                             │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   OpenAI     │  │   Google     │  │  Anthropic   │          │
│  │   API        │  │   Gemini     │  │   Claude     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────────────────────────────┐   │
│  │   Ollama     │  │  ChromaDB (RAG: NIST controls)        │   │
│  │  (local)     │  │  • HTTP client, configurable host/port │   │
│  └──────────────┘  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
itmt_/
├── app.py                    # Optional entry: exposes Flask app for "flask run"
├── run_flask.py              # Main entry: creates app and runs server
├── requirements.txt
├── Dockerfile
├── docker-compose.yaml
├── example_env                # Template for .env
├── blocks/                   # Prompt templates
│   ├── main_content.txt
│   ├── fs.txt                # Few-shot examples
│   ├── cot.txt               # Chain-of-thought instructions
│   └── json_output.txt
└── threat_modeling/
    ├── __init__.py
    ├── coverage_cli.py       # CLI: reference coverage across threat sources
    ├── config/
    │   ├── __init__.py
    │   └── settings.py       # Env-based config (API keys, RAG, paths)
    ├── models/
    │   ├── __init__.py
    │   ├── threat_model.py   # Dataclasses: ThreatModelTM7, DiagramTM7, etc.
    │   ├── parser.py         # TM7Parser, dataflows_to_json, etc.
    │   ├── rag_models.py     # Pydantic: RAGResponse
    │   └── comparison_models.py  # Pydantic: ThreatComparisonResponse
    ├── api/
    │   ├── __init__.py
    │   ├── llm_client.py     # LLMClient (invoke, invoke_batch, invoke_with_structure)
    │   ├── message_builder.py # Prompts for analysis, RAG, comparison
    │   ├── model_lister.py   # list_openai_models, list_google_models, list_anthropic_models
    │   └── providers/
    │       ├── openai_provider.py
    │       ├── google_provider.py
    │       ├── anthropic_provider.py
    │       └── ollama_provider.py
    ├── services/
    │   ├── __init__.py
    │   ├── threat_model_service.py  # Parse .tm7, get diagram/threat JSON, validate
    │   ├── analysis_service.py      # Run analysis, build DataFrame from results
    │   ├── rag_service.py           # ChromaDB search, RAG enhance, parse RAGResponse
    │   ├── comparison_service.py    # Compare TMT vs AI threats, LLM-based similarity
    │   ├── coverage_service.py      # Reference coverage across threat sources (LLM judge)
    │   └── judging.py               # Runs many judge calls: memory, parallel calls, failures reported
    ├── web/
    │   ├── __init__.py
    │   ├── app.py            # create_app(): Flask factory, session, blueprint
    │   ├── forms.py          # FileUploadForm, AnalysisForm, RAGEnhancementForm
    │   ├── routes.py         # main_bp: index, select_diagram, analyze, results, compare, RAG, download
    │   └── templates/        # Jinja2: base, index, select_diagram, analyze, results, compare
    └── static/
        ├── css/custom.css
        └── js/main.js
```

## Main Components

### 1. Presentation Layer

- **Flask app** (`threat_modeling.web.app`): Application factory; configures secret key, upload limit, session (filesystem), and registers the main blueprint.
- **Routes** (`threat_modeling.web.routes`):
  - **GET/POST /** — Upload .tm7 and system description; parse and validate; store in session; redirect to diagram selection or analyze.
  - **GET/POST /select-diagram** — When multiple diagrams exist, choose one; store selected diagram data in session.
  - **GET /analyze** — Analysis form (provider, API key, model, few-shot, chain-of-thought).
  - **POST /analyze** — Run analysis via `AnalysisService`, store results in session, redirect to results.
  - **GET /results** — Show analysis table and optional RAG column.
  - **GET /compare** — Compare TMT threats vs AI results (similar / TMT-only / AI-only) via `ComparisonService`.
  - **POST /rag-enhance** — For each threat, RAG search + LLM; add NIST controls column.
  - **GET /download/<format_type>** — Download JSON/CSV (analysis, RAG, or comparison).
- **API endpoints** (same blueprint): `/api/diagram-json/<int>`, `/api/list-models` (POST), `/api/diagram-threats/<int>`.

### 2. Application Layer — Services

- **ThreatModelService**: Parses .tm7 XML via `TM7Parser`; returns `ThreatModelTM7`; provides diagram JSON, threat JSON, diagram threats, DataFrame generation, and validation.
- **AnalysisService**: Builds prompts (main content, few-shot, CoT) via `message_builder`; uses `LLMClient` to run analysis per interaction; builds DataFrame from LLM responses (OpenAI/Anthropic JSON vs Google structured).
- **RAGService**: Connects to ChromaDB (HTTP client); uses configurable embeddings (Ollama, OpenAI, Google); similarity search; RAG enhancement uses `generate_rag_messages` and `LLMClient.invoke_with_structure(RAGResponse)`; parses response to NIST control list.
- **ComparisonService**: Pairs TMT and AI threats by (dataflow, category); for each pair calls LLM with `generate_comparison_messages` and `invoke_with_structure(ThreatComparisonResponse)`; builds DataFrame with similarity and source (both / tmt_only / ai_only).
- **CoverageService**: Checks a reference threat list (e.g. the expected threats of a benchmark scenario) against any number of threat sources (TMT threats from the .tm7, AI analysis exports, other pipelines). No dataflow/category key: every reference threat is judged against every distinct threat of each source with `generate_coverage_messages` and `invoke_with_structure(ThreatComparisonResponse)`; a reference threat is covered by a source when its best score reaches the threshold (default 0.7). Exposed through `python -m threat_modeling.coverage_cli`.
- **judging** (`judge_all`, `JudgmentCache`): shared by ComparisonService and CoverageService. Judgments already made are read from a SQLite memory in `DATA_DIR` (key: provider, model, temperature, seed and the full prompt text, so any change in prompt, scenario description or threat text is a new judgment); identical prompts in a run are judged once; the rest run through `LLMClient.map_ordered` (in parallel for paid providers, one at a time for Ollama), with retries. A call that still fails is reported (`error`, a warning on screen) and not remembered, so running again retries only it. Each judgment records the model that answered, its call id, cost (OpenRouter reports it) and time. Measured on CS-OT-UAV-0287 (695 judgments): about 2 min in parallel against about 15 min in a row, same coverage tiles; a repeated run takes 1.5 s from memory. Study: `Thales/tmt/docs/ESTUDO-OTIMIZACAO-AVALIACAO.md` in the UAVThreatBench-ITA repository.

### 3. API and Models

- **LLMClient** (`threat_modeling.api.llm_client`): Single interface for OpenAI, Google, Anthropic, Ollama. Methods: `invoke`, `invoke_batch` (parallel for paid providers, input order kept), `invoke_with_structure(pydantic_model)`, `invoke_with_structure_meta` (also returns the model that answered, call id and cost), `with_retries`, `map_ordered`; `concurrency` is 1 for Ollama and `LLM_MAX_CONCURRENCY` otherwise.
- **message_builder**: Builds system/human messages for: main analysis (with system description and JSON output format), few-shot, chain-of-thought, RAG (NIST selection), and comparison (similarity + explanation).
- **model_lister**: Lists models for OpenAI and Google via their APIs; returns fixed list for Anthropic.
- **threat_model (dataclasses)**: `ThreatModelTM7`, `DiagramTM7`, `ElementTM7`, `DataFlowTM7`, `TrustBoundaryTM7`, `ThreatTM7`, `PropertyTM7`.
- **parser**: `TM7Parser` parses .tm7 XML into `ThreatModelTM7`; helpers: `dataflows_to_json`, `threat_model_to_json`, `generate_tmt_dataframe`.
- **Pydantic**: `RAGResponse` (nist_controls list); `ThreatComparisonResponse` (is_similar, similarity_score, explanation).

### 4. Configuration

- **settings.py**: Reads from environment: API keys (OpenAI, Google), Ollama URL, default provider/model; sampling (`LLM_TEMPERATURE`, default 0, and `LLM_SEED`, default 42, applied to every provider that supports them; empty value = provider default); RAG (Chroma host/port/SSL, collection name, embedding provider/model); `DATA_DIR`, `BLOCKS_DIR`; throughput (`LLM_MAX_CONCURRENCY`, default 8, paid providers only; `LLM_MAX_RETRIES`, default 3); judgment memory (`JUDGMENT_CACHE_PATH`, default `DATA_DIR/judgment_cache.sqlite`, empty = off).
- **Environment**: Use `example_env` as template; copy to `.env` and set keys and optional overrides.

## Data Flows

### Main flow: Threat model analysis

1. User uploads .tm7 and system description.
2. `ThreatModelService.parse_tm7_file` → `TM7Parser` → `ThreatModelTM7`.
3. Validation; diagram selection if multiple; diagram JSON and threat data stored in session.
4. User selects provider, model, API key, few-shot, CoT on /analyze.
5. `AnalysisService.run_analysis`: `generate_messages(interactions)` + prompt contents → `LLMClient.invoke_batch` → list of LLM responses.
6. `AnalysisService.generate_dataframe` maps responses to rows (handling Google vs others); result stored in session.
7. User sees results on /results; can run RAG enhance or comparison, and download JSON/CSV.

### RAG enhancement flow

1. From results, user submits RAG form (e.g. k_controls=5).
2. For each analysis row: RAGService.search(category + description, k) → docs; `generate_rag_messages` → `LLMClient.invoke_with_structure(RAGResponse)` → `RAGService.parse_llm_response` → NIST controls string.
3. New column (e.g. rag_nist) stored; optional RAG-specific download.

### Comparison flow

1. From results, user opens /compare.
2. TMT threats for selected diagram and AI results DataFrame are passed to `ComparisonService.run_comparison`.
3. Pairs (TMT, AI) by (dataflow, category); each pair → comparison messages → `judge_all` (memory, parallel calls, retries) → `ThreatComparisonResponse`.
4. DataFrame with similar, TMT-only, AI-only; comparison CSV download.

### Coverage flow (CLI)

1. `coverage_cli` loads the reference threats and scenario description from a scenario JSON, the TMT threats saved in a .tm7, and extra sources from .txt/.csv/.json files.
2. `CoverageService.run_coverage`: for each reference threat × source × distinct candidate text → coverage messages → `judge_all` (memory, parallel calls, retries) → `ThreatComparisonResponse`. `--fresh` judges everything again instead of reusing the memory.
3. Outputs (tab-separated): `<out>-pairs.csv` (every judgment), `<out>-coverage.csv` (best score and covered flag per reference threat and source), `<out>-summary.csv` (covered count per source).

## Parsing flow (.tm7)

```
.tm7 XML
    │
    ▼
TM7Parser.parse()
    │
    ├── Parse Diagrams (DrawingSurfaceModel)
    │       ├── Elements (Process, External Interactor, Data Store, Trust Boundary)
    │       ├── Data Flows
    │       └── Trust Boundaries
    │
    ├── Parse Threats (ThreatInstances)
    │
    └── Parse Meta Information
            │
            ▼
    ThreatModelTM7 (dataclasses)
```

## Supported providers and features

- **OpenAI**: Chat models (gpt-*, o1-*, o3-*); list from API; structured output where supported.
- **Google**: Gemini models; list from API; structured output via provider.
- **Anthropic**: Claude models; fixed list in model_lister; JSON parsing in AnalysisService.
- **Ollama**: Local models; base_url from settings/OLLAMA_URL; no API key.

Prompt techniques: **Zero-shot** (main instructions only), **Few-shot** (examples from blocks/fs.txt), **Chain-of-thought** (blocks/cot.txt).

## RAG (ChromaDB)

- ChromaDB runs as HTTP server (e.g. docker-compose service or standalone).
- Embeddings: Ollama (e.g. qwen3-embedding:4b), OpenAI, or Google (configurable).
- Collection name can vary by provider (e.g. nist_controls_ollama).
- RAG is optional; if ChromaDB is unavailable, RAG enhance will fail unless disabled or mocked.

## Security and deployment

- **Secrets**: API keys and Flask secret from environment (e.g. `.env`); not committed.
- **Session**: Filesystem-backed; session cookie HttpOnly, SameSite Lax.
- **Upload**: Max size 16MB; only .tm7 allowed via form validation.
- **Docker**: Dockerfile runs `run_flask.py`; docker-compose runs app and ChromaDB; env vars passed for API keys and RAG.

## Dependencies (summary)

- **Flask**, Flask-WTF, Flask-Session, Werkzeug — web and forms.
- **LangChain** (langchain, langchain-core, langchain-openai, langchain-google-genai, langchain-anthropic, langchain-ollama) — LLM abstraction.
- **ChromaDB**, langchain-chroma — vector store and embeddings.
- **openai**, **anthropic**, **google-genai** — provider SDKs.
- **pandas** — DataFrames for results and comparison.
- **python-dotenv** — optional env loading.

## Possible improvements

- Add REST API for headless/CI use.
- Add authentication and authorization.
- Persist analyses and history in a database.
- Parallelize analysis and comparison calls.
- Cache RAG and comparison results.
- Add structured logging and metrics.
