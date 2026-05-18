# Predictive Risk Assessment System

## Prerequisites

### Install Ollama

Download and install Ollama from:
[Ollama Official Website](https://ollama.com)

After installation, verify:

```bash
ollama --version
```

---

## Pull Required Ollama Model

Example using Qwen 2.5 7B:

```bash
ollama pull qwen2.5:7b
```

You can use other Ollama-supported models as well.

---

## Create Environment File

Create a `.env` file in the project root:

```env
GOOGLE_API_KEY=your_gemini_api_key
```

This is required only when using the Gemini backend.

---

# Setup Instructions

## 1. Create Virtual Environment

```powershell
python -m venv venv
```

---

## 2. Activate Virtual Environment

### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

### Git Bash

```bash
source venv/Scripts/activate
```

---

## 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

---

## 4. Generate Enriched Trivy Output

If you need to regenerate the enriched Trivy output:

```powershell
python trivy_runner.py
```

This generates:

```text
enriched_trivy_output.json
```

which is used as the input for Pipeline A.

---

# Running Pipeline A

## Default Run

Uses:

- Ollama backend
- Scans the `test/` directory

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test
```

---

## Specify Exact Ollama Model

Example using Qwen 2.5 7B:

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test --ollama-model qwen2.5:7b
```

---

## Using Gemini Backend Instead of Ollama

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test --llm gemini
```

---

# Presentation Demo (Phases 1–9, no LLM)

Uses frozen Trivy input, handcrafted Semgrep rules, offline EPSS/KEV, and optional Neo4j.

```powershell
# 1. Start Neo4j (optional — pipeline falls back to graph_snapshot.json)
docker compose up -d

# 2. Install graph/report dependencies
pip install -r requirements-graph.txt

# 3. Run full demo pipeline
python pipeline_a.py --demo --project-dir ./test --services services.yaml --output-dir ./demo_out

# 4. Open HTML report
start .\demo_out\risk_report.html

# 5. Future-work agent stub (mocked, no LLM)
python -m src.agent

# 6. Tear down Neo4j
docker compose down
```

If Neo4j is not running, the pipeline still completes using the JSON graph snapshot.

Skip graph phases: add `--no-graph`.