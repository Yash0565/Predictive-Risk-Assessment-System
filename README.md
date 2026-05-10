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