````markdown
# Predictive Risk Assessment System

## Setup Instructions

### 1. Activate Virtual Environment

#### Windows PowerShell
```powershell
.\venv\Scripts\Activate.ps1
```

#### Git Bash
```bash
source venv/Scripts/activate
```

---

## 2. Install Dependencies

```powershell
pip install -r requirements.txt
```

---

## 3. Generate Enriched Trivy Output

If you need to regenerate the enriched Trivy output:

```powershell
python trivy_runner.py
```

This produces:

```text
enriched_trivy_output.json
```

which is used as the input for Pipeline A.

---

## 4. Run Pipeline A

### Default Run
Uses:
- Ollama backend
- Scans the `test/` directory

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test
```

---

### Specify Exact Ollama Model

Example using Qwen 2.5 7B:

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test --ollama-model qwen2.5:7b
```

---

### Using Gemini Backend Instead of Ollama

```powershell
python pipeline_a.py --input enriched_trivy_output.json --project-dir ./test --llm gemini
```
````
