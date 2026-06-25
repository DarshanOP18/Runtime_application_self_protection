# RASP Security AI Backend

FastAPI backend for a Flutter RASP app. It receives mobile threat signals, computes a deterministic risk score, stores history in SQLite, and uses a local Ollama model for explanations, chat, and remediation guidance.

No xAI/Grok key is required. No backend API key is required.

## LLM Runtime

This backend is configured for:

```text
Ollama model: qwen2.5:7b
Ollama URL:   http://127.0.0.1:11434
GPU request:  OLLAMA_NUM_GPU=999
```

`OLLAMA_NUM_GPU=999` asks Ollama to offload all possible layers to your GPU. GPU execution still depends on your local Ollama installation, GPU drivers, and available VRAM.

Install and prepare the model:

```bash
ollama pull qwen2.5:7b
ollama serve
```

Check the model directly:

```bash
ollama run qwen2.5:7b "reply with ok"
```

## Backend Setup

```bash
cd D:\DarshanProject\rasp_ai_agent\backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -m app.database.migrate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API is available at:

- Swagger UI: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/v1/security/health`

Expected health fields include:

```json
{
  "status": "healthy",
  "agent_available": true,
  "agent_mode": "local_llm",
  "llm_available": true,
  "database_connected": true,
  "model_loaded": "qwen2.5:7b"
}
```

If Ollama is not running or the model is not available, the backend still works with rule-based fallback responses and reports `agent_mode: "fallback"`.

## API Examples

Analyze a threat payload:

```bash
curl -X POST http://localhost:8000/api/v1/security/analyze ^
  -H "Content-Type: application/json" ^
  -d "{\"device_id\":\"TEST001\",\"root_detected\":true,\"frida_detected\":true}"
```

Ask the security chat:

```bash
curl -X POST http://localhost:8000/api/v1/security/chat ^
  -H "Content-Type: application/json" ^
  -d "{\"message\":\"What is Frida?\",\"session_id\":\"sess_abc123\"}"
```

Fetch threat history:

```bash
curl http://localhost:8000/api/v1/security/history/TEST001
```

## Flutter App Connection

Your Flutter app path is:

```text
D:\DarshanProject\jarvis_v2_complete\RASP\rasp_app
```

Point the app to this backend server URL. If the app runs on a physical device, use your computer's LAN IP instead of `localhost`, for example:

```text
http://192.168.1.10:8000/api/v1
```

No `X-API-Key` header is needed.

## Configuration

Important `.env` values:

```env
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_TIMEOUT=120.0
OLLAMA_MAX_RETRIES=3
OLLAMA_MAX_TOKENS=1000
OLLAMA_NUM_GPU=999
OLLAMA_KEEP_ALIVE=30m
```

## Tests

```bash
pytest -q
```
