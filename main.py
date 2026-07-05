from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess, json, importlib.util, os, sys

app = FastAPI(title="RedMind-AI VAPT Scanner")

# Allow browser fetch from the dashboard HTML (file:// or same origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the frontend folder so dashboard.html is accessible as a static file
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# ── Root: serve the new dashboard ──────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home():
    path = os.path.join(os.path.dirname(__file__), "frontend", "dashboard.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


# ── /run  — execute a single check module ──────────────────────────────────
class RunRequest(BaseModel):
    module_id: str
    target: str
    context: dict = {}


@app.post("/run")
def run_module(req: RunRequest):
    module_path = os.path.join(
        os.path.dirname(__file__), "modules", f"{req.module_id}.py"
    )

    if not os.path.exists(module_path):
        return {"error": f"Module {req.module_id} not found", "result": None}

    try:
        spec = importlib.util.spec_from_file_location(req.module_id, module_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        result = mod.run(
            target=req.target,
            timeout=10,
            dangerous=True,
        )
        return {"module_id": req.module_id, "result": result}

    except Exception as e:
        return {
            "module_id": req.module_id,
            "result": {
                "check_id": req.module_id,
                "severity": "INFO",
                "target": req.target,
                "findings": [],
                "error": str(e),
                "summary": {"tested_requests": 0, "positive_hits": 0},
            }
        }


# ── /ws  — legacy WebSocket scan endpoint (kept for compatibility) ──────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    data   = await ws.receive_json()
    target = data.get("target")

    await ws.send_json({"progress": 10, "msg": "Scan started..."})

    proc = subprocess.run(
        [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-NoProfile",
            "-File", "run_all_modules.ps1",
            "-Target", target,
            "-Checks", "checks_runtime.json",
        ],
        capture_output=True,
        text=True,
    )

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    await ws.send_json({"progress": 80, "msg": f"--- RAW STDOUT ---\n{stdout}"})
    if stderr:
        await ws.send_json({"progress": 85, "msg": f"--- RAW STDERR ---\n{stderr}"})

    try:
        parsed = json.loads(stdout)
        await ws.send_json({"progress": 100, "msg": "JSON parsed successfully ✔"})
        await ws.send_json({"msg": json.dumps(parsed, indent=2)})
    except Exception as e:
        await ws.send_json({"progress": 100, "msg": f"[ERROR] JSON parse failed: {e}"})

    await ws.close()
