from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import json

try:
    from backend.pipeline.orchestrator import PipelineOrchestrator
    from backend.data.feature_store import FeatureStore
    from backend.data.audit_logger import AuditLogger
except ImportError:
    PipelineOrchestrator = None
    FeatureStore = None
    AuditLogger = None

app = FastAPI(title="MobileGuard AI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = None
if PipelineOrchestrator:
    orchestrator = PipelineOrchestrator()

feature_store = FeatureStore() if FeatureStore else None
audit_logger = AuditLogger() if AuditLogger else None

@app.get("/health")
async def health_check():
    return {
        "status": "ok", 
        "version": "1.0.0",
        "model_loaded": orchestrator.risk_scorer.xgb_model is not None if orchestrator else False,
        "sandbox_available": orchestrator.dynamic_analyzer.use_live_sandbox if orchestrator else False
    }

@app.post("/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    if not file.filename.endswith('.apk'):
        raise HTTPException(status_code=422, detail="File must be an APK")
        
    apk_bytes = await file.read()
    
    # 150MB limit check
    if len(apk_bytes) > 150 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large")

    def event_generator():
        if orchestrator:
            for event in orchestrator.analyze(apk_bytes, file.filename):
                yield f"data: {event.to_json()}\n\n"
        else:
            yield f"data: {{\"stage\": \"error\", \"error\": \"Orchestrator not initialized\"}}\n\n"
            
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/audit-log")
async def get_audit_log(limit: int = 50, offset: int = 0):
    if not feature_store:
        return {"entries": []}
    entries = feature_store.list(limit=limit, offset=offset)
    return {"entries": entries}

@app.get("/analysis/{apk_hash}")
async def get_analysis(apk_hash: str):
    if not feature_store:
        raise HTTPException(status_code=503, detail="Cache unavailable")
    result = feature_store.get(apk_hash)
    if not result:
        raise HTTPException(status_code=404, detail="Not found in cache")
    return result

@app.delete("/cache/{apk_hash}")
async def delete_cache(apk_hash: str):
    if not feature_store:
        raise HTTPException(status_code=503, detail="Cache unavailable")
    feature_store.delete(apk_hash)
    return {"status": "ok"}
