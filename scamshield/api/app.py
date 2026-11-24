"""Owner: dashboard. STUB."""
from fastapi import FastAPI

app = FastAPI(title="ScamShield")


@app.get("/api/health")
def health():
    return {"ok": True}
