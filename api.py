import os
import logging

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse

from main import load_model, analyze_email_raw

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ScamShield API", version="1.0.0")

# ML model loaded once at startup
_model = None

API_KEY = os.getenv("SCAMSHIELD_API_KEY")  # optional — set env var to enforce auth


@app.on_event("startup")
def startup():
    global _model
    logger.info("Loading ScamShield ML model...")
    _model = load_model()
    logger.info("Model loaded successfully.")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model is not None}


@app.post("/analyze")
async def analyze(request: Request, x_api_key: str = Header(default=None)):
    """
    Accepts a raw RFC 2822 email as the request body (Content-Type: text/plain
    or message/rfc822) and returns a JSON analysis report.

    cPanel pipe script should POST the piped email to this endpoint.
    """
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Api-Key header")

    body_bytes = await request.body()
    if not body_bytes:
        raise HTTPException(status_code=400, detail="Request body is empty")

    raw_email = body_bytes.decode("utf-8", errors="replace")
    if not raw_email.strip():
        raise HTTPException(status_code=400, detail="Email content is empty")

    try:
        report = analyze_email_raw(raw_email, _model)
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))

    return JSONResponse(content=report)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port)
