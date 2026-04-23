import os
import logging
import json
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse

import psycopg
from psycopg.rows import dict_row
from email.utils import parsedate_to_datetime

from main import load_model, analyze_email_raw

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres.lbounrtpongoaizuzktw:28gI51Im4cwKP7Jw@aws-0-eu-west-1.pooler.supabase.com:5432/postgres")

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

    top_from_email = report.get("top_from_email")
    if not top_from_email:
        return JSONResponse(content={"status": "skipped", "reason": "No top_from_email extracted", "report": report})

    # Query Database
    try:
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                # Check user exists (the user forwarding the email is top_from_email)
                cur.execute(
                    "SELECT id FROM users WHERE lower(email) = lower(%s)",
                    (top_from_email,)
                )
                user = cur.fetchone()

                if not user:
                    return JSONResponse(content={"status": "skipped", "reason": f"User {top_from_email} not found", "report": report})

                user_id = user["id"]
                message_id = report.get("message_id")
                if not message_id:
                    message_id = str(uuid.uuid4())

                # Parse date
                received_at = None
                date_str = report.get("date")
                if date_str:
                    try:
                        received_at = parsedate_to_datetime(date_str)
                    except Exception:
                        pass
                
                now = datetime.now(timezone.utc)

                insert_query = """
                    INSERT INTO email_submissions (
                        user_id, message_id, subject, top_from, top_from_email,
                        effective_from, effective_from_email, effective_from_domain,
                        sender_source, received_at, overall_verdict, risk_label,
                        scam_probability, scam_category, ml_score, heuristic_score,
                        infrastructure_score, gemini_score, gemini_scam_type,
                        brand_name, brand_legitimate, flags, reasons, urls_found,
                        url_reports, analysis_json, raw_email, created_at, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) ON CONFLICT (user_id, message_id) DO NOTHING
                """
                
                analysis_json = json.dumps(report)
                flags_json = json.dumps(report.get("flags", []))
                reasons_json = json.dumps(report.get("reasons", []))
                urls_found_json = json.dumps(report.get("urls_found", []))
                url_reports_json = json.dumps(report.get("url_reports", []))

                cur.execute(insert_query, (
                    user_id,
                    message_id,
                    report.get("subject"),
                    report.get("top_from"),
                    report.get("top_from_email"),
                    report.get("effective_from"),
                    report.get("effective_from_email"),
                    report.get("effective_from_domain"),
                    report.get("sender_source"),
                    received_at,
                    report.get("overall_verdict"),
                    report.get("risk_label"),
                    report.get("scam_probability"),
                    report.get("scam_category"),
                    report.get("ml_score"),
                    report.get("heuristic_score"),
                    report.get("infrastructure_score"),
                    report.get("gemini_score"),
                    report.get("gemini_scam_type"),
                    report.get("brand_name"),
                    report.get("brand_legitimate"),
                    flags_json,
                    reasons_json,
                    urls_found_json,
                    url_reports_json,
                    analysis_json,
                    raw_email,
                    now,
                    now
                ))
            conn.commit()
            
        return JSONResponse(content={"status": "success", "user_id": user_id, "message_id": message_id, "report": report})
    except Exception as e:
        logger.exception("Database insert failed")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port)
