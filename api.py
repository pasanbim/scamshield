import os
import logging
import json
import uuid
from datetime import datetime, timezone

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse

import psycopg
from psycopg.rows import dict_row
from email.utils import parsedate_to_datetime

from main import load_model, analyze_email_raw

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres.lbounrtpongoaizuzktw:28gI51Im4cwKP7Jw@aws-0-eu-west-1.pooler.supabase.com:5432/postgres")

MAIL_HOST = os.getenv("MAIL_HOST", "mail.scam-shield.uk")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "noreply@scam-shield.uk")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "LKA,4-gdN2w^zPJn")
MAIL_FROM_ADDRESS = os.getenv("MAIL_FROM_ADDRESS", "noreply@scam-shield.uk")
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "ScamShield")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_report_email(to_email: str, subject_of_original: str, report: dict):
    # Safely strip "Fwd: " from subject without regex
    clean_subject = subject_of_original.strip()
    if clean_subject.lower().startswith("fwd: "):
        clean_subject = clean_subject[5:].strip()
    elif clean_subject.lower().startswith("fwd:"):
        clean_subject = clean_subject[4:].strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"ScamShield Analysis Report: {clean_subject}"
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM_ADDRESS}>"
    msg["To"] = to_email

    verdict = report.get('overall_verdict', 'UNKNOWN')
    risk = report.get('risk_label', 'UNKNOWN')
    probability = report.get('scam_probability', 0)
    
    # Determine colors based on risk
    if verdict == "UNSAFE":
        color_theme = "#dc2626" # Red
        bg_theme = "#fef2f2"
    elif verdict == "SUSPICIOUS":
        color_theme = "#d97706" # Orange
        bg_theme = "#fffbeb"
    else:
        color_theme = "#16a34a" # Green
        bg_theme = "#f0fdf4"

    text = f"ScamShield Analysis Report\n\nWe have analyzed the email you forwarded.\n\nOriginal Subject: {clean_subject}\nOverall Verdict: {verdict}\nRisk Label: {risk}\nScam Probability: {probability}%\n\nReasons identifying this verdict:\n"
    for r in report.get("reasons", []):
        text += f"- {r}\n"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
      body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6; padding: 20px; color: #1f2937; margin: 0; }}
      .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
      .header {{ background-color: {color_theme}; color: #ffffff; padding: 24px; text-align: center; }}
      .header h1 {{ margin: 0; font-size: 24px; font-weight: 600; letter-spacing: 0.5px; }}
      .content {{ padding: 32px 24px; }}
      .greeting {{ font-size: 16px; margin-bottom: 24px; color: #4b5563; }}
      .verdict-box {{ background-color: {bg_theme}; border-left: 4px solid {color_theme}; padding: 16px; margin-bottom: 24px; border-radius: 4px; }}
      .verdict-title {{ font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: #6b7280; margin: 0 0 4px 0; font-weight: 600; }}
      .verdict-value {{ font-size: 20px; font-weight: 700; color: {color_theme}; margin: 0; }}
      .details-table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
      .details-table th {{ text-align: left; padding: 12px 8px; border-bottom: 1px solid #e5e7eb; color: #6b7280; font-weight: 600; width: 40%; }}
      .details-table td {{ padding: 12px 8px; border-bottom: 1px solid #e5e7eb; font-weight: 500; }}
      .reasons-title {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
      .reasons-list {{ margin: 0; padding-left: 20px; color: #4b5563; }}
      .reasons-list li {{ margin-bottom: 8px; line-height: 1.5; }}
      .footer {{ background-color: #f9fafb; padding: 16px; text-align: center; font-size: 12px; color: #9ca3af; border-top: 1px solid #f3f4f6; }}
    </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>ScamShield Analysis Report</h1>
        </div>
        <div class="content">
          <p class="greeting">Hello,</p>
          <p class="greeting">We have completed the security analysis of the email you recently forwarded across to us.</p>
          
          <div class="verdict-box">
            <p class="verdict-title">Overall Verdict</p>
            <p class="verdict-value">{verdict}</p>
          </div>

          <table class="details-table">
            <tr>
              <th>Original Subject</th>
              <td>{clean_subject}</td>
            </tr>
            <tr>
              <th>Risk Label</th>
              <td>{risk}</td>
            </tr>
            <tr>
              <th>Scam Probability</th>
              <td>{probability}%</td>
            </tr>
          </table>

          <h3 class="reasons-title">Detailed Findings</h3>
          <ul class="reasons-list">
    """
    for r in report.get("reasons", []):
        html += f"<li>{r}</li>"
    html += """
          </ul>
        </div>
        <div class="footer">
          &copy; ScamShield Automated Scanner
        </div>
      </div>
    </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")
    msg.attach(part1)
    msg.attach(part2)

    try:
        server = smtplib.SMTP(MAIL_HOST, MAIL_PORT)
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_FROM_ADDRESS, to_email, msg.as_string())
        server.quit()
        logger.info(f"Report emailed to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")

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
            
        send_report_email(top_from_email, report.get("subject", "Unknown"), report)
            
        return JSONResponse(content={"status": "success", "user_id": user_id, "message_id": message_id, "report": report})
    except Exception as e:
        logger.exception("Database insert failed")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port)
