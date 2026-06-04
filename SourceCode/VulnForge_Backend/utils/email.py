import smtplib
import random
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from email.utils import formataddr

load_dotenv()

EMAIL          = os.getenv("EMAIL")          # noreply@vulnforge.app
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") # Resend API key
FRONTEND_URL   = os.getenv("FRONTEND_URL", "https://vulnforge.app")


def generate_otp():
    return str(random.randint(100000, 999999))


def _send(to_email: str, subject: str, html: str) -> bool:
    """Shared SMTP sender via Resend"""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = formataddr(("VulnForge", EMAIL))
        msg["To"]      = to_email
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.resend.com", 465) as server:
            server.login("resend", EMAIL_PASSWORD)
            server.sendmail(EMAIL, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False


def send_otp_email(to_email: str, otp: str) -> bool:
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<style>
body {{ font-family: Arial, sans-serif; background: #0a0a0a; margin: 0; padding: 40px; color: #fff; }}
.container {{ max-width: 500px; margin: 0 auto; background: #111; border-radius: 10px; padding: 40px; border: 1px solid #00ff88; }}
.header h1 {{ color: #00ff88; margin: 0; font-size: 28px; text-align: center; }}
.subtitle {{ color: #aaa; font-size: 14px; margin-top: 6px; text-align: center; }}
.divider {{ border: 1px solid #222; margin: 25px 0; }}
.content h2 {{ text-align: center; color: #fff; }}
.otp-box {{ background: #1a1a1a; border-radius: 8px; padding: 25px; text-align: center; margin: 25px 0; border: 1px solid #00ff8844; }}
.otp-code {{ color: #00ff88; font-size: 36px; letter-spacing: 10px; font-family: Arial; margin: 0; }}
.expiry {{ text-align: center; color: #888; font-size: 13px; }}
.footer {{ text-align: center; color: #444; font-size: 11px; }}
</style></head>
<body>
<div class="container">
  <div class="header"><h1>VulnForge</h1><p class="subtitle">Autonomous Penetration Testing Platform</p></div>
  <hr class="divider">
  <div class="content">
    <h2>Your Verification Code</h2>
    <div class="otp-box"><h1 class="otp-code">{otp}</h1></div>
    <p class="expiry">This OTP expires in <b style="color:#fff;">10 minutes</b></p>
    <p class="expiry">If you didn't request this, ignore this email.</p>
  </div>
  <hr class="divider">
  <p class="footer">© 2026 VulnForge. All rights reserved.</p>
  <p class="footer">This is an automated email — please do not reply.</p>
</div>
</body></html>"""
    return _send(to_email, "VulnForge — Your OTP Code", html)


def send_scan_complete_email(
    to_email: str,
    user_name: str,
    target: str,
    scan_id: str,
    risk_level: str,
    security_score: int,
    scan_type: str,
    critical_findings: int,
) -> bool:
    """Send scan completion notification with direct report link"""

    risk_color = {
        "CRITICAL": "#EF4444",
        "HIGH":     "#F97316",
        "MEDIUM":   "#F59E0B",
        "LOW":      "#10B981",
    }.get(risk_level.upper(), "#6B7280")

    scan_type_label = {"light": "Light Scan", "medium": "Medium Scan", "deep": "Deep Scan"}.get(scan_type, "Scan")
    report_url = f"{FRONTEND_URL}/scans/{scan_id}"

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: Arial, sans-serif; background: #F6F8FA; padding: 40px 20px; color: #0D1117; }}
.container {{ max-width: 560px; margin: 0 auto; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 24px rgba(0,0,0,0.08); }}
.header {{ background: #1E293B; padding: 28px 32px; }}
.header-brand {{ display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }}
.brand-name {{ color: #fff; font-size: 18px; font-weight: 700; }}
.brand-badge {{ background: rgba(16,185,129,0.2); color: #10B981; border: 1px solid rgba(16,185,129,0.3); border-radius: 999px; padding: 2px 10px; font-size: 11px; font-weight: 600; }}
.header-title {{ color: #F0F6FC; font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
.header-sub {{ color: #8B949E; font-size: 14px; }}
.body {{ padding: 28px 32px; }}
.greeting {{ font-size: 15px; color: #374151; margin-bottom: 20px; }}
.stats {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }}
.stat {{ background: #F6F8FA; border: 1px solid #E5E7EB; border-radius: 8px; padding: 14px 16px; }}
.stat-label {{ font-size: 11px; font-weight: 600; color: #6B7280; letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 4px; }}
.stat-value {{ font-size: 18px; font-weight: 700; color: #0D1117; }}
.risk-badge {{ display: inline-block; background: {risk_color}18; border: 1px solid {risk_color}40; border-radius: 6px; padding: 4px 12px; color: {risk_color}; font-size: 13px; font-weight: 700; }}
.cta {{ text-align: center; margin: 24px 0; }}
.cta-btn {{ display: inline-block; background: #10B981; color: #fff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-size: 15px; font-weight: 600; }}
.cta-sub {{ font-size: 13px; color: #6B7280; margin-top: 10px; }}
.divider {{ height: 1px; background: #E5E7EB; margin: 20px 0; }}
.target-box {{ background: #F6F8FA; border: 1px solid #E5E7EB; border-radius: 8px; padding: 12px 16px; font-family: monospace; font-size: 14px; color: #374151; margin-bottom: 20px; }}
.footer {{ background: #F6F8FA; padding: 20px 32px; border-top: 1px solid #E5E7EB; }}
.footer p {{ font-size: 12px; color: #9CA3AF; margin-bottom: 4px; }}
.footer a {{ color: #10B981; text-decoration: none; }}
</style></head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-brand">
      <span class="brand-name">VulnForge</span>
      <span class="brand-badge">v1.0</span>
    </div>
    <div class="header-title">Scan Complete</div>
    <div class="header-sub">{scan_type_label} finished for {target}</div>
  </div>

  <!-- Body -->
  <div class="body">
    <p class="greeting">Hi <strong>{user_name}</strong>, your security scan has completed. Here's a summary:</p>

    <div class="target-box">Target: {target}</div>

    <!-- Stats grid -->
    <div class="stats">
      <div class="stat">
        <div class="stat-label">Risk Level</div>
        <div class="stat-value"><span class="risk-badge">{risk_level}</span></div>
      </div>
      <div class="stat">
        <div class="stat-label">CVSS Score</div>
        <div class="stat-value" style="color: {risk_color};">{security_score}/10.0</div>
      </div>
      <div class="stat">
        <div class="stat-label">Scan Type</div>
        <div class="stat-value" style="font-size: 15px;">{scan_type_label}</div>
      </div>
      <div class="stat">
        <div class="stat-label">AI Findings</div>
        <div class="stat-value" style="color: {'#EF4444' if critical_findings > 0 else '#10B981'};">{critical_findings}</div>
      </div>
    </div>

    <!-- CTA -->
    <div class="cta">
      <a href="{report_url}" class="cta-btn">View Full Report</a>
      <p class="cta-sub">Report includes port scan, subdomains, CVEs, AI analysis and remediation steps</p>
    </div>

    <div class="divider"></div>

    <p style="font-size: 13px; color: #6B7280;">
      You can also download the full PDF report directly from the report page.
      If you didn't initiate this scan, please contact support immediately.
    </p>
  </div>

  <!-- Footer -->
  <div class="footer">
    <p>© 2026 VulnForge — For authorized security testing only.</p>
    <p><a href="https://github.com/harman1418">github.com/harman1418</a> · <a href="https://linkedin.com/in/harmanjotcs">linkedin.com/in/harmanjotcs</a></p>
  </div>

</div>
</body></html>"""

    return _send(
        to_email,
        f"VulnForge — Scan Complete: {target} [{risk_level}]",
        html
    )


if __name__ == "__main__":
    otp = generate_otp()
    send_otp_email("test@example.com", otp)
