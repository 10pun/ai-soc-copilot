from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import re
import ipaddress
from urllib.parse import urlparse
from typing import Literal

app = FastAPI(title="AI SOC Copilot", version="1.0.0")

SUSPICIOUS_TLDS = {"zip", "ru", "cn", "top", "click", "loan", "gq", "tk"}
BRANDS = {"microsoft", "google", "apple", "paypal", "amazon", "netflix", "bank", "dhl"}


class Indicator(BaseModel):
    indicator: str
    type: Literal["ip", "domain", "url", "email"]


class AnalysisRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    body: str = ""
    urls: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    evidence: str


class AnalysisResponse(BaseModel):
    verdict: Literal["benign", "suspicious", "malicious"]
    score: int
    confidence: float
    findings: list[Finding]


def extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>\"']+", text)


def classify_url(url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        try:
            ipaddress.ip_address(host)
            findings.append(Finding(category="ip-hosted-url", severity="high", evidence=f"URL uses an IP host: {host}"))
        except ValueError:
            pass
        parts = host.split(".")
        if parts and parts[-1] in SUSPICIOUS_TLDS:
            findings.append(Finding(category="suspicious-tld", severity="medium", evidence=f"Suspicious top-level domain: .{parts[-1]}"))
        if re.search(r"@|%(25)?[0-9a-f]{2}", parsed.netloc, re.I):
            findings.append(Finding(category="obfuscated-url", severity="high", evidence="URL contains obfuscated or deceptive components"))
        for brand in BRANDS:
            if brand in host and not host.endswith(f"{brand}.com"):
                findings.append(Finding(category="brand-impersonation", severity="high", evidence=f"Brand-like domain {host} may impersonate {brand}"))
        if len(host) > 30:
            findings.append(Finding(category="long-domain", severity="medium", evidence=f"Unusually long domain: {host}"))
    except ValueError:
        findings.append(Finding(category="malformed-url", severity="medium", evidence=f"Malformed URL: {url}"))
    return findings


@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-soc-copilot"}


@app.post("/analyze", response_model=AnalysisResponse)
def analyze(request: AnalysisRequest):
    text = f"{request.subject}\n{request.sender}\n{request.body}".lower()
    findings: list[Finding] = []

    urgency = re.findall(r"\b(urgent|verify|suspend|password|reset|invoice|payment|confirm|immediate|expires?)\b", text)
    if len(set(urgency)) >= 2:
        findings.append(Finding(category="social-engineering", severity="high", evidence=f"Urgency/credential language: {', '.join(sorted(set(urgency)))}"))

    if re.search(r"(?:password|credential|otp|2fa).{0,30}(?:click|send|enter|verify)", text):
        findings.append(Finding(category="credential-theft", severity="critical", evidence="Message appears to request or verify credentials"))

    if re.search(r"[\w.+-]+@(?!gmail|outlook|yahoo)[\w.-]+\.[a-z]{2,}", request.sender.lower()):
        domain = request.sender.rsplit("@", 1)[-1] if "@" in request.sender else ""
        for brand in BRANDS:
            if brand in domain:
                findings.append(Finding(category="sender-brand-mismatch", severity="high", evidence=f"Sender domain resembles {brand}: {domain}"))

    attachment_names = re.findall(r"(?:\.exe|\.scr|\.js|\.hta|\.iso|\.vbs|\.dll|\.lnk|\.bat)", text)
    if attachment_names:
        findings.append(Finding(category="dangerous-attachment", severity="critical", evidence="Potential dangerous attachment or executable reference detected"))

    urls = list(dict.fromkeys(request.urls + extract_urls(request.body)))
    for url in urls:
        findings += classify_url(url)

    weights = {"low": 5, "medium": 15, "high": 30, "critical": 45}
    score = min(100, sum(weights[f.severity] for f in findings))
    if score >= 70:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "benign"
    confidence = round(min(0.99, 0.5 + score / 200), 2)

    return AnalysisResponse(verdict=verdict, score=score, confidence=confidence, findings=findings)


@app.post("/indicators/extract")
def extract_indicators(request: AnalysisRequest):
    text = "\n".join([request.subject, request.sender, request.body])
    indicators: list[Indicator] = []

    for ip in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
        try:
            ipaddress.ip_address(ip)
            indicators.append(Indicator(indicator=ip, type="ip"))
        except ValueError:
            pass

    urls = list(dict.fromkeys(request.urls + extract_urls(text)))
    for url in urls:
        indicators.append(Indicator(indicator=url, type="url"))

    for email in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
        indicators.append(Indicator(indicator=email, type="email"))

    unique = {(i.type, i.indicator): i for i in indicators}
    return {"count": len(unique), "indicators": list(unique.values())}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
