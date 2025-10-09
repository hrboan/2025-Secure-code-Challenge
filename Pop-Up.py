from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, HttpUrl
from datetime import datetime
import tldextract, re, uuid

app = FastAPI(title="Phish Investigator — Pop-Up Alert")

BAD_WORDS = [
    "login", "verify", "secure", "wallet", "invoice", "billing",
    "account", "bank", "update", "password", "signin", "onedrive",
]

SUSPICIOUS_TLDS = ["zip", "mov", "top", "xyz", "gq", "tk", "cf", "ml", "ga"]
BRANDS = ["microsoft", "apple", "naver", "kakao", "nh", "kb", "woori", "line", "pay"]

# 휴리스틱 점수 계산
def heuristic_score(url: str) -> int:
    score = 0
    u = url.lower()
    for w in BAD_WORDS:
        if w in u:
            score += 8
    for b in BRANDS:
        if b in u:
            score += 10
    if len(url) > 120:
        score += 5
    if url.count("?") + url.count("&") > 3:
        score += 5
    if re.search(r"[@%]|0auth|paypa1|mícrosoft|faceb00k|g00gle", u):
        score += 12
    ext = tldextract.extract(url)
    tld = (ext.suffix or "").split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 10
    if ext.subdomain and len(ext.subdomain.split('.')) >= 2:
        score += 6
    return min(score, 100)


# 정책 결정
def decision_from_score(score: int) -> str:
    if score >= 80:
        return "위험"
    if 50 <= score < 80:
        return "주의"
    return "안전"


# --- UI ---
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
    <head>
        <title>Phish Investigator — Pop-Up Demo</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-50 flex items-center justify-center h-screen">
        <div class="text-center bg-white p-8 rounded-2xl shadow-md w-[400px]">
            <h1 class="text-2xl font-bold mb-4">🔎 Phish Investigator</h1>
            <form method="post" action="/check" class="flex flex-col gap-4">
                <input name="url" type="url" placeholder="https://example-login.com" required
                    class="rounded-xl border border-slate-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-700"/>
                <button type="submit" class="bg-slate-900 text-white py-2 rounded-xl shadow">조사 시작</button>
            </form>
        </div>
    </body>
    </html>
    """


# --- 점수 분석 및 팝업 처리 ---
@app.post("/check", response_class=HTMLResponse)
async def check_url(url: str = Form(...)):
    score = heuristic_score(url)
    decision = decision_from_score(score)

    # 결과 텍스트
    message = f"{url} 의 점수는 {score}점이며, 상태는 '{decision}' 입니다."

    # 주의 / 위험 단계에서는 팝업(alert) + 신고 페이지 버튼
    if decision in ["주의", "위험"]:
        return f"""
        <html>
        <head>
            <script>
                alert("{message}\\n⚠️ 위험 URL이 감지되었습니다!");
                function goReport() {{
                    window.location.href = "https://phishing.gov.kr"; // 악성 사이트 신고 페이지
                }}
            </script>
        </head>
        <body class="flex items-center justify-center h-screen bg-slate-50">
            <div class="text-center bg-white p-8 rounded-2xl shadow-md w-[400px]">
                <h2 class="text-xl font-semibold mb-4">🚨 {decision} 단계 감지</h2>
                <p class="mb-6 text-sm text-slate-700">{message}</p>
                <button onclick="goReport()" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-xl shadow">
                    🔗 악성 사이트 신고하기
                </button>
            </div>
        </body>
        </html>
        """
    else:
        # 안전 단계면 팝업 없이 결과만 표시
        return f"""
        <html>
        <head><script>alert("{message}\\n✅ 안전 URL로 판단되었습니다.");</script></head>
        <body class="flex items-center justify-center h-screen bg-slate-50">
            <div class="text-center bg-white p-8 rounded-2xl shadow-md w-[400px]">
                <h2 class="text-xl font-semibold mb-4">✅ 안전한 URL</h2>
                <p class="text-slate-700">{message}</p>
                <a href="/" class="mt-6 inline-block text-blue-600 underline">돌아가기</a>
            </div>
        </body>
        </html>
        """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
