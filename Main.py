from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, HttpUrl
from typing import List
from datetime import datetime
import tldextract
import re
import uuid
import urllib.parse

app = FastAPI(title="Phish Investigator — Main")

# --- 데이터 구조 ---
class Investigation(BaseModel):
    id: str
    url: str
    domain: str
    submitted_at: datetime
    status: str
    score: int
    decision: str
    notes: str = ""

STORE: List[Investigation] = []

# --- 휴리스틱 점수 계산 ---
BAD_WORDS = [
    "login", "verify", "secure", "wallet", "invoice", "billing",
    "account", "bank", "update", "password", "signin", "onedrive",
]
SUSPICIOUS_TLDS = ["zip", "mov", "top", "xyz", "gq", "tk", "cf", "ml", "ga"]
BRANDS = ["microsoft", "apple", "naver", "kakao", "nh", "kb", "woori", "kbstar", "line", "pay"]

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

def decision_from_score(score: int) -> str:
    if score >= 80:
        return "자동 신고 + 긴급 차단"
    if 50 <= score < 80:
        return "내부 차단"
    return "모니터링"

# --- HTML 기본 구조 ---
HTML_HEAD = """
<!doctype html>
<html lang="ko">
  <head>
    <meta charset="utf-8"> 
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Phish Investigator — 메인</title>
    <script src="https://unpkg.com/htmx.org@1.9.12" crossorigin="anonymous"></script>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-slate-50 text-slate-900">
    <div class="max-w-6xl mx-auto p-6">
      <header class="mb-6">
        <h1 class="text-2xl font-bold">🔎 Phish Investigator</h1>
        <p class="text-sm text-slate-600">
          의심 URL을 즉시 조사하여 연관 인프라를 묶고 정책에 따라 차단/신고까지 자동화하는 시스템 (메인 페이지 MVP)
        </p>
      </header>
"""

HTML_FOOT = """
      <footer class="mt-10 text-xs text-slate-500">
        <p>Made with FastAPI · HTMX · Tailwind — MVP (데모 점수/결정 로직)</p>
      </footer>
    </div>
  </body>
</html>
"""

# --- 테이블 렌더링 ---
def render_recent_table(items: List[Investigation]) -> str:
    if not items:
        return "<p class='text-sm text-slate-500'>아직 기록이 없습니다.</p>"

    rows = []
    for it in items[:20]:
        if it.score >= 80:
            badge = "bg-red-600 text-white"
            label = "위험"
        elif 30 <= it.score < 80:
            badge = "bg-yellow-400 text-black"
            label = "주의"
        else:
            badge = "bg-blue-600 text-white"
            label = "안전"

        rows.append(
            f"""
            <tr class="border-b last:border-0">
              <td class="py-3 px-4 align-top">
                <div class="font-mono text-xs break-all">{it.url}</div>
                <div class="text-[11px] text-slate-500">{it.domain}</div>
              </td>
              <td class="py-3 px-4 align-top">{it.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}</td>
              <td class="py-3 px-4 align-top">
                <span class="px-3 py-1 rounded-full text-xs {badge}">
                  {it.score} {label}
                </span>
              </td>
              <td class="py-3 px-4 align-top">{it.decision}</td>
              <td class="py-3 px-4 align-top"><span class="text-xs">{it.status}</span></td>
            </tr>
            """
        )

    return f"""
    <div class="overflow-hidden rounded-2xl shadow bg-white">
      <table class="w-full text-sm">
        <thead class="bg-slate-100 text-slate-700">
          <tr>
            <th class="text-left px-4 py-2">URL</th>
            <th class="text-left px-4 py-2">제출 시각</th>
            <th class="text-left px-4 py-2">점수</th>
            <th class="text-left px-4 py-2">결정</th>
            <th class="text-left px-4 py-2">상태</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
    """

# --- 메인 페이지 ---
@app.get("/", response_class=HTMLResponse)
async def index(_: Request):
    form_html = """
    <section class="mb-8">
      <form hx-post="/investigate" hx-target="#recent" hx-swap="innerHTML" class="flex gap-2 items-end">
        <div class="flex-1">
          <label for="url" class="block text-sm font-medium text-slate-700">의심 URL</label>
          <input type="url" id="url" name="url" required
                 placeholder="https://bank.example-login.com/login"
                 class="mt-1 w-full rounded-xl border border-slate-300 px-3 py-2
                        focus:outline-none focus:ring-2 focus:ring-slate-700" />
        </div>
        <button type="submit" class="h-10 px-4 rounded-xl bg-slate-900 text-white text-sm shadow">조사 시작</button>
      </form>
      <p class="mt-2 text-xs text-slate-500">
        제출 즉시 점수와 정책 결정을 보여줍니다. (데모: 로컬 휴리스틱 사용)
      </p>
    </section>
    """

    recent_html = f"""
    <section>
      <div class="flex items-center justify-between mb-2">
        <h2 class="text-lg font-semibold">최근 조사</h2>
        <button class="text-xs underline" hx-get="/recent" hx-target="#recent" hx-swap="innerHTML">새로고침</button>
      </div>
      {render_recent_table(STORE)}
    </section>
    """

    # 모달 표시용 오버레이 영역 추가
    return HTML_HEAD + form_html + f"<div id='recent'>{recent_html}</div><div id='overlay'></div>" + HTML_FOOT

# --- 최근 목록 갱신 ---
@app.get("/recent", response_class=HTMLResponse)
async def recent():
    return f"""
    <div class="flex items-center justify-between mb-2">
      <h2 class="text-lg font-semibold">최근 조사</h2>
      <button class="text-xs underline" hx-get="/recent" hx-target="#recent" hx-swap="innerHTML">새로고침</button>
    </div>
    {render_recent_table(STORE)}
    """

# --- URL 검증 ---
class UrlModel(BaseModel):
    url: HttpUrl

# --- 조사 로직 (팝업 모달 트리거 포함) ---
@app.post("/investigate", response_class=HTMLResponse)
async def investigate(url: str = Form(...)):
    try:
        UrlModel(url=url)
    except Exception:
        return "<p class='text-red-600 text-sm'>유효한 URL이 아닙니다.</p>"

    ext = tldextract.extract(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    score = heuristic_score(url)
    decision = decision_from_score(score)

    inv = Investigation(
        id=str(uuid.uuid4()),
        url=url,
        domain=domain or "(unknown)",
        submitted_at=datetime.now(),
        status="analyzed",
        score=score,
        decision=decision,
    )
    STORE.insert(0, inv)

    # 주의/위험 단계면 Pop-Up 서버의 fragment 로드
    popup_script = ""
    if score >= 30:
        encoded_url = urllib.parse.quote(url)
        popup_script = f"""
        <script>
          htmx.ajax('GET',
            'http://127.0.0.1:8001/fragment?url={encoded_url}&score={score}&decision={urllib.parse.quote(decision)}',
            '#overlay');
        </script>
        """

    html = f"""
    <div class="flex items-center justify-between mb-2">
      <h2 class="text-lg font-semibold">최근 조사</h2>
      <button class="text-xs underline" hx-get="/recent" hx-target="#recent" hx-swap="innerHTML">새로고침</button>
    </div>
    {render_recent_table(STORE)}
    {popup_script}
    """
    return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
