from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from urllib.parse import unquote
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Phish Investigator — Popup Fragment")

# CORS 허용 (Main:8000 → Popup:8001)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) 

@app.get("/fragment", response_class=HTMLResponse)
async def popup_fragment(url: str = "", score: str = "", decision: str = ""):
    url = unquote(url)
    score_int = int(score) if score.isdigit() else 0

    # 색상 및 라벨 구분
    if score_int >= 80:
        color = "bg-red-100 text-red-800"
        label = "🚨 위험"
    else:
        color = "bg-yellow-100 text-yellow-800"
        label = "⚠️ 주의"

    # 모달 HTML + fade-out 애니메이션 포함
    return f"""
    <style>
      @keyframes fadeOut {{
        0% {{ opacity: 1; }}
        100% {{ opacity: 0; }}
      }}
      .fade-out {{
        animation: fadeOut 0.3s ease forwards;
      }}
    </style>

    <div id="popup-modal" class="fixed inset-0 flex items-center justify-center z-50 transition-opacity duration-300">
      <!-- 배경 클릭 시 닫기 -->
      <div class="absolute inset-0 bg-black/40" onclick="closeModal()"></div>

      <div class="relative bg-white rounded-xl p-6 shadow max-w-md z-60 transform transition-all">
        <h3 class="text-lg font-semibold mb-2 {color} px-2 py-1 rounded">{label}</h3>
        <p class="text-sm text-slate-700 mb-4">
          의심 URL:<br><span class="font-mono text-xs break-all">{url}</span>
        </p>
        <p class="mb-4">탐지 점수: <strong>{score}</strong></p>

        <div class="flex gap-2 justify-end">
          <a href="https://phishing.gov.kr" target="_blank"
             class="bg-red-600 text-white px-4 py-2 rounded-xl hover:bg-red-700">신고하기</a>
          <button onclick="closeModal()" 
                  class="bg-slate-200 px-4 py-2 rounded-xl hover:bg-slate-300">
            닫기
          </button>
        </div>
      </div>
    </div>

    <script>
      // 닫기 함수 (fade-out 애니메이션 후 제거)
      function closeModal() {{
        const modal = document.getElementById('popup-modal');
        if (modal) {{
          modal.classList.add('fade-out');
          setTimeout(() => modal.remove(), 300); // 0.3초 후 완전 제거
        }}
      }}
    </script>
    """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
