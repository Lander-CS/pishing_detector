const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const analyzeButton = document.getElementById("analyze-button");
const formError = document.getElementById("form-error");

const resultContainer = document.getElementById("result");
const resultUrl = document.getElementById("result-url");
const riskBadge = document.getElementById("risk-badge");
const riskScore = document.getElementById("risk-score");
const riskLevel = document.getElementById("risk-level");
const indicatorsList = document.getElementById("indicators-list");

const historyBody = document.getElementById("history-body");
const refreshHistoryButton = document.getElementById("refresh-history");

function setLoading(isLoading) {
  analyzeButton.disabled = isLoading;
  analyzeButton.textContent = isLoading ? "Analyzing..." : "Analyze";
}

function clearResult() {
  resultContainer.hidden = true;
  indicatorsList.innerHTML = "";
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

function clearError() {
  formError.hidden = true;
  formError.textContent = "";
}

function riskClass(level) {
  switch (level) {
    case "low":
      return "low";
    case "medium":
      return "medium";
    case "high":
      return "high";
    case "critical":
      return "critical";
    default:
      return "low";
  }
}

function renderResult(data) {
  resultUrl.textContent = data.url;
  riskScore.textContent = `${data.risk_score}/10`;
  riskLevel.textContent = data.risk_level.toUpperCase();

  riskBadge.className = `badge badge-${riskClass(data.risk_level)}`;

  indicatorsList.innerHTML = "";
  if (data.indicators && data.indicators.length > 0) {
    data.indicators.forEach((ind) => {
      const li = document.createElement("li");
      li.textContent = ind.message;
      indicatorsList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "No obvious phishing indicators found.";
    indicatorsList.appendChild(li);
  }

  resultContainer.hidden = false;
}

async function submitAnalysis(url) {
  clearError();
  clearResult();
  setLoading(true);
  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      const message =
        (errorData && errorData.detail) ||
        "An error occurred while analyzing the URL.";
      showError(message);
      return;
    }

    const data = await response.json();
    renderResult(data);
    await loadHistory();
  } catch (err) {
    console.error(err);
    showError("Network error while contacting the server.");
  } finally {
    setLoading(false);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) {
    showError("Please enter a URL.");
    return;
  }
  submitAnalysis(url);
});

async function loadHistory() {
  try {
    const response = await fetch("/history?limit=20");
    if (!response.ok) {
      return;
    }
    const items = await response.json();
    historyBody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");

      const urlTd = document.createElement("td");
      urlTd.textContent = item.url;
      tr.appendChild(urlTd);

      const scoreTd = document.createElement("td");
      scoreTd.textContent = item.risk_score;
      tr.appendChild(scoreTd);

      const levelTd = document.createElement("td");
      const pill = document.createElement("span");
      const cls = riskClass(item.risk_level);
      pill.className = `pill pill-${cls}`;
      pill.textContent = item.risk_level.toUpperCase();
      levelTd.appendChild(pill);
      tr.appendChild(levelTd);

      const whenTd = document.createElement("td");
      const date = new Date(item.created_at);
      whenTd.textContent = date.toLocaleString();
      tr.appendChild(whenTd);

      historyBody.appendChild(tr);
    });
  } catch (err) {
    console.error(err);
  }
}

refreshHistoryButton.addEventListener("click", () => {
  loadHistory();
});

// Initial load
loadHistory();

