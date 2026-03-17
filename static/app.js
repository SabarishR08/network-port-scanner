const form = document.getElementById("scanForm");
const profile = document.getElementById("profile");
const target = document.getElementById("target");
const startPort = document.getElementById("startPort");
const endPort = document.getElementById("endPort");
const timeout = document.getElementById("timeout");
const workers = document.getElementById("workers");
const bannerGrab = document.getElementById("bannerGrab");
const exportFormat = document.getElementById("exportFormat");

const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const exportBtn = document.getElementById("exportBtn");
const clearBtn = document.getElementById("clearBtn");
const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");

const statusText = document.getElementById("statusText");
const resolvedIp = document.getElementById("resolvedIp");
const elapsed = document.getElementById("elapsed");
const openCount = document.getElementById("openCount");

const progressText = document.getElementById("progressText");
const progressPercent = document.getElementById("progressPercent");
const progressFill = document.getElementById("progressFill");
const resultsBody = document.getElementById("resultsBody");
const errorsEl = document.getElementById("errors");
const historyBody = document.getElementById("historyBody");

let currentJobId = null;
let pollTimer = null;

const profiles = {
  quick: [1, 1024],
  extended: [1, 5000],
  full: [1, 65535]
};

profile.addEventListener("change", () => {
  if (profile.value in profiles) {
    const [start, end] = profiles[profile.value];
    startPort.value = start;
    endPort.value = end;
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearTimer();

  const payload = {
    target: target.value.trim(),
    start_port: Number(startPort.value),
    end_port: Number(endPort.value),
    timeout: Number(timeout.value),
    max_workers: Number(workers.value),
    banner_grab: bannerGrab.checked
  };

  if (!payload.target) {
    setStatus("Target required");
    return;
  }

  startBtn.disabled = true;
  stopBtn.disabled = false;
  exportBtn.disabled = true;
  setStatus("Starting...");

  try {
    const response = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await parseJsonSafe(response);

    if (!response.ok || !data || !data.ok) {
      throw new Error((data && data.error) || `Failed to start scan (HTTP ${response.status}).`);
    }

    currentJobId = data.job.job_id;
    renderJob(data.job);
    pollTimer = setInterval(pollJob, 350);
  } catch (error) {
    setStatus(formatApiError(error));
    startBtn.disabled = false;
    stopBtn.disabled = true;
  }
});

stopBtn.addEventListener("click", async () => {
  if (!currentJobId) {
    return;
  }

  stopBtn.disabled = true;
  try {
    const response = await fetch(`/api/scan/${currentJobId}/stop`, { method: "POST" });
    const data = await parseJsonSafe(response);
    if (response.ok && data.ok) {
      renderJob(data.job);
    }
  } catch (error) {
    setStatus(`Stop error: ${formatApiError(error)}`);
  }
});

exportBtn.addEventListener("click", () => {
  if (!currentJobId) {
    return;
  }
  const format = exportFormat.value || "txt";
  window.location.href = `/api/scan/${currentJobId}/export?format=${encodeURIComponent(format)}`;
});

clearBtn.addEventListener("click", () => {
  clearTimer();
  currentJobId = null;
  setStatus("Idle");
  resolvedIp.textContent = "-";
  elapsed.textContent = "0.00s";
  openCount.textContent = "0";
  progressText.textContent = "0 / 0 scanned";
  progressPercent.textContent = "0%";
  progressFill.style.width = "0%";
  errorsEl.textContent = "No errors.";
  resultsBody.innerHTML = '<tr><td colspan="3" class="empty">No scan data yet.</td></tr>';
  startBtn.disabled = false;
  stopBtn.disabled = true;
  exportBtn.disabled = true;
});

refreshHistoryBtn.addEventListener("click", () => {
  loadHistory();
});

historyBody.addEventListener("click", async (event) => {
  const trigger = event.target.closest("button[data-job-id]");
  if (!trigger) {
    return;
  }

  const historyJobId = trigger.getAttribute("data-job-id");
  if (!historyJobId) {
    return;
  }

  try {
    const response = await fetch(`/api/history/${historyJobId}`);
    const data = await parseJsonSafe(response);
    if (!response.ok || !data || !data.ok) {
      throw new Error((data && data.error) || `History load failed (HTTP ${response.status}).`);
    }

    currentJobId = historyJobId;
    clearTimer();
    renderJob(data.job);
    startBtn.disabled = false;
    stopBtn.disabled = true;
    exportBtn.disabled = data.job.open_count < 1;
  } catch (error) {
    setStatus(`History error: ${formatApiError(error)}`);
  }
});

async function pollJob() {
  if (!currentJobId) {
    clearTimer();
    return;
  }

  try {
    const response = await fetch(`/api/scan/${currentJobId}/status`);
    const data = await parseJsonSafe(response);
    if (!response.ok || !data || !data.ok) {
      throw new Error((data && data.error) || `Status request failed (HTTP ${response.status}).`);
    }

    renderJob(data.job);

    if (["completed", "stopped"].includes(data.job.status)) {
      clearTimer();
      startBtn.disabled = false;
      stopBtn.disabled = true;
      exportBtn.disabled = data.job.open_count < 1;
      loadHistory();
    }
  } catch (error) {
    setStatus(`Polling error: ${formatApiError(error)}`);
    clearTimer();
    startBtn.disabled = false;
    stopBtn.disabled = true;
  }
}

function renderJob(job) {
  setStatus(job.status);
  resolvedIp.textContent = job.resolved_ip || "-";
  elapsed.textContent = `${Number(job.elapsed_seconds).toFixed(2)}s`;
  openCount.textContent = String(job.open_count);

  const total = Number(job.total_ports || 0);
  const scanned = Number(job.scanned_count || 0);
  const percent = total > 0 ? Math.round((scanned / total) * 100) : 0;
  progressText.textContent = `${scanned} / ${total} scanned`;
  progressPercent.textContent = `${percent}%`;
  progressFill.style.width = `${Math.min(percent, 100)}%`;

  if (job.open_ports && job.open_ports.length > 0) {
    const rows = job.open_ports
      .map((row) => {
        const banner = row.banner ? escapeHtml(row.banner) : "-";
        return `<tr><td>${row.port}</td><td>${escapeHtml(row.service)}</td><td>${banner}</td></tr>`;
      })
      .join("");
    resultsBody.innerHTML = rows;
  } else {
    resultsBody.innerHTML = '<tr><td colspan="3" class="empty">No open ports found yet.</td></tr>';
  }

  if (job.errors && job.errors.length > 0) {
    errorsEl.textContent = job.errors.join("\n");
  } else {
    errorsEl.textContent = "No errors.";
  }
}

function setStatus(value) {
  statusText.textContent = (value || "unknown").toUpperCase();
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history?limit=20");
    const data = await parseJsonSafe(response);
    if (!response.ok || !data || !data.ok) {
      throw new Error((data && data.error) || `History request failed (HTTP ${response.status}).`);
    }

    if (!data.items || data.items.length === 0) {
      historyBody.innerHTML = '<tr><td colspan="7" class="empty">No persisted scans yet.</td></tr>';
      return;
    }

    historyBody.innerHTML = data.items.map((item) => {
      const range = `${item.start_port}-${item.end_port}`;
      const elapsedValue = Number(item.elapsed_seconds || 0).toFixed(2);
      return `
        <tr>
          <td>${escapeHtml(item.target)}</td>
          <td>${range}</td>
          <td>${escapeHtml(item.status)}</td>
          <td>${item.open_count}</td>
          <td>${elapsedValue}s</td>
          <td>${item.banner_grab ? "Yes" : "No"}</td>
          <td><button type="button" class="ghost" data-job-id="${item.job_id}">Load</button></td>
        </tr>
      `;
    }).join("");
  } catch {
    historyBody.innerHTML = '<tr><td colspan="7" class="empty">History unavailable.</td></tr>';
  }
}

async function parseJsonSafe(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    return null;
  }
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function formatApiError(error) {
  if (error instanceof TypeError) {
    return "Cannot reach backend. Start server with: python portscanergui.py";
  }
  return error.message || "Unexpected error";
}

function clearTimer() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

  loadHistory();
