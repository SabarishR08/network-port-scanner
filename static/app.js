const form = document.getElementById("scanForm");
const profile = document.getElementById("profile");
const target = document.getElementById("target");
const startPort = document.getElementById("startPort");
const endPort = document.getElementById("endPort");
const timeout = document.getElementById("timeout");
const workers = document.getElementById("workers");

const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const exportBtn = document.getElementById("exportBtn");
const clearBtn = document.getElementById("clearBtn");

const statusText = document.getElementById("statusText");
const resolvedIp = document.getElementById("resolvedIp");
const elapsed = document.getElementById("elapsed");
const openCount = document.getElementById("openCount");

const progressText = document.getElementById("progressText");
const progressPercent = document.getElementById("progressPercent");
const progressFill = document.getElementById("progressFill");
const resultsBody = document.getElementById("resultsBody");
const errorsEl = document.getElementById("errors");

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
    max_workers: Number(workers.value)
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
    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Failed to start scan.");
    }

    currentJobId = data.job.job_id;
    renderJob(data.job);
    pollTimer = setInterval(pollJob, 350);
  } catch (error) {
    setStatus(error.message);
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
    const data = await response.json();
    if (response.ok && data.ok) {
      renderJob(data.job);
    }
  } catch (error) {
    setStatus(`Stop error: ${error.message}`);
  }
});

exportBtn.addEventListener("click", () => {
  if (!currentJobId) {
    return;
  }
  window.location.href = `/api/scan/${currentJobId}/export`;
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
  resultsBody.innerHTML = '<tr><td colspan="2" class="empty">No scan data yet.</td></tr>';
  startBtn.disabled = false;
  stopBtn.disabled = true;
  exportBtn.disabled = true;
});

async function pollJob() {
  if (!currentJobId) {
    clearTimer();
    return;
  }

  try {
    const response = await fetch(`/api/scan/${currentJobId}/status`);
    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Status request failed.");
    }

    renderJob(data.job);

    if (["completed", "stopped"].includes(data.job.status)) {
      clearTimer();
      startBtn.disabled = false;
      stopBtn.disabled = true;
      exportBtn.disabled = data.job.open_count < 1;
    }
  } catch (error) {
    setStatus(`Polling error: ${error.message}`);
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
      .map((row) => `<tr><td>${row.port}</td><td>${escapeHtml(row.service)}</td></tr>`)
      .join("");
    resultsBody.innerHTML = rows;
  } else {
    resultsBody.innerHTML = '<tr><td colspan="2" class="empty">No open ports found yet.</td></tr>';
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
