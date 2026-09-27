const API = "/api";
const OVERRIDE_FIELDS = [
  "google_index", "page_rank", "web_traffic",
  "domain_age", "domain_registration_length", "whois_registered_domain",
];

const $ = (id) => document.getElementById(id);

async function checkHealth() {
  const el = $("apiStatus");
  try {
    const res = await fetch(`${API}/health`);
    if (!res.ok) throw new Error();
    el.textContent = "API online";
    el.className = "status ok";
  } catch {
    el.textContent = "API offline";
    el.className = "status down";
  }
}

async function loadModelInfo() {
  const box = $("modelInfo");
  try {
    const info = await (await fetch(`${API}/model-info`)).json();
    const max = info.top_features[0]?.importance || 1;
    box.innerHTML = `
      <div class="stats">
        <div><b>${info.model_type.replace("Classifier", "")}</b>Algorithm</div>
        <div><b>${info.n_estimators}</b>Trees</div>
        <div><b>${info.max_depth}</b>Max depth</div>
        <div><b>${info.feature_count}</b>Features</div>
      </div>
      <p class="muted" style="margin:0 0 8px;font-size:13px">Most influential features</p>
      <div class="bars">
        ${info.top_features.map((f) => `
          <div class="bar" title="${(f.importance * 100).toFixed(1)}%">
            <span>${f.feature}</span>
            <span class="bar-fill" style="width:${(f.importance / max) * 100}%"></span>
          </div>`).join("")}
      </div>`;
  } catch {
    box.textContent = "Couldn't load model info.";
  }
}

function collectOverrides() {
  const overrides = {};
  for (const id of OVERRIDE_FIELDS) {
    const v = $(id).value.trim();
    if (v !== "") overrides[id] = Number(v);
  }
  return Object.keys(overrides).length ? overrides : null;
}

function formatValue(v) {
  return typeof v === "number" && !Number.isInteger(v) ? v.toFixed(3) : v;
}

function renderResult(data) {
  const pct = Math.round(data.phishing_probability * 100);
  const phishing = data.label === "phishing";

  const gauge = $("gauge");
  gauge.style.setProperty("--p", pct);
  gauge.className = "gauge" + (phishing ? " danger" : pct >= 30 ? " warn" : "");
  $("gaugeValue").textContent = `${pct}%`;

  const badge = $("badge");
  badge.textContent = phishing ? "Phishing" : "Legitimate";
  badge.className = "badge" + (phishing ? " danger" : "");
  $("verdictTitle").textContent = phishing
    ? "This URL looks like phishing"
    : "This URL looks legitimate";
  $("resultUrl").textContent = data.url;

  const notes = [];
  notes.push(data.page_fetched
    ? "The page content was fetched and analysed."
    : `The page content wasn't analysed${data.fetch_error ? ` (${data.fetch_error})` : ""}. The result is based on the URL alone.`);
  if (data.defaulted_features.length) {
    notes.push(`${data.defaulted_features.length} external signals used dataset medians (highlighted below). Add them under Advanced signals for a more accurate result.`);
  }
  $("notes").replaceChildren(...notes.map((n) => {
    const li = document.createElement("li");
    li.textContent = n;
    return li;
  }));

  const defaulted = new Set(data.defaulted_features);
  const tbody = $("featureTable");
  tbody.replaceChildren(...Object.entries(data.features).map(([k, v]) => {
    const tr = document.createElement("tr");
    if (defaulted.has(k)) tr.className = "defaulted";
    tr.innerHTML = "<td></td><td></td>";
    tr.children[0].textContent = k + (defaulted.has(k) ? " (default)" : "");
    tr.children[1].textContent = formatValue(v);
    return tr;
  }));

  $("result").hidden = false;
}

async function onSubmit(e) {
  e.preventDefault();
  const url = $("urlInput").value.trim();
  if (!url) return;

  const btn = $("scanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  $("error").hidden = true;

  try {
    const res = await fetch(`${API}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        fetch_page: $("fetchPage").checked,
        overrides: collectOverrides(),
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join(", ") : data.detail;
      throw new Error(detail || "Request failed");
    }
    renderResult(data);
  } catch (err) {
    $("result").hidden = true;
    $("error").textContent = err.message || "Something went wrong.";
    $("error").hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan URL";
  }
}

$("advToggle").addEventListener("click", () => {
  const adv = $("advanced");
  adv.hidden = !adv.hidden;
  $("advToggle").setAttribute("aria-expanded", String(!adv.hidden));
});
$("scanForm").addEventListener("submit", onSubmit);

checkHealth();
loadModelInfo();
