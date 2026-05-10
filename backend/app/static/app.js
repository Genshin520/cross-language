const storageKey = "depVulnLatestResult";
const page = document.body.dataset.page;

const statusText = document.getElementById("statusText");
const statsGrid = document.getElementById("statsGrid");
const architectureSummary = document.getElementById("architectureSummary");
const summaryPanel = document.getElementById("summaryPanel");
const distributionPanel = document.getElementById("distributionPanel");
const vulnerabilityList = document.getElementById("vulnerabilityList");
const riskList = document.getElementById("riskList");
const historyList = document.getElementById("historyList");
const reportActions = document.getElementById("reportActions");
const graphCanvas = document.getElementById("graphCanvas");
const graphLegend = document.getElementById("graphLegend");
const graphTools = document.getElementById("graphTools");
const graphStats = document.getElementById("graphStats");
const architectureProfile = document.getElementById("architectureProfile");
const graphImpactPanel = document.getElementById("graphImpactPanel");
const remediationList = document.getElementById("remediationList");
const visualKpis = document.getElementById("visualKpis");
const riskDonut = document.getElementById("riskDonut");
const languageChart = document.getElementById("languageChart");
const serviceHeatmap = document.getElementById("serviceHeatmap");
const propagationChart = document.getElementById("propagationChart");
const remediationChart = document.getElementById("remediationChart");
const authStatus = document.getElementById("authStatus");
const syncVulnButtons = document.querySelectorAll("[data-sync-source]");
const vulnerabilitySources = document.getElementById("vulnerabilitySources");
const vulnerabilityLibrary = document.getElementById("vulnerabilityLibrary");
const vulnerabilityStatus = document.getElementById("vulnerabilityStatus");
const uploadScanBtn = document.getElementById("uploadScanBtn");

let latestResult = null;
let graphState = null;
let showAllVulnerabilities = false;

initPage();

function initPage() {
  if (page === "login") {
    bindAuthActions();
    return;
  }
  if (page === "analysis") {
    bindAnalysisActions();
  }
  if (page === "history" || page === "graph") {
    loadHistory();
  }
  if (page === "vulnerabilities") {
    bindVulnerabilityLibrary();
    loadVulnerabilityLibrary();
  }
  bindTabs();
  bindGraphTools();
  bindVisualNavigation();
  ensureModal();

  const cached = loadCachedResult();
  if (cached) {
    latestResult = cached;
    renderForPage(cached);
  } else if (["risk", "graph", "reports", "remediation", "visualization"].includes(page)) {
    renderEmptyForPage();
  }
}

function bindAuthActions() {
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  const tabs = document.querySelectorAll(".auth-tab");

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.authTab;
      tabs.forEach((item) => item.classList.toggle("active", item === tab));
      loginForm.classList.toggle("hidden", target !== "login");
      registerForm.classList.toggle("hidden", target !== "register");
      setAuthStatus("请登录或注册后进入系统。");
    });
  });

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(loginForm);
    await submitAuth("/api/login", {
      account: formData.get("account"),
      password: formData.get("password"),
    });
  });

  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(registerForm);
    await submitAuth("/api/register", {
      username: formData.get("username"),
      email: formData.get("email"),
      password: formData.get("password"),
    });
  });
}

async function submitAuth(url, payload) {
  setAuthStatus("正在处理，请稍候...");
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "登录失败");
    setAuthStatus(`欢迎，${data.user.username}，正在进入项目...`, "success");
    window.location.href = "/home";
  } catch (error) {
    setAuthStatus(error.message, "error");
  }
}

function setAuthStatus(message, tone = "") {
  if (!authStatus) return;
  authStatus.textContent = message;
  authStatus.className = `auth-status ${tone}`.trim();
}

function bindAnalysisActions() {
  document.getElementById("scanBtn").addEventListener("click", runCustomScan);
  document.getElementById("sampleBtn").addEventListener("click", loadSampleProject);
  uploadScanBtn?.addEventListener("click", runUploadedScan);
}

function bindTabs() {
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab-button").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".compact-result-list").forEach((item) => item.classList.add("hidden"));
      button.classList.add("active");
      document.getElementById(button.dataset.target)?.classList.remove("hidden");
    });
  });
}

function bindGraphTools() {
  if (!graphTools) return;
  graphTools.addEventListener("click", (event) => {
    const action = event.target.dataset.action;
    if (!action || !graphState) return;
    if (action === "fit") fitGraphToView(true);
    if (action === "zoom-in") graphState.svg.transition().call(graphState.zoom.scaleBy, 1.2);
    if (action === "zoom-out") graphState.svg.transition().call(graphState.zoom.scaleBy, 0.82);
  });
}

function bindVisualNavigation() {
  const buttons = document.querySelectorAll(".visual-nav-item");
  if (!buttons.length) return;
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.visualTarget;
      buttons.forEach((item) => item.classList.toggle("active", item === button));
      document.querySelectorAll(".visual-section").forEach((section) => {
        section.classList.toggle("active", section.id === target);
      });
    });
  });
}

function bindVulnerabilityLibrary() {
  if (!syncVulnButtons.length) return;
  syncVulnButtons.forEach((button) => {
    button.addEventListener("click", () => syncVulnerabilityLibrary(button.dataset.syncSource));
  });
}

async function runCustomScan() {
  const projectPath = document.getElementById("projectPath").value.trim();
  if (!projectPath) {
    setStatus("请先输入项目路径", true);
    return;
  }

  await requestAnalysis("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ project_path: projectPath }),
  });
}

async function runUploadedScan() {
  const folderInput = document.getElementById("projectFolder");
  const archiveInput = document.getElementById("projectArchive");
  const formData = new FormData();
  const archive = archiveInput?.files?.[0];
  const folderFiles = Array.from(folderInput?.files || []);

  if (archive) {
    formData.append("archive", archive, archive.name);
  } else if (folderFiles.length) {
    folderFiles.forEach((file) => {
      formData.append("files", file, file.webkitRelativePath || file.name);
    });
  } else {
    setStatus("请先选择项目文件夹或 ZIP 项目包", true);
    return;
  }

  await requestAnalysis("/api/scan-upload", {
    method: "POST",
    body: formData,
  });
}

async function loadSampleProject() {
  await requestAnalysis("/api/sample");
}

async function requestAnalysis(url, options = {}) {
  setStatus("正在执行扫描，请稍候...");
  try {
    const data = await fetchJson(url, options);
    latestResult = data;
    cacheResult(data);
    renderForPage(data);
    setStatus(`分析完成：${data.project_name}`);
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function loadHistory() {
  if (!historyList) return;
  let data;
  try {
    data = await fetchJson("/api/history");
  } catch (error) {
    historyList.innerHTML = `<div class="empty-state">${error.message}</div>`;
    return;
  }
  historyList.innerHTML = data.items.length
    ? data.items
        .map(
          (item) => `
            <button class="history-item" data-scan-id="${item.id}">
              <strong>${item.project_name}</strong>
              <span>${item.scanned_at}</span>
              <p>漏洞组件：${item.vulnerability_count}</p>
              <p>受影响服务：${item.affected_service_count}</p>
              <div class="history-tags">${renderTagList(item.risk_levels)}</div>
            </button>
          `
        )
        .join("")
    : `<div class="empty-state">暂无扫描记录</div>`;

  historyList.querySelectorAll("[data-scan-id]").forEach((node) => {
    node.addEventListener("click", async () => {
      const scanId = node.getAttribute("data-scan-id");
      setStatus("正在载入历史结果...");
      try {
        const data = await fetchJson(`/api/history/${scanId}`);
        latestResult = data;
        cacheResult(data);
        setStatus(`已载入：${data.project_name} - ${data.scanned_at}`);
      } catch (error) {
        setStatus(error.message, true);
      }
    });
  });
}

function renderForPage(data) {
  if (statsGrid) renderStats(data.statistics);
  if (architectureSummary) renderArchitectureSummary(data.architecture_profile);
  if (summaryPanel) renderSummary(data);
  if (distributionPanel) renderDistribution(data);
  if (vulnerabilityList) renderVulnerabilities(data);
  if (riskList) renderRiskSummary(data);
  if (reportActions) renderReportActions(data);
  if (graphCanvas) renderGraph(data.graph);
  if (graphLegend) renderLegend();
  if (architectureProfile || graphImpactPanel) renderGraphInsights(data);
  if (remediationList) renderRemediation(data.remediation || []);
  if (visualKpis) renderVisualDashboard(data);
}

function renderEmptyForPage() {
  const empty = `<div class="empty-state">请先到“项目扫描”页面执行一次分析，再回来查看结果。</div>`;
  if (summaryPanel) summaryPanel.innerHTML = empty;
  if (architectureSummary) architectureSummary.innerHTML = empty;
  if (distributionPanel) distributionPanel.innerHTML = empty;
  if (vulnerabilityList) vulnerabilityList.innerHTML = empty;
  if (riskList) riskList.innerHTML = empty;
  if (reportActions) reportActions.innerHTML = empty;
  if (graphCanvas) graphCanvas.innerHTML = empty;
  if (graphStats) graphStats.innerHTML = `<span>暂无图谱数据</span>`;
  if (architectureProfile) architectureProfile.innerHTML = `<strong>项目架构识别</strong>${empty}`;
  if (graphImpactPanel) graphImpactPanel.innerHTML = `<strong>模块影响展示</strong>${empty}`;
  if (remediationList) remediationList.innerHTML = empty;
  if (visualKpis) visualKpis.innerHTML = empty;
  if (riskDonut) riskDonut.innerHTML = empty;
  if (languageChart) languageChart.innerHTML = empty;
  if (serviceHeatmap) serviceHeatmap.innerHTML = empty;
  if (propagationChart) propagationChart.innerHTML = empty;
  if (remediationChart) remediationChart.innerHTML = empty;
}

async function loadVulnerabilityLibrary() {
  if (!vulnerabilitySources || !vulnerabilityLibrary) return;
  try {
    const [sourcesResponse, libraryResponse] = await Promise.all([
      fetch("/api/vulnerability-sources"),
      fetch("/api/vulnerabilities"),
    ]);
    const sources = await parseJsonResponse(sourcesResponse);
    const library = await parseJsonResponse(libraryResponse);
    if (!sourcesResponse.ok) throw new Error(sources.error || "加载漏洞来源失败");
    if (!libraryResponse.ok) throw new Error(library.error || "加载漏洞缓存失败");
    renderVulnerabilitySources(sources.items || []);
    renderVulnerabilityLibrary(library);
  } catch (error) {
    if (vulnerabilityStatus) vulnerabilityStatus.textContent = error.message;
  }
}

async function syncVulnerabilityLibrary(source = "nvd") {
  const input = document.getElementById("syncComponents");
  const components = (input?.value || "")
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
  const sourceLabel = source === "oss" ? "OSS Index" : "NVD";
  if (vulnerabilityStatus) vulnerabilityStatus.textContent = `正在同步 ${sourceLabel} 漏洞数据...`;
  syncVulnButtons.forEach((button) => (button.disabled = true));
  openSyncProgressModal(components, sourceLabel);
  try {
    const response = await fetch(`/api/vulnerabilities/sync/${source}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ components }),
    });
    const data = await parseJsonResponse(response);
    if (!response.ok) throw new Error(data.error || "同步失败");
    if (vulnerabilityStatus) vulnerabilityStatus.textContent = data.message;
    openSyncResultModal(data);
    await loadVulnerabilityLibrary();
  } catch (error) {
    if (vulnerabilityStatus) vulnerabilityStatus.textContent = error.message;
    openDetailModal("同步失败", `<p class="modal-note">${error.message}</p>`);
  } finally {
    syncVulnButtons.forEach((button) => (button.disabled = false));
  }
}

function openSyncProgressModal(components, sourceLabel = "漏洞源") {
  openDetailModal(
    `正在同步 ${sourceLabel}`,
    `
      <p class="modal-note">系统正在从 ${sourceLabel} 获取漏洞数据，组件来源：${components.length ? `${components.length} 个手动输入组件` : "最近一次扫描结果"}。</p>
      <div class="progress-shell">
        <div class="progress-bar indeterminate"></div>
      </div>
      <div class="sync-steps">
        <span>连接漏洞源</span>
        <span>匹配组件</span>
        <span>写入缓存</span>
      </div>
    `
  );
}

function openSyncResultModal(data) {
  const rows = data.sources || [data];
  const sourceRows = rows
    .map(
      (item) => `
        <div class="sync-result-row">
          <span>${item.source}</span>
          <strong>${item.saved || 0} 条</strong>
          <small>${item.status}</small>
        </div>
      `
    )
    .join("");
  openDetailModal(
    "同步完成",
    `
      <div class="sync-result-summary">
        <div><span>写入记录</span><strong>${data.saved || 0}</strong></div>
        <div><span>同步状态</span><strong>${data.status || "unknown"}</strong></div>
      </div>
      <p class="modal-note">${data.message || "漏洞库同步完成。"}</p>
      <div class="sync-result-list">${sourceRows}</div>
    `
  );
}

async function parseJsonResponse(response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return {
      error: response.ok
        ? "接口返回内容不是 JSON，请刷新页面后重试。"
        : `接口返回异常页面，状态码 ${response.status}。请确认 Flask 已重启到最新版本。`,
    };
  }
}

function renderVulnerabilitySources(items) {
  vulnerabilitySources.innerHTML = items.length
    ? items
        .map(
          (item) => `
            <div class="source-item">
              <strong>${item.source_name}</strong>
              <span>${item.enabled ? "已启用" : "待配置"}</span>
              <p>${item.last_message || "暂无同步记录"}</p>
              <small>${item.last_synced_at || "未同步"}</small>
            </div>
          `
        )
        .join("")
    : `<div class="empty-state">暂无漏洞来源</div>`;
}

function renderVulnerabilityLibrary(data) {
  const items = data.items || [];
  const visibleItems = showAllVulnerabilities ? items : items.slice(0, 12);
  vulnerabilityLibrary.innerHTML = `
    <div class="repair-summary-grid">
      <div><span>本地漏洞</span><strong>${data.local_count || 0}</strong></div>
      <div><span>外部缓存</span><strong>${data.external_count || 0}</strong></div>
      <div><span>当前展示</span><strong>${items.length}</strong></div>
    </div>
    ${renderVulnerabilityBarCharts(items)}
    ${
      items.length
        ? `
          <div class="vuln-table-toolbar">
            <strong>${showAllVulnerabilities ? "全部漏洞记录" : "精简漏洞记录"}</strong>
            <button type="button" class="detail-button" id="toggleAllVulnerabilities">
              ${showAllVulnerabilities ? "收起列表" : `查看所有漏洞（${items.length}）`}
            </button>
          </div>
          <div class="table-shell">
            <table class="data-table">
              <thead>
                <tr>
                  <th>来源</th>
                  <th>CVE</th>
                  <th>组件</th>
                  <th>严重等级</th>
                  <th>CVSS</th>
                  <th>影响版本</th>
                </tr>
              </thead>
              <tbody>
                ${visibleItems
                  .map(
                    (item) => `
                      <tr>
                        <td>${item.source_name}</td>
                        <td><strong>${item.cve_id}</strong></td>
                        <td>${item.component_name}</td>
                        <td><span class="status-badge ${severityBadgeClass(item.severity)}">${item.severity}</span></td>
                        <td><span class="mono-value">${item.cvss_score || 0}</span></td>
                        <td>${(item.affected_versions || []).join("、") || "NVD 未给出明确范围"}</td>
                      </tr>
                    `
                  )
                  .join("")}
              </tbody>
            </table>
          </div>
        `
        : `<div class="empty-state">暂无外部漏洞缓存，请点击上方按钮同步 NVD 或 OSS Index。</div>`
    }
  `;
  document.getElementById("toggleAllVulnerabilities")?.addEventListener("click", () => {
    showAllVulnerabilities = !showAllVulnerabilities;
    renderVulnerabilityLibrary(data);
  });
}

function renderVulnerabilityBarCharts(items) {
  const nvdGroups = groupVulnerabilitiesByComponent(items.filter((item) => item.source_name === "NVD"));
  const ossGroups = groupVulnerabilitiesByComponent(items.filter((item) => item.source_name === "OSS Index"));
  return `
    <div class="vuln-chart-grid">
      ${renderSourceBarChart("NVD 漏洞聚合", nvdGroups)}
      ${renderSourceBarChart("OSS Index 漏洞聚合", ossGroups)}
    </div>
  `;
}

function groupVulnerabilitiesByComponent(items) {
  const grouped = new Map();
  items.forEach((item) => {
    const key = item.component_name || "unknown";
    if (!grouped.has(key)) grouped.set(key, { name: key, count: 0, maxScore: 0, severities: new Set() });
    const group = grouped.get(key);
    group.count += 1;
    group.maxScore = Math.max(group.maxScore, Number(item.cvss_score || 0));
    group.severities.add(item.severity || "unknown");
  });
  return Array.from(grouped.values())
    .map((item) => ({ ...item, severities: Array.from(item.severities) }))
    .sort((a, b) => b.count - a.count || b.maxScore - a.maxScore)
    .slice(0, 10);
}

function renderSourceBarChart(title, groups) {
  if (!groups.length) {
    return `
      <article class="vuln-bar-card">
        <div class="section-title"><h2>${title}</h2></div>
        <div class="empty-state">暂无该来源的漏洞缓存</div>
      </article>
    `;
  }
  const maxCount = Math.max(...groups.map((item) => item.count), 1);
  const width = 620;
  const height = 340;
  const margin = { top: 22, right: 24, bottom: 92, left: 46 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const band = plotWidth / groups.length;
  const barWidth = Math.min(42, Math.max(18, band * 0.56));
  const ticks = buildAxisTicks(maxCount);
  return `
    <article class="vuln-bar-card">
      <div class="section-title"><h2>${title}</h2><span>按组件聚合相似漏洞</span></div>
      <div class="vuln-axis-chart" role="img" aria-label="${title}柱状图，横轴为组件，纵轴为漏洞数量">
        <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet">
          <g class="axis-grid">
            ${ticks
              .map((tick) => {
                const y = margin.top + plotHeight - (tick / maxCount) * plotHeight;
                return `
                  <line x1="${margin.left}" y1="${y}" x2="${width - margin.right}" y2="${y}"></line>
                  <text x="${margin.left - 10}" y="${y + 4}" text-anchor="end">${tick}</text>
                `;
              })
              .join("")}
          </g>
          <line class="chart-axis" x1="${margin.left}" y1="${margin.top}" x2="${margin.left}" y2="${height - margin.bottom}"></line>
          <line class="chart-axis" x1="${margin.left}" y1="${height - margin.bottom}" x2="${width - margin.right}" y2="${height - margin.bottom}"></line>
          <text class="axis-title" x="16" y="${margin.top + plotHeight / 2}" transform="rotate(-90 16 ${margin.top + plotHeight / 2})">漏洞数量</text>
          <text class="axis-title" x="${margin.left + plotWidth / 2}" y="${height - 10}" text-anchor="middle">组件名称</text>
          ${groups
            .map((item, index) => {
              const x = margin.left + index * band + (band - barWidth) / 2;
              const barHeight = Math.max(4, (item.count / maxCount) * plotHeight);
              const y = margin.top + plotHeight - barHeight;
              return `
                <g class="vuln-column">
                  <title>${item.name}：${item.count} 个漏洞，最高 CVSS ${item.maxScore || 0}</title>
                  <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="6"></rect>
                  <text class="bar-value" x="${x + barWidth / 2}" y="${y - 7}" text-anchor="middle">${item.count}</text>
                  <text class="bar-label" x="${x + barWidth / 2}" y="${height - margin.bottom + 18}" text-anchor="end" transform="rotate(-38 ${x + barWidth / 2} ${height - margin.bottom + 18})">${truncateText(item.name, 14)}</text>
                </g>
              `;
            })
            .join("")}
        </svg>
      </div>
    </article>
  `;
}

function buildAxisTicks(maxCount) {
  const top = Math.max(1, maxCount);
  const step = Math.max(1, Math.ceil(top / 4));
  const ticks = [];
  for (let value = 0; value <= top; value += step) ticks.push(value);
  if (!ticks.includes(top)) ticks.push(top);
  return ticks;
}

function renderStats(stats) {
  const cards = [
    { label: "组件总数", value: stats.component_count },
    { label: "服务数量", value: stats.service_count },
    { label: "漏洞组件数", value: stats.vulnerable_component_count },
    { label: "受影响服务数", value: stats.affected_service_count },
  ];

  statsGrid.innerHTML = cards
    .map(
      (card) => `
        <div class="stat-card">
          <span>${card.label}</span>
          <strong>${card.value}</strong>
        </div>
      `
    )
    .join("");
}

function renderArchitectureSummary(profile) {
  if (!profile) {
    architectureSummary.innerHTML = `<div class="empty-state">暂无项目架构识别结果</div>`;
    return;
  }

  architectureSummary.innerHTML = `
    <div class="architecture-card">
      <div>
        <span>项目类型识别</span>
        <strong>${profile.architecture_type}</strong>
        <p>${profile.description}</p>
      </div>
      <div class="impact-tags">
        ${renderImpactTag("前端", profile.frontend_modules)}
        ${renderImpactTag("后端", profile.backend_modules)}
        ${renderImpactTag("网关", profile.gateway_modules)}
      </div>
    </div>
  `;
}

function renderSummary(data) {
  const topRisk = data.insights.top_risk_component;
  const deepest = data.insights.deepest_spread_component;
  summaryPanel.innerHTML = `
    <div class="summary-item">
      <span>项目名称</span>
      <strong>${data.project_name}</strong>
      <p>${data.project_path}</p>
    </div>
    <div class="summary-item">
      <span>扫描时间</span>
      <strong>${data.scanned_at}</strong>
      <p>最近一次已载入结果</p>
    </div>
    <div class="summary-item">
      <span>最高风险组件</span>
      <strong>${topRisk ? topRisk.component_name : "暂无"}</strong>
      <p>${topRisk ? `${topRisk.risk_level}，评分 ${topRisk.score}` : "未发现高风险组件"}</p>
    </div>
    <div class="summary-item">
      <span>传播最深组件</span>
      <strong>${deepest ? deepest.component_name : "暂无"}</strong>
      <p>${deepest ? `传播深度 ${deepest.max_depth}` : "暂无传播路径"}</p>
    </div>
  `;
}

function renderDistribution(data) {
  distributionPanel.innerHTML = `
    <div class="distribution-block">
      <h3>语言分布</h3>
      ${renderBars(data.statistics.language_distribution)}
    </div>
    <div class="distribution-block">
      <h3>风险分布</h3>
      ${renderBars(data.statistics.risk_distribution)}
    </div>
    <div class="distribution-block">
      <h3>服务情况</h3>
      ${renderServiceHeat(data.insights.service_heat)}
    </div>
  `;
}

function renderVulnerabilities(data) {
  const items = data.vulnerabilities;
  vulnerabilityList.innerHTML = items.length
    ? `
      <div class="table-shell">
        <table class="data-table">
          <thead>
            <tr>
              <th>组件</th>
              <th>所属服务</th>
              <th>版本</th>
              <th>漏洞编号</th>
              <th>影响范围</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
        ${items
          .map((item, index) => {
            const cves = item.vulnerabilities.map((vuln) => vuln.cve_id).join("、");
            return `
              <tr>
                <td><strong>${item.component_name}</strong></td>
                <td>${item.service}</td>
                <td><span class="mono-value">${item.component_version}</span></td>
                <td>${cves}</td>
                <td><span class="status-badge neutral">${item.affected_services.length} 个服务</span></td>
                <td><button type="button" class="detail-button" data-detail="vulnerability" data-index="${index}">详情</button></td>
              </tr>
            `;
          })
          .join("")}
          </tbody>
        </table>
      </div>
    `
    : `<div class="empty-state">暂无漏洞命中</div>`;
  bindDetailButtons(data);
}

function renderRiskSummary(data) {
  const items = data.risk_summary;
  riskList.innerHTML = items.length
    ? `
      <div class="table-shell">
        <table class="data-table">
          <thead>
            <tr>
              <th>组件</th>
              <th>风险等级</th>
              <th>评分</th>
              <th>影响服务</th>
              <th>传播深度</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
        ${items
          .map(
            (item, index) => `
              <tr>
                <td><strong>${item.component_name}</strong></td>
                <td><span class="status-badge ${riskBadgeClass(item.risk_level)}">${item.risk_level}</span></td>
                <td><span class="mono-value">${item.score}</span></td>
                <td>${item.affected_services.length} 个</td>
                <td>${item.max_depth}</td>
                <td><button type="button" class="detail-button" data-detail="risk" data-index="${index}">详情</button></td>
              </tr>
            `
          )
          .join("")}
          </tbody>
        </table>
      </div>
    `
    : `<div class="empty-state">暂无风险评估数据</div>`;
  bindDetailButtons(data);
}

function renderRemediation(items) {
  remediationList.innerHTML = items.length
    ? `
      <div class="repair-summary-grid">
        <div><span>待修复组件</span><strong>${items.length}</strong></div>
        <div><span>高优先级</span><strong>${items.filter((item) => Math.max(1, 6 - item.priority) <= 2).length}</strong></div>
        <div><span>受影响服务</span><strong>${new Set(items.flatMap((item) => item.affected_services || [])).size}</strong></div>
      </div>
      <div class="repair-board">
        ${items
          .map(
            (item, index) => `
              <article class="repair-card">
                <div class="repair-card-head">
                  <span class="status-badge priority">P${Math.max(1, 6 - item.priority)}</span>
                  <span class="status-badge ${riskBadgeClass(item.risk_level)}">${item.risk_level}</span>
                </div>
                <h2>${item.component_name}</h2>
                <p>${item.service}</p>
                <div class="version-flow">
                  <span>${item.current_version}</span>
                  <i></i>
                  <strong>${item.target_version}</strong>
                </div>
                <button type="button" class="detail-button" data-repair-index="${index}">查看修复依据</button>
              </article>
            `
          )
          .join("")}
      </div>
    `
    : `<div class="empty-state">暂无修复建议</div>`;

  remediationList.querySelectorAll("[data-repair-index]").forEach((button) => {
    button.onclick = () => {
      const item = items[Number(button.dataset.repairIndex)];
      openDetailModal(
        `${item.component_name} 修复建议`,
        `
          <dl class="detail-grid">
            <div><dt>风险等级</dt><dd>${item.risk_level}</dd></div>
            <div><dt>风险评分</dt><dd>${item.score}</dd></div>
            <div><dt>当前版本</dt><dd>${item.current_version}</dd></div>
            <div><dt>建议版本</dt><dd>${item.target_version}</dd></div>
            <div><dt>所属服务</dt><dd>${item.service}</dd></div>
            <div><dt>受影响服务</dt><dd>${item.affected_services.join("、") || "无"}</dd></div>
          </dl>
          <h3>关联漏洞</h3>
          <p>${item.cve_ids.join("、")}</p>
          <h3>处理建议</h3>
          <p>${item.suggestion}</p>
        `
      );
    };
  });
}

function renderVisualDashboard(data) {
  renderVisualKpis(data);
  renderRiskMatrix(data.risk_summary || []);
  renderLanguageRiskBars(data.components || [], data.vulnerabilities || []);
  renderServiceHeatmap(data.insights.service_heat || []);
  renderRemediationPriority(data.remediation || []);
}

function renderVisualKpis(data) {
  const stats = data.statistics;
  const vulnerableRatio = data.insights?.vulnerable_ratio ?? 0;
  visualKpis.innerHTML = [
    ["服务模块", stats.service_count],
    ["依赖组件", stats.component_count],
    ["风险组件", stats.vulnerable_component_count],
    ["风险命中率", `${vulnerableRatio}%`],
  ]
    .map(
      ([label, value]) => `
        <div class="visual-kpi">
          <span>${label}</span>
          <strong>${value}</strong>
        </div>
      `
    )
    .join("");
}

function renderRiskDonut(distribution) {
  riskDonut.innerHTML = "";
  const entries = Object.entries(distribution);
  if (!entries.length) {
    riskDonut.innerHTML = `<div class="empty-state">暂无风险数据</div>`;
    return;
  }

  const width = riskDonut.clientWidth || 360;
  const height = 260;
  const radius = Math.min(width, height) / 2 - 20;
  const colors = {
    严重风险: "#991b1b",
    高风险: "#92400e",
    中风险: "#a16207",
    低风险: "#475569",
  };

  const svg = d3.select(riskDonut).append("svg").attr("viewBox", `0 0 ${width} ${height}`);
  const group = svg.append("g").attr("transform", `translate(${width / 2},${height / 2})`);
  const pie = d3.pie().value((d) => d[1]).sort(null);
  const arc = d3.arc().innerRadius(radius * 0.58).outerRadius(radius);
  const total = d3.sum(entries, (d) => d[1]);

  group
    .selectAll("path")
    .data(pie(entries))
    .enter()
    .append("path")
    .attr("d", arc)
    .attr("fill", (d) => colors[d.data[0]] || "#64748b")
    .attr("stroke", "#fff")
    .attr("stroke-width", 3);

  group.append("text").attr("class", "donut-number").attr("text-anchor", "middle").attr("y", -4).text(total);
  group.append("text").attr("class", "donut-label").attr("text-anchor", "middle").attr("y", 20).text("风险组件");

  const legend = d3.select(riskDonut).append("div").attr("class", "chart-legend");
  entries.forEach(([label, value]) => {
    legend
      .append("span")
      .html(`<i style="background:${colors[label] || "#64748b"}"></i>${label} ${value}`);
  });
}

function renderRiskMatrix(items) {
  riskDonut.innerHTML = "";
  if (!items.length) {
    riskDonut.innerHTML = `<div class="empty-state">暂无风险评估数据</div>`;
    return;
  }
  const levels = ["严重风险", "高风险", "中风险", "低风险"];
  const buckets = levels.map((level) => ({
    level,
    items: items.filter((item) => item.risk_level === level),
  }));
  riskDonut.innerHTML = buckets
    .map(
      (bucket) => `
        <div class="risk-matrix-row">
          <span class="status-badge ${riskBadgeClass(bucket.level)}">${bucket.level}</span>
          <strong>${bucket.items.length}</strong>
          <div>
            ${
              bucket.items.length
                ? bucket.items
                    .slice(0, 3)
                    .map((item) => `<small>${item.component_name}</small>`)
                    .join("")
                : "<small>暂无</small>"
            }
          </div>
        </div>
      `
    )
    .join("");
}

function renderLanguageRiskBars(components, vulnerabilities) {
  if (!languageChart) return;
  languageChart.innerHTML = "";
  const vulnerableIds = new Set(vulnerabilities.map((item) => item.component_id));
  const grouped = new Map();
  components.forEach((component) => {
    const language = component.language || "unknown";
    if (!grouped.has(language)) grouped.set(language, { total: 0, vulnerable: 0 });
    const item = grouped.get(language);
    item.total += 1;
    if (vulnerableIds.has(component.component_id)) item.vulnerable += 1;
  });
  const entries = Array.from(grouped.entries()).sort((a, b) => b[1].vulnerable - a[1].vulnerable);
  if (!entries.length) {
    languageChart.innerHTML = `<div class="empty-state">暂无语言依赖数据</div>`;
    return;
  }
  languageChart.innerHTML = entries
    .map(([language, item]) => {
      const ratio = item.total ? Math.round((item.vulnerable / item.total) * 100) : 0;
      return `
        <div class="language-risk-row">
          <div>
            <strong>${language}</strong>
            <span>${item.vulnerable} / ${item.total} 个组件存在风险</span>
          </div>
          <div class="risk-track"><i style="width:${ratio}%"></i></div>
          <b>${ratio}%</b>
        </div>
      `;
    })
    .join("");
}

function renderHorizontalBars(container, distribution, unit) {
  if (!container) return;
  container.innerHTML = "";
  const entries = Object.entries(distribution);
  if (!entries.length) {
    container.innerHTML = `<div class="empty-state">暂无数据</div>`;
    return;
  }

  const width = container.clientWidth || 420;
  const height = Math.max(220, entries.length * 46);
  const margin = { top: 16, right: 42, bottom: 20, left: 92 };
  const svg = d3.select(container).append("svg").attr("viewBox", `0 0 ${width} ${height}`);
  const x = d3.scaleLinear().domain([0, d3.max(entries, (d) => d[1]) || 1]).range([0, width - margin.left - margin.right]);
  const y = d3.scaleBand().domain(entries.map((d) => d[0])).range([margin.top, height - margin.bottom]).padding(0.28);

  svg
    .append("g")
    .selectAll("rect")
    .data(entries)
    .enter()
    .append("rect")
    .attr("x", margin.left)
    .attr("y", (d) => y(d[0]))
    .attr("width", (d) => x(d[1]))
    .attr("height", y.bandwidth())
    .attr("rx", 6)
    .attr("fill", "#334155");

  svg
    .append("g")
    .selectAll("text.label")
    .data(entries)
    .enter()
    .append("text")
    .attr("class", "chart-axis-label")
    .attr("x", margin.left - 10)
    .attr("y", (d) => y(d[0]) + y.bandwidth() / 2 + 5)
    .attr("text-anchor", "end")
    .text((d) => d[0]);

  svg
    .append("g")
    .selectAll("text.value")
    .data(entries)
    .enter()
    .append("text")
    .attr("class", "chart-value")
    .attr("x", (d) => margin.left + x(d[1]) + 8)
    .attr("y", (d) => y(d[0]) + y.bandwidth() / 2 + 5)
    .text((d) => `${d[1]} ${unit}`);
}

function renderServiceHeatmap(items) {
  serviceHeatmap.innerHTML = "";
  if (!items.length) {
    serviceHeatmap.innerHTML = `<div class="empty-state">暂无服务数据</div>`;
    return;
  }

  const maxVuln = Math.max(...items.map((item) => item.vulnerability_count), 1);
  serviceHeatmap.innerHTML = items
    .slice()
    .sort((a, b) => b.vulnerability_count - a.vulnerability_count)
    .map(
      (item) => `
        <div class="impact-rank-row">
          <div>
            <strong>${item.service}</strong>
            <span>${item.component_count} 个组件</span>
          </div>
          <div class="risk-track"><i style="width:${Math.max(6, (item.vulnerability_count / maxVuln) * 100)}%"></i></div>
          <b>${item.vulnerability_count}</b>
        </div>
      `
    )
    .join("");
}

function renderPropagationBubbles(items) {
  propagationChart.innerHTML = "";
  const data = items
    .map((item) => ({
      name: item.component_name,
      service: item.service,
      score: item.propagation_score || 0,
      affected: item.affected_services.length,
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 12);

  if (!data.length) {
    propagationChart.innerHTML = `<div class="empty-state">暂无传播评分数据</div>`;
    return;
  }

  const width = propagationChart.clientWidth || 420;
  const height = 300;
  const svg = d3.select(propagationChart).append("svg").attr("viewBox", `0 0 ${width} ${height}`);
  const pack = d3.pack().size([width, height]).padding(8);
  const root = d3.hierarchy({ children: data }).sum((d) => Math.max(d.score, 1));
  const nodes = pack(root).leaves();

  const group = svg.selectAll("g").data(nodes).enter().append("g").attr("transform", (d) => `translate(${d.x},${d.y})`);
  group.append("circle").attr("r", (d) => d.r).attr("fill", "#f8fafc").attr("stroke", "#334155").attr("stroke-width", 2);
  group.append("text").attr("class", "bubble-title").attr("text-anchor", "middle").attr("y", -2).text((d) => truncateText(d.data.name, 10));
  group.append("text").attr("class", "bubble-score").attr("text-anchor", "middle").attr("y", 15).text((d) => d.data.score);
}

function renderRemediationPriority(items) {
  remediationChart.innerHTML = "";
  const topItems = items.slice(0, 10);
  if (!topItems.length) {
    remediationChart.innerHTML = `<div class="empty-state">暂无修复建议</div>`;
    return;
  }

  remediationChart.innerHTML = topItems
    .map(
      (item) => `
        <div class="repair-queue-row">
          <span class="status-badge priority">P${Math.max(1, 6 - item.priority)}</span>
          <div>
            <strong>${item.component_name}</strong>
            <span>${item.service}：${item.current_version} → ${item.target_version}</span>
          </div>
          <b>${item.affected_services.length} 个服务</b>
        </div>
      `
    )
    .join("");
}

function truncateText(value, maxLength) {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}

function riskBadgeClass(level = "") {
  if (level.includes("严重") || level.includes("高")) return "danger";
  if (level.includes("中")) return "warning";
  if (level.includes("低")) return "safe";
  return "neutral";
}

function severityBadgeClass(level = "") {
  const normalized = level.toLowerCase();
  if (normalized.includes("critical") || normalized.includes("high")) return "danger";
  if (normalized.includes("medium")) return "warning";
  if (normalized.includes("low")) return "safe";
  return "neutral";
}

function bindDetailButtons(data) {
  document.querySelectorAll(".detail-button").forEach((button) => {
    button.onclick = () => {
      const index = Number(button.dataset.index);
      if (button.dataset.detail === "vulnerability") {
        openVulnerabilityDetail(data, data.vulnerabilities[index]);
      } else {
        openRiskDetail(data, data.risk_summary[index]);
      }
    };
  });
}

function openVulnerabilityDetail(data, item) {
  const fixedVersions = item.vulnerabilities.map((vuln) => vuln.fixed_version).join("、");
  const descriptions = item.vulnerabilities
    .map((vuln) => `<li><strong>${vuln.cve_id}</strong>：${vuln.description}</li>`)
    .join("");
  openDetailModal(
    `${item.component_name} ${item.component_version}`,
    `
      <dl class="detail-grid">
        <div><dt>所属服务</dt><dd>${item.service}</dd></div>
        <div><dt>受影响服务</dt><dd>${item.affected_services.join("、") || "无"}</dd></div>
        <div><dt>建议修复版本</dt><dd>${fixedVersions}</dd></div>
        <div><dt>传播评分</dt><dd>${item.propagation_score}</dd></div>
        <div><dt>组件重要性</dt><dd>${item.importance}</dd></div>
        <div><dt>影响路径</dt><dd>${renderPathPreview(data, item.component_id)}</dd></div>
      </dl>
      <h3>漏洞说明</h3>
      <ul class="detail-list">${descriptions}</ul>
      <h3>分析方法</h3>
      <p>${item.analysis_methods.join("、")}</p>
    `
  );
}

function openRiskDetail(data, risk) {
  const item = data.vulnerabilities.find((vuln) => vuln.component_id === risk.component_id);
  openDetailModal(
    `${risk.component_name} 风险详情`,
    `
      <dl class="detail-grid">
        <div><dt>风险等级</dt><dd>${risk.risk_level}</dd></div>
        <div><dt>风险评分</dt><dd>${risk.score}</dd></div>
        <div><dt>受影响服务</dt><dd>${risk.affected_services.join("、") || "无"}</dd></div>
        <div><dt>传播深度</dt><dd>${item?.max_depth ?? 0}</dd></div>
        <div><dt>传播评分</dt><dd>${item?.propagation_score ?? 0}</dd></div>
        <div><dt>最短路径</dt><dd>${renderPathPreview(data, risk.component_id)}</dd></div>
      </dl>
      <h3>判断依据</h3>
      <p>${risk.reason || "系统综合漏洞等级、受影响服务数量、传播深度、组件重要性和影响路径给出风险结果。"}</p>
    `
  );
}

function renderReportActions(data) {
  const reports = data.reports || data;
  if (page === "home") {
    reportActions.innerHTML = `
      <button type="button" class="report-query-card" id="quickReportBtn">
        <span>网页查询</span>
        <strong>查看可视化结果摘要</strong>
      </button>
      <div class="home-report-files">
        <a href="/api/reports/${reports.html}">
          <span>HTML</span>
          <strong>下载报告</strong>
        </a>
        <a href="/api/reports/${reports.json}">
          <span>JSON</span>
          <strong>下载数据</strong>
        </a>
        <a href="/api/reports/${reports.txt}">
          <span>TXT</span>
          <strong>下载文本</strong>
        </a>
      </div>
    `;
    document.getElementById("quickReportBtn")?.addEventListener("click", () => openReportSummaryModal(data));
    return;
  }

  reportActions.innerHTML = `
    <div class="table-shell report-table">
      <table class="data-table">
        <thead>
          <tr>
            <th>报告类型</th>
            <th>适用场景</th>
            <th>文件</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>JSON</strong></td>
            <td>系统集成与数据归档</td>
            <td><span class="mono-value">${reports.json}</span></td>
            <td><a class="report-link" href="/api/reports/${reports.json}">下载</a></td>
          </tr>
          <tr>
            <td><strong>TXT</strong></td>
            <td>论文附件与文本审阅</td>
            <td><span class="mono-value">${reports.txt}</span></td>
            <td><a class="report-link" href="/api/reports/${reports.txt}">下载</a></td>
          </tr>
          <tr>
            <td><strong>HTML</strong></td>
            <td>可视化汇报与浏览器预览</td>
            <td><span class="mono-value">${reports.html}</span></td>
            <td><a class="report-link" href="/api/reports/${reports.html}">下载</a></td>
          </tr>
        </tbody>
      </table>
    </div>
  `;
}

function openReportSummaryModal(data) {
  const stats = data.statistics || {};
  const risks = data.statistics?.risk_distribution || {};
  const topRisk = data.insights?.top_risk_component;
  const riskText = Object.entries(risks)
    .map(([level, count]) => `${level} ${count}`)
    .join("、") || "暂无风险";
  openDetailModal(
    "项目分析结果摘要",
    `
      <dl class="detail-grid compact">
        <div><dt>项目名称</dt><dd>${data.project_name || "暂无"}</dd></div>
        <div><dt>扫描时间</dt><dd>${data.scanned_at || "暂无"}</dd></div>
        <div><dt>漏洞组件</dt><dd>${stats.vulnerable_component_count || 0} 个</dd></div>
        <div><dt>受影响服务</dt><dd>${stats.affected_service_count || 0} 个</dd></div>
        <div><dt>严重等级</dt><dd>${riskText}</dd></div>
        <div><dt>最高风险</dt><dd>${topRisk ? `${topRisk.component_name}，${topRisk.risk_level}` : "暂无"}</dd></div>
      </dl>
      <div class="modal-actions">
        <a class="report-link" href="/reports">打开报告中心</a>
        <a class="secondary-link compact" href="/graph">查看传播路径</a>
      </div>
    `
  );
}

function renderGraph(graph) {
  graphCanvas.innerHTML = "";
  const nodes = graph.nodes.map((node) => ({ ...node }));
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  const edges = graph.edges
    .map((edge) => ({ ...edge, sourceId: edge.source, targetId: edge.target }))
    .filter((edge) => nodesById.has(edge.sourceId) && nodesById.has(edge.targetId));

  const viewportWidth = graphCanvas.clientWidth || 1100;
  const viewportHeight = graphCanvas.clientHeight || 720;
  renderGraphStats(nodes, edges);

  const svg = d3.select("#graphCanvas").append("svg").attr("viewBox", `0 0 ${viewportWidth} ${viewportHeight}`);
  const defs = svg.append("defs");
  defs
    .append("marker")
    .attr("id", "arrow-component")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 21)
    .attr("refY", 0)
    .attr("markerWidth", 7)
    .attr("markerHeight", 7)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("class", "arrow component-arrow");
  defs
    .append("marker")
    .attr("id", "arrow-service")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 24)
    .attr("refY", 0)
    .attr("markerWidth", 7)
    .attr("markerHeight", 7)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("class", "arrow service-arrow");

  const zoomLayer = svg.append("g").attr("class", "graph-zoom-layer");
  const zoom = d3.zoom().scaleExtent([0.08, 4.5]).on("zoom", (event) => {
    zoomLayer.attr("transform", event.transform);
  });
  svg.call(zoom);

  const link = zoomLayer
    .append("g")
    .selectAll("path")
    .data(edges)
    .enter()
    .append("path")
    .attr("class", (d) => edgeClassName(d))
    .attr("marker-end", (d) => (isServiceRelation(d) ? "url(#arrow-service)" : "url(#arrow-component)"));

  const node = zoomLayer
    .append("g")
    .selectAll("g")
    .data(nodes)
    .enter()
    .append("g")
    .attr("class", (d) => graphNodeClassName(d))
    .on("click", (event, d) => {
      event.stopPropagation();
      selectGraphNode(d.id);
    });

  node
    .filter((d) => d.node_type === "service")
    .append("rect")
    .attr("class", "node-shape")
    .attr("x", -76)
    .attr("y", -19)
    .attr("width", 152)
    .attr("height", 38)
    .attr("rx", 10);

  node
    .filter((d) => d.node_type !== "service")
    .append("circle")
    .attr("class", "node-shape")
    .attr("r", (d) => (d.vulnerable ? 16 : 11));

  node
    .append("text")
    .attr("class", "graph-label")
    .attr("text-anchor", "middle")
    .attr("y", (d) => (d.node_type === "service" ? 5 : 31))
    .text((d) => truncateText(d.label, d.node_type === "service" ? 18 : 16));

  node.append("title").text((d) => `${d.node_type === "service" ? "服务模块" : "依赖库组件"}：${d.label}${d.version ? ` ${d.version}` : ""}`);

  const simulation = d3
    .forceSimulation(nodes)
    .force(
      "link",
      d3
        .forceLink(edges)
        .id((d) => d.id)
        .distance((edge) => (isServiceRelation(edge) ? 190 : 135))
        .strength(0.58)
    )
    .force("charge", d3.forceManyBody().strength(-620))
    .force("center", d3.forceCenter(viewportWidth / 2, viewportHeight / 2))
    .force("collision", d3.forceCollide().radius((d) => (d.node_type === "service" ? 90 : d.vulnerable ? 52 : 42)).strength(0.95))
    .force("x", d3.forceX((d) => graphForceX(d, viewportWidth)).strength(0.12))
    .force("y", d3.forceY(viewportHeight / 2).strength(0.08))
    .stop();

  for (let index = 0; index < 260; index += 1) simulation.tick();

  link.attr("d", (d) => graphEdgePath(edgeEndpoint(d.source), edgeEndpoint(d.target)));
  node.attr("transform", (d) => `translate(${d.x},${d.y})`);

  graphState = {
    svg,
    zoom,
    nodes,
    edges,
    node,
    link,
    label: node.selectAll(".graph-label"),
    width: viewportWidth,
    height: viewportHeight,
    layoutWidth: viewportWidth,
    layoutHeight: viewportHeight,
  };
  fitGraphToView(false);
}

function graphEdgePath(source, target) {
  const midX = (source.x + target.x) / 2;
  return `M ${source.x} ${source.y} C ${midX} ${source.y}, ${midX} ${target.y}, ${target.x} ${target.y}`;
}

function edgeEndpoint(node) {
  return typeof node === "string" ? graphState?.nodes.find((item) => item.id === node) : node;
}

function graphForceX(node, width) {
  if (node.node_type === "service") return width * 0.22;
  if (node.vulnerable) return width * 0.52;
  return width * 0.78;
}

function renderGraphStats(nodes, edges) {
  if (!graphStats) return;
  const services = nodes.filter((node) => node.node_type === "service").length;
  const vulnerable = nodes.filter((node) => node.vulnerable).length;
  const libraries = nodes.length - services;
  graphStats.innerHTML = `
    <span><strong>${services}</strong> 服务模块</span>
    <span><strong>${libraries}</strong> 依赖组件</span>
    <span><strong>${vulnerable}</strong> 风险组件</span>
    <span><strong>${edges.length}</strong> 依赖/调用关系</span>
  `;
}

function graphNodeClassName(node) {
  const classes = ["graph-node"];
  classes.push(node.node_type === "service" ? "service" : "component");
  if (node.language) classes.push(node.language);
  if (node.vulnerable) classes.push("vulnerable");
  return classes.join(" ");
}

function fitGraphToView(animated = true) {
  if (!graphState || !graphState.nodes.length) return;
  const { svg, zoom, nodes, width, height, layoutWidth, layoutHeight } = graphState;
  const padding = 120;
  const minX = d3.min(nodes, (d) => d.x) - padding;
  const maxX = d3.max(nodes, (d) => d.x) + padding;
  const minY = d3.min(nodes, (d) => d.y) - padding;
  const maxY = d3.max(nodes, (d) => d.y) + padding;
  const graphWidth = Math.max(maxX - minX, layoutWidth * 0.72, 1);
  const graphHeight = Math.max(maxY - minY, Math.min(layoutHeight, height), 1);
  const scale = Math.max(0.08, Math.min(1.25, Math.min(width / graphWidth, height / graphHeight)));
  const translateX = (width - graphWidth * scale) / 2 - minX * scale;
  const translateY = (height - graphHeight * scale) / 2 - minY * scale;
  const transform = d3.zoomIdentity.translate(translateX, translateY).scale(scale);
  const target = animated ? svg.transition().duration(260) : svg;
  target.call(zoom.transform, transform);
}

function renderLegend() {
  graphLegend.innerHTML = `
    <span class="legend-item"><i class="dot service"></i>服务</span>
    <span class="legend-item"><i class="dot java"></i>Java 组件</span>
    <span class="legend-item"><i class="dot javascript"></i>JavaScript 组件</span>
    <span class="legend-item"><i class="dot python"></i>Python 组件</span>
    <span class="legend-item"><i class="dot vulnerable"></i>风险组件</span>
    <span class="legend-item"><i class="line-sample service-line"></i>服务调用</span>
    <span class="legend-item"><i class="line-sample dependency-line"></i>组件依赖</span>
  `;
}

function renderGraphInsights(data) {
  if (architectureProfile) {
    const profile = data.architecture_profile;
    architectureProfile.innerHTML = profile
      ? `
        <strong>项目架构识别</strong>
        <p class="impact-title">${profile.architecture_type}</p>
        <p>${profile.description}</p>
        <div class="impact-tags">
          ${renderImpactTag("前端入口", profile.frontend_modules)}
          ${renderImpactTag("后端模块", profile.backend_modules)}
          ${renderImpactTag("网关模块", profile.gateway_modules)}
          ${renderImpactTag("数据分析模块", profile.data_modules)}
        </div>
      `
      : `<strong>项目架构识别</strong><p>暂无架构识别结果，请先完成一次项目扫描。</p>`;
  }

  if (!graphImpactPanel) return;
  const impacts = data.module_impacts || [];
  if (!impacts.length) {
    graphImpactPanel.innerHTML = `<strong>模块影响展示</strong><p>暂无漏洞传播影响数据。</p>`;
    return;
  }

  graphImpactPanel.innerHTML = `
    <strong>模块影响展示</strong>
    <label class="impact-select-label" for="impactSelector">选择漏洞组件</label>
    <select id="impactSelector" class="impact-selector">
      ${impacts
        .map(
          (item) => `
            <option value="${escapeHtml(item.component_id)}">${item.component_name} / ${item.service}</option>
          `
        )
        .join("")}
    </select>
    <div id="impactDetail"></div>
  `;

  const selector = document.getElementById("impactSelector");
  selector.addEventListener("change", () => selectGraphComponent(selector.value));
  selectGraphComponent(selector.value);
}

function selectGraphComponent(componentId) {
  if (!latestResult || !componentId) return;
  const impact = (latestResult.module_impacts || []).find((item) => item.component_id === componentId);
  const issue = (latestResult.vulnerabilities || []).find((item) => item.component_id === componentId);
  if (!impact || !issue) {
    highlightNodeNeighborhood(componentId);
    focusGraphNode(componentId);
    return;
  }

  const selector = document.getElementById("impactSelector");
  if (selector && selector.value !== componentId) selector.value = componentId;

  renderImpactDetail(impact);
  highlightImpactPath(componentId, impact.raw_paths || issue.shortest_paths || issue.paths || []);
  focusGraphNode(componentId);
}

function selectGraphNode(nodeId) {
  const node = graphState?.nodes.find((item) => item.id === nodeId);
  if (!node) return;
  if (node.vulnerable) {
    selectGraphComponent(nodeId);
    return;
  }
  highlightNodeNeighborhood(nodeId);
  renderNodeNeighborhoodDetail(node);
  focusGraphNode(nodeId);
}

function renderImpactDetail(impact) {
  const detail = document.getElementById("impactDetail");
  if (!detail) return;
  detail.innerHTML = `
    <div class="impact-card">
      <span>${impact.impact_scope}</span>
      <h3>${impact.component_name} ${impact.component_version}</h3>
      <p>${impact.impact_summary}</p>
      <div class="impact-columns">
        ${renderModuleGroup("上游受影响模块", impact.upstream_modules)}
        ${renderModuleGroup("直接调用方", impact.direct_callers)}
        ${renderModuleGroup("下游依赖模块", impact.downstream_modules)}
      </div>
      <div class="impact-paths">
        <strong>可读传播链路</strong>
        ${
          impact.readable_paths.length
            ? impact.readable_paths.slice(0, 5).map((path) => `<p>${path}</p>`).join("")
            : "<p>暂无可读传播路径</p>"
        }
      </div>
      <div class="impact-tags">
        ${(impact.cve_ids || []).map((id) => `<span>${id}</span>`).join("")}
      </div>
    </div>
  `;
}

function renderNodeNeighborhoodDetail(node) {
  const detail = document.getElementById("impactDetail");
  if (!detail) return;
  const relatedEdges = graphState.edges.filter((edge) => {
    const sourceId = edge.sourceId || edgeNodeId(edge.source);
    const targetId = edge.targetId || edgeNodeId(edge.target);
    return sourceId === node.id || targetId === node.id;
  });
  const relatedNodes = relatedEdges
    .map((edge) => (edge.sourceId || edgeNodeId(edge.source)) === node.id ? edge.targetId || edgeNodeId(edge.target) : edge.sourceId || edgeNodeId(edge.source))
    .map((id) => graphState.nodes.find((item) => item.id === id))
    .filter(Boolean);
  detail.innerHTML = `
    <div class="impact-card">
      <span>${node.node_type === "service" ? "服务模块" : "依赖组件"}</span>
      <h3>${node.label}</h3>
      <p>${node.version ? `版本：${node.version}` : "该节点当前未命中漏洞，可查看其直接依赖关系。"}</p>
      <div class="impact-paths">
        <strong>直接关联节点</strong>
        ${
          relatedNodes.length
            ? relatedNodes.slice(0, 12).map((item) => `<p>${item.label}${item.vulnerable ? "（风险组件）" : ""}</p>`).join("")
            : "<p>暂无直接关联关系</p>"
        }
      </div>
    </div>
  `;
}

function highlightImpactPath(componentId, paths) {
  if (!graphState) return;
  const highlightedNodes = new Set([componentId]);
  const highlightedEdges = new Set();
  const pathList = Array.isArray(paths) ? paths.filter((path) => Array.isArray(path) && path.length) : [];

  pathList.forEach((path) => {
    path.forEach((nodeId) => highlightedNodes.add(nodeId));
    for (let index = 0; index < path.length - 1; index += 1) {
      highlightedEdges.add(`${path[index]}=>${path[index + 1]}`);
      highlightedEdges.add(`${path[index + 1]}=>${path[index]}`);
    }
  });

  if (!pathList.length) {
    graphState.edges.forEach((edge) => {
      const sourceId = edge.sourceId || edgeNodeId(edge.source);
      const targetId = edge.targetId || edgeNodeId(edge.target);
      if (sourceId === componentId || targetId === componentId) {
        highlightedNodes.add(sourceId);
        highlightedNodes.add(targetId);
        highlightedEdges.add(`${sourceId}=>${targetId}`);
        highlightedEdges.add(`${targetId}=>${sourceId}`);
      }
    });
  }

  graphState.node
    .classed("highlighted", (node) => highlightedNodes.has(node.id))
    .classed("selected", (node) => node.id === componentId)
    .classed("dimmed", (node) => !highlightedNodes.has(node.id));

  graphState.label.classed("dimmed", (node) => !highlightedNodes.has(node.id));

  graphState.link
    .classed("highlighted", (edge) =>
      highlightedEdges.has(`${edge.sourceId || edgeNodeId(edge.source)}=>${edge.targetId || edgeNodeId(edge.target)}`)
    )
    .classed(
      "dimmed",
      (edge) =>
        !highlightedEdges.has(`${edge.sourceId || edgeNodeId(edge.source)}=>${edge.targetId || edgeNodeId(edge.target)}`)
    );
}

function highlightNodeNeighborhood(nodeId) {
  if (!graphState) return;
  const highlightedNodes = new Set([nodeId]);
  const highlightedEdges = new Set();
  graphState.edges.forEach((edge) => {
    const sourceId = edge.sourceId || edgeNodeId(edge.source);
    const targetId = edge.targetId || edgeNodeId(edge.target);
    if (sourceId === nodeId || targetId === nodeId) {
      highlightedNodes.add(sourceId);
      highlightedNodes.add(targetId);
      highlightedEdges.add(`${sourceId}=>${targetId}`);
      highlightedEdges.add(`${targetId}=>${sourceId}`);
    }
  });
  graphState.node
    .classed("highlighted", (node) => highlightedNodes.has(node.id))
    .classed("selected", (node) => node.id === nodeId)
    .classed("dimmed", (node) => !highlightedNodes.has(node.id));
  graphState.label.classed("dimmed", (node) => !highlightedNodes.has(node.id));
  graphState.link
    .classed("highlighted", (edge) =>
      highlightedEdges.has(`${edge.sourceId || edgeNodeId(edge.source)}=>${edge.targetId || edgeNodeId(edge.target)}`)
    )
    .classed(
      "dimmed",
      (edge) =>
        !highlightedEdges.has(`${edge.sourceId || edgeNodeId(edge.source)}=>${edge.targetId || edgeNodeId(edge.target)}`)
    );
}

function edgeNodeId(node) {
  return typeof node === "string" ? node : node.id;
}

function focusGraphNode(nodeId) {
  if (!graphState) return;
  const targetNode = graphState.nodes.find((node) => node.id === nodeId);
  if (!targetNode) return;
  const scale = Math.min(1.25, Math.max(0.72, graphState.height / Math.max(graphState.layoutHeight, graphState.height)));
  const transform = d3.zoomIdentity
    .translate(graphState.width / 2 - targetNode.x * scale, graphState.height / 2 - targetNode.y * scale)
    .scale(scale);
  graphState.svg.transition().duration(280).call(graphState.zoom.transform, transform);
}

function renderImpactTag(label, items) {
  const values = items && items.length ? items : ["无"];
  return `<span>${label}：${values.join("、")}</span>`;
}

function renderModuleGroup(title, items) {
  return `
    <div>
      <strong>${title}</strong>
      <p>${items && items.length ? items.join("、") : "暂无"}</p>
    </div>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function isServiceRelation(edge) {
  const relation = edge.relation || "";
  return ["service_call", "http_call", "auth_call", "api_call", "data_query", "token_check"].includes(relation);
}

function edgeClassName(edge) {
  return isServiceRelation(edge) ? "graph-link service-relation" : "graph-link component-relation";
}

function renderBars(distribution) {
  const entries = Object.entries(distribution || {});
  if (!entries.length) {
    return `<div class="empty-state">暂无数据</div>`;
  }

  const max = Math.max(...entries.map(([, value]) => value), 1);
  return entries
    .map(
      ([label, value]) => `
        <div class="bar-item">
          <div class="bar-meta">
            <strong>${label}</strong>
            <span>${value}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:${(value / max) * 100}%"></div>
          </div>
        </div>
      `
    )
    .join("");
}

function renderServiceHeat(items) {
  return items.length
    ? items
        .map(
          (item) => `
            <div class="heat-item">
              <div>
                <strong>${item.service}</strong>
                <span>组件 ${item.component_count}，漏洞 ${item.vulnerability_count}</span>
              </div>
              <div class="heat-score">${item.vulnerability_count}</div>
            </div>
          `
        )
        .join("")
    : `<div class="empty-state">暂无服务数据</div>`;
}

function renderTagList(items) {
  return [...new Set(items)].map((item) => `<span class="history-tag">${item}</span>`).join("");
}

function renderPathPreview(data, componentId) {
  const match = data.vulnerabilities.find((item) => item.component_id === componentId);
  const path = match?.shortest_paths?.[0] || match?.paths?.[0];
  if (!path) return "无";
  return path.map(formatGraphNode).join(" -> ");
}

function formatGraphNode(node) {
  if (node.startsWith("service:")) {
    return node.replace("service:", "");
  }
  const parts = node.split(":");
  if (parts[0] === "component") {
    return parts[3] || node;
  }
  return parts[1] || node;
}

function nodeClassName(node) {
  if (node.vulnerable) return "node vulnerable";
  if (node.node_type === "service") return "node service";
  return `node ${node.language}`;
}

function drag() {
  function dragStarted(event) {
    event.sourceEvent.stopPropagation();
    d3.select(this).raise();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  }

  function dragged(event) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  }

  function dragEnded(event) {
    event.subject.fx = null;
    event.subject.fy = null;
  }

  return d3.drag().on("start", dragStarted).on("drag", dragged).on("end", dragEnded);
}

function ensureModal() {
  if (document.getElementById("detailModal")) return;
  document.body.insertAdjacentHTML(
    "beforeend",
    `
      <div class="modal-backdrop hidden" id="detailModal">
        <div class="detail-modal" role="dialog" aria-modal="true">
          <div class="modal-header">
            <h2 id="modalTitle"></h2>
            <button type="button" class="modal-close" id="modalClose">×</button>
          </div>
          <div class="modal-body" id="modalBody"></div>
        </div>
      </div>
    `
  );
  document.getElementById("modalClose").addEventListener("click", closeDetailModal);
  document.getElementById("detailModal").addEventListener("click", (event) => {
    if (event.target.id === "detailModal") closeDetailModal();
  });
}

function openDetailModal(title, body) {
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalBody").innerHTML = body;
  document.getElementById("detailModal").classList.remove("hidden");
}

function closeDetailModal() {
  document.getElementById("detailModal").classList.add("hidden");
}

function cacheResult(data) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(data));
  } catch {
    setStatus("浏览器缓存不可用，本次结果仍可在当前页面查看", true);
  }
}

function loadCachedResult() {
  try {
    const raw = localStorage.getItem(storageKey);
    return raw ? JSON.parse(raw) : null;
  } catch {
    localStorage.removeItem(storageKey);
    return null;
  }
}

function setStatus(message, isError = false) {
  if (!statusText) return;
  statusText.textContent = message;
  statusText.className = isError ? "status-text error" : "status-text";
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "请求失败，请稍后重试");
  }
  return data;
}
