const storageKey = "depVulnLatestResult";
const page = document.body.dataset.page;

const statusText = document.getElementById("statusText");
const statsGrid = document.getElementById("statsGrid");
const summaryPanel = document.getElementById("summaryPanel");
const distributionPanel = document.getElementById("distributionPanel");
const vulnerabilityList = document.getElementById("vulnerabilityList");
const riskList = document.getElementById("riskList");
const historyList = document.getElementById("historyList");
const reportActions = document.getElementById("reportActions");
const graphCanvas = document.getElementById("graphCanvas");
const graphLegend = document.getElementById("graphLegend");
const graphTools = document.getElementById("graphTools");
const remediationList = document.getElementById("remediationList");
const comparePanel = document.getElementById("comparePanel");
const compareRefreshBtn = document.getElementById("compareRefreshBtn");

let latestResult = null;
let graphState = null;

initPage();

function initPage() {
  if (page === "analysis") {
    bindAnalysisActions();
  }
  if (page === "history") {
    loadHistory();
  }
  if (page === "compare") {
    loadComparison();
  }
  if (compareRefreshBtn) {
    compareRefreshBtn.addEventListener("click", loadComparison);
  }
  bindTabs();
  bindGraphTools();
  ensureModal();

  const cached = loadCachedResult();
  if (cached) {
    latestResult = cached;
    renderForPage(cached);
  } else if (["risk", "graph", "reports", "remediation"].includes(page)) {
    renderEmptyForPage();
  }
}

function bindAnalysisActions() {
  document.getElementById("scanBtn").addEventListener("click", runCustomScan);
  document.getElementById("sampleBtn").addEventListener("click", loadSampleProject);
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
  if (summaryPanel) renderSummary(data);
  if (distributionPanel) renderDistribution(data);
  if (vulnerabilityList) renderVulnerabilities(data);
  if (riskList) renderRiskSummary(data);
  if (reportActions) renderReportActions(data.reports);
  if (graphCanvas) renderGraph(data.graph);
  if (graphLegend) renderLegend();
  if (remediationList) renderRemediation(data.remediation || []);
}

function renderEmptyForPage() {
  const empty = `<div class="empty-state">请先到“项目扫描”页面执行一次分析，再回来查看结果。</div>`;
  if (summaryPanel) summaryPanel.innerHTML = empty;
  if (distributionPanel) distributionPanel.innerHTML = empty;
  if (vulnerabilityList) vulnerabilityList.innerHTML = empty;
  if (riskList) riskList.innerHTML = empty;
  if (reportActions) reportActions.innerHTML = empty;
  if (graphCanvas) graphCanvas.innerHTML = empty;
  if (remediationList) remediationList.innerHTML = empty;
}

async function loadComparison() {
  if (!comparePanel) return;
  comparePanel.innerHTML = `<div class="empty-state">正在生成对比结果...</div>`;
  try {
    const data = await fetchJson("/api/compare/latest");
    renderComparison(data);
  } catch (error) {
    comparePanel.innerHTML = `<div class="empty-state">${error.message}</div>`;
  }
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
      <div class="compact-table">
        ${items
          .map((item, index) => {
            const cves = item.vulnerabilities.map((vuln) => vuln.cve_id).join("、");
            return `
              <div class="compact-row">
                <div>
                  <strong>${item.component_name}</strong>
                  <span>${item.service} · ${item.component_version}</span>
                </div>
                <div class="row-meta">${item.affected_services.length} 个服务</div>
                <button type="button" class="detail-button" data-detail="vulnerability" data-index="${index}">查看详情</button>
              </div>
              <div class="row-subline">${cves}</div>
            `;
          })
          .join("")}
      </div>
    `
    : `<div class="empty-state">暂无漏洞命中</div>`;
  bindDetailButtons(data);
}

function renderRiskSummary(data) {
  const items = data.risk_summary;
  riskList.innerHTML = items.length
    ? `
      <div class="compact-table">
        ${items
          .map(
            (item, index) => `
              <div class="compact-row">
                <div>
                  <strong>${item.component_name}</strong>
                  <span>${item.risk_level}</span>
                </div>
                <div class="row-meta">评分 ${item.score}</div>
                <button type="button" class="detail-button" data-detail="risk" data-index="${index}">查看详情</button>
              </div>
            `
          )
          .join("")}
      </div>
    `
    : `<div class="empty-state">暂无风险评估数据</div>`;
  bindDetailButtons(data);
}

function renderRemediation(items) {
  remediationList.innerHTML = items.length
    ? items
        .map(
          (item, index) => `
            <div class="remediation-item">
              <div class="priority-badge">P${Math.max(1, 6 - item.priority)}</div>
              <div>
                <strong>${item.component_name}</strong>
                <span>${item.service} · 当前版本 ${item.current_version}</span>
                <p>${item.suggestion}</p>
              </div>
              <div class="repair-target">
                <span>建议版本</span>
                <strong>${item.target_version}</strong>
              </div>
              <button type="button" class="detail-button" data-repair-index="${index}">查看</button>
            </div>
          `
        )
        .join("")
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

function renderComparison(data) {
  const delta = data.delta;
  comparePanel.innerHTML = `
    <div class="compare-grid">
      ${renderScanSnapshot("上一次扫描", data.previous)}
      ${renderScanSnapshot("本次扫描", data.current)}
    </div>
    <div class="compare-metrics">
      ${renderDeltaCard("组件变化", delta.component_count)}
      ${renderDeltaCard("漏洞变化", delta.vulnerability_count)}
      ${renderDeltaCard("受影响服务变化", delta.affected_service_count)}
    </div>
    <div class="compare-columns">
      ${renderChangeList("新增风险", data.new_risks)}
      ${renderChangeList("已消除风险", data.resolved_risks)}
      ${renderChangeList("持续存在风险", data.unchanged_risks)}
    </div>
  `;
}

function renderScanSnapshot(title, item) {
  return `
    <div class="compare-snapshot">
      <span>${title}</span>
      <strong>${item.project_name}</strong>
      <p>${item.scanned_at}</p>
      <div class="snapshot-numbers">
        <b>${item.component_count}</b><span>组件</span>
        <b>${item.vulnerability_count}</b><span>漏洞</span>
        <b>${item.affected_service_count}</b><span>服务</span>
      </div>
    </div>
  `;
}

function renderDeltaCard(label, value) {
  const trend = value > 0 ? "up" : value < 0 ? "down" : "flat";
  const prefix = value > 0 ? "+" : "";
  return `
    <div class="delta-card ${trend}">
      <span>${label}</span>
      <strong>${prefix}${value}</strong>
    </div>
  `;
}

function renderChangeList(title, items) {
  return `
    <div class="change-list">
      <h3>${title}</h3>
      ${
        items.length
          ? items
              .map((item) => `<p><strong>${item.name}</strong><span>${item.service} ${item.version}</span></p>`)
              .join("")
          : `<div class="empty-state compact">暂无</div>`
      }
    </div>
  `;
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

function renderReportActions(reports) {
  reportActions.innerHTML = `
    <a class="report-link" href="/api/reports/${reports.json}">下载 JSON 报告</a>
    <a class="report-link" href="/api/reports/${reports.txt}">下载 TXT 报告</a>
    <a class="report-link" href="/api/reports/${reports.html}">下载 HTML 报告</a>
  `;
}

function renderGraph(graph) {
  graphCanvas.innerHTML = "";
  const width = graphCanvas.clientWidth || 1000;
  const height = graphCanvas.clientHeight || 680;
  const nodes = graph.nodes.map((node) => ({ ...node }));
  const edges = graph.edges.map((edge) => ({ ...edge }));

  const svg = d3.select("#graphCanvas").append("svg").attr("viewBox", `0 0 ${width} ${height}`);
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
  const zoom = d3.zoom().scaleExtent([0.35, 2.6]).on("zoom", (event) => {
    zoomLayer.attr("transform", event.transform);
  });
  svg.call(zoom);

  const link = zoomLayer
    .append("g")
    .selectAll("line")
    .data(edges)
    .enter()
    .append("line")
    .attr("class", (d) => edgeClassName(d))
    .attr("marker-end", (d) => (isServiceRelation(d) ? "url(#arrow-service)" : "url(#arrow-component)"));

  const node = zoomLayer
    .append("g")
    .selectAll("circle")
    .data(nodes)
    .enter()
    .append("circle")
    .attr("r", (d) => (d.node_type === "service" ? 18 : 11))
    .attr("class", (d) => nodeClassName(d))
    .call(drag());

  node.append("title").text((d) => `${d.label}${d.version ? ` ${d.version}` : ""}`);

  const label = zoomLayer
    .append("g")
    .selectAll("text")
    .data(nodes)
    .enter()
    .append("text")
    .attr("class", "graph-label")
    .text((d) => d.label);

  const simulation = d3
    .forceSimulation(nodes)
    .force("link", d3.forceLink(edges).id((d) => d.id).distance((d) => (isServiceRelation(d) ? 180 : 112)))
    .force("charge", d3.forceManyBody().strength(-520))
    .force("collide", d3.forceCollide().radius((d) => (d.node_type === "service" ? 56 : 42)))
    .force("x", d3.forceX((d) => graphColumnX(d, width)).strength(0.18))
    .force("y", d3.forceY((d, index) => graphRowY(d, index, height)).strength(0.12))
    .force("center", d3.forceCenter(width / 2, height / 2));

  simulation.on("tick", () => {
    nodes.forEach((d) => {
      d.x = Math.max(42, Math.min(width - 140, d.x));
      d.y = Math.max(36, Math.min(height - 36, d.y));
    });

    link
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y);
    node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
    label.attr("x", (d) => d.x + 15).attr("y", (d) => d.y + 4);
  });

  graphState = { svg, zoom, nodes, width, height };
  simulation.on("end", () => fitGraphToView(false));
  setTimeout(() => fitGraphToView(false), 650);
}

function graphColumnX(node, width) {
  if (node.node_type === "service") return width * 0.24;
  if (node.vulnerable) return width * 0.55;
  return width * 0.76;
}

function graphRowY(node, index, height) {
  const lanes = {
    service: 0.25,
    java: 0.36,
    javascript: 0.52,
    python: 0.68,
  };
  return height * (lanes[node.language] || lanes[node.node_type] || 0.5) + (index % 4) * 18;
}

function fitGraphToView(animated = true) {
  if (!graphState || !graphState.nodes.length) return;
  const { svg, zoom, nodes, width, height } = graphState;
  const padding = 80;
  const minX = d3.min(nodes, (d) => d.x) - padding;
  const maxX = d3.max(nodes, (d) => d.x) + padding + 120;
  const minY = d3.min(nodes, (d) => d.y) - padding;
  const maxY = d3.max(nodes, (d) => d.y) + padding;
  const graphWidth = Math.max(maxX - minX, 1);
  const graphHeight = Math.max(maxY - minY, 1);
  const scale = Math.max(0.45, Math.min(1.35, Math.min(width / graphWidth, height / graphHeight)));
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
