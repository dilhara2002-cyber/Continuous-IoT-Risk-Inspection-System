/**
 * Secure IoT Device Discovery & Risk Management System
 * Frontend Application Controller (SLIIT IE3092 - Group 14)
 */

let allDevices = [];
let allClassifiedDevices = [];

document.addEventListener("DOMContentLoaded", () => {
  // Check user authentication
  checkAuth(true);

  const currentUser = getCurrentUser();
  if (currentUser) {
    const nameEl = document.getElementById("user-display-name");
    const roleEl = document.getElementById("user-role-badge");
    if (nameEl) nameEl.innerText = currentUser.full_name || currentUser.username;
    if (roleEl) {
      roleEl.innerText = currentUser.role.toUpperCase();
      if (currentUser.role === "viewer") {
        roleEl.style.backgroundColor = "#64748b";
        // Disable admin-only scan buttons if viewer
        const execBtn = document.getElementById("exec-scan-btn");
        if (execBtn) {
          execBtn.disabled = true;
          execBtn.title = "Admin role required to trigger discovery scan";
        }
      }
    }
  }

  // Set up navigation tab listeners
  document.querySelectorAll(".nav-item[data-view]").forEach(nav => {
    nav.addEventListener("click", () => {
      const viewId = nav.getAttribute("data-view");
      navigateTo(viewId);
    });
  });

  // Load initial view
  loadDashboardOverview();
  loadUnresolvedAlertBadge();
});

/* =========================================================================
   NAVIGATION CONTROLLER
   ========================================================================= */
function navigateTo(viewId) {
  document.querySelectorAll(".nav-item[data-view]").forEach(i => i.classList.remove("active"));
  document.querySelectorAll(".view-section").forEach(s => s.classList.remove("active"));

  const targetNav = document.querySelector(`.nav-item[data-view="${viewId}"]`);
  const targetView = document.getElementById(viewId);

  if (targetNav) targetNav.classList.add("active");
  if (targetView) targetView.classList.add("active");

  // Trigger data loader for the selected page
  if (viewId === "dashboard-view") loadDashboardOverview();
  else if (viewId === "discovery-view") loadDiscoveryTable();
  else if (viewId === "info-view") loadDeviceInventory();
  else if (viewId === "classification-view") loadClassificationData();
  else if (viewId === "risk-view") loadRiskAssessmentData();
  else if (viewId === "alerts-view") loadAlerts();
  else if (viewId === "audit-view") loadAuditLogs();
}

/* =========================================================================
   1. MAIN DASHBOARD VIEW
   ========================================================================= */
async function loadDashboardOverview() {
  try {
    const res = await fetch("/api/risk/summary", { headers: getAuthHeaders() });
    if (!res.ok) {
      if (res.status === 401) return logout();
      throw new Error("Failed to load overview");
    }
    const data = await res.json();

    document.getElementById("dash-stat-total").innerText = data.total_devices;
    document.getElementById("dash-stat-high").innerText = data.risk_distribution.High || 0;
    document.getElementById("dash-stat-medium").innerText = data.risk_distribution.Medium || 0;
    document.getElementById("dash-stat-low").innerText = data.risk_distribution.Low || 0;

    // Render device categories progress list
    const catList = document.getElementById("dash-category-list");
    catList.innerHTML = "";
    const categories = data.device_categories || {};

    if (Object.keys(categories).length === 0) {
      catList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.85rem;">No devices discovered yet.</div>`;
    } else {
      for (const [cat, count] of Object.entries(categories)) {
        const pct = data.total_devices > 0 ? Math.round((count / data.total_devices) * 100) : 0;
        const div = document.createElement("div");
        div.innerHTML = `
          <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.25rem;">
            <span>${getCategoryIcon(cat)} <strong>${escapeHtml(cat)}</strong></span>
            <span style="color: var(--text-muted);">${count} (${pct}%)</span>
          </div>
          <div class="progress-bar-bg">
            <div class="progress-bar-fill" style="width: ${pct}%;"></div>
          </div>
        `;
        catList.appendChild(div);
      }
    }

    // Load recent alerts summary
    loadDashboardRecentAlerts();
  } catch (err) {
    console.error("Dashboard overview error:", err);
  }
}

async function loadDashboardRecentAlerts() {
  try {
    const res = await fetch("/api/alerts?unresolved_only=true", { headers: getAuthHeaders() });
    if (!res.ok) return;
    const alerts = await res.json();
    const container = document.getElementById("dash-recent-alerts");
    container.innerHTML = "";

    if (alerts.length === 0) {
      container.innerHTML = `<div style="color: var(--success); font-size: 0.85rem; padding: 1rem 0;">✓ No active unresolved security alerts. All systems healthy.</div>`;
      return;
    }

    alerts.slice(0, 3).forEach(a => {
      const item = document.createElement("div");
      item.style.cssText = "padding: 0.75rem 0; border-bottom: 1px solid var(--border-color);";
      item.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 0.9rem;">${escapeHtml(a.title)}</strong>
          <span class="badge ${getRiskBadgeClass(a.severity)}">${a.severity}</span>
        </div>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">${escapeHtml(a.description)}</div>
      `;
      container.appendChild(item);
    });
  } catch (e) {}
}

/* =========================================================================
   2. DEVICE DISCOVERY PAGE
   ========================================================================= */
async function executeDiscoveryScan() {
  const btn = document.getElementById("exec-scan-btn");
  const feedback = document.getElementById("scan-feedback");
  const subnet = document.getElementById("scan-subnet").value.trim() || "192.168.1.0/24";
  const scanMode = document.getElementById("scan-mode").value;

  btn.disabled = true;
  btn.innerText = "⏳ Scanning LAN...";
  feedback.style.display = "block";
  feedback.style.backgroundColor = "rgba(59, 130, 246, 0.15)";
  feedback.style.border = "1px solid rgba(59, 130, 246, 0.3)";
  feedback.style.color = "#93c5fd";
  feedback.innerHTML = `Initiating non-intrusive discovery on subnet <code>${subnet}</code> (Mode: ${scanMode})...`;

  try {
    const res = await fetch("/api/devices/scan", {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ scan_type: scanMode, target_subnet: subnet })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Discovery scan failed");
    }

    const result = await res.json();
    feedback.style.backgroundColor = "rgba(16, 185, 129, 0.15)";
    feedback.style.border = "1px solid rgba(16, 185, 129, 0.3)";
    feedback.style.color = "#34d399";
    feedback.innerHTML = `✓ ${result.message} (${result.devices_found} active devices identified, ${result.new_devices_added} new entries).`;

    loadDiscoveryTable();
    loadUnresolvedAlertBadge();
  } catch (err) {
    feedback.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
    feedback.style.border = "1px solid rgba(239, 68, 68, 0.3)";
    feedback.style.color = "#f87171";
    feedback.innerText = `Error: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.innerText = "⚡ Start Discovery Scan";
  }
}

async function quickScan() {
  navigateTo("discovery-view");
  await executeDiscoveryScan();
}

async function loadDiscoveryTable() {
  try {
    const res = await fetch("/api/devices", { headers: getAuthHeaders() });
    if (!res.ok) throw new Error("Could not load devices");
    const devices = await res.json();
    const tbody = document.getElementById("discovery-table-body");
    tbody.innerHTML = "";

    if (devices.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No devices discovered yet.</td></tr>`;
      return;
    }

    devices.forEach(d => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escapeHtml(d.ip_address)}</code></td>
        <td><code>${escapeHtml(d.mac_address)}</code></td>
        <td><strong>${escapeHtml(d.hostname || "Unknown Host")}</strong></td>
        <td><span class="type-tag">ARP / mDNS Broadcast</span></td>
        <td><small>${escapeHtml(d.first_seen)}</small></td>
        <td><small>${escapeHtml(d.last_seen)}</small></td>
        <td><span style="color: var(--success); font-size: 0.85rem;">● ${escapeHtml(d.status)}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Discovery table error:", err);
  }
}

/* =========================================================================
   3. DEVICE INFORMATION PAGE
   ========================================================================= */
async function loadDeviceInventory() {
  try {
    const res = await fetch("/api/devices", { headers: getAuthHeaders() });
    if (!res.ok) throw new Error("Could not load devices");
    allDevices = await res.json();
    renderDeviceInventory(allDevices);
  } catch (err) {
    console.error("Device inventory error:", err);
  }
}

function renderDeviceInventory(devices) {
  const tbody = document.getElementById("info-table-body");
  tbody.innerHTML = "";

  if (devices.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No devices match the filter criteria.</td></tr>`;
    return;
  }

  devices.forEach(d => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>
        <strong>${escapeHtml(d.hostname || "Unnamed Asset")}</strong>
        <div style="font-size: 0.75rem; color: var(--text-muted);">${d.is_known_device ? "✓ Approved Asset" : "⚠️ Rogue / Unregistered"}</div>
      </td>
      <td><code>${escapeHtml(d.ip_address)}</code></td>
      <td><code>${escapeHtml(d.mac_address)}</code></td>
      <td>${escapeHtml(d.manufacturer || "Unknown")}</td>
      <td><span class="type-tag">${getCategoryIcon(d.device_type)} ${escapeHtml(d.device_type)}</span></td>
      <td><small>${escapeHtml(d.firmware_version || "Unknown")}</small></td>
      <td><span style="color: ${d.status === 'Online' ? 'var(--success)' : 'var(--text-muted)'}; font-size: 0.85rem;">● ${d.status}</span></td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="inspectDevice(${d.id})">🔍 Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function filterDeviceInventory() {
  const search = (document.getElementById("info-search").value || "").toLowerCase();
  const cat = document.getElementById("info-filter-type").value;
  const status = document.getElementById("info-filter-status").value;

  const filtered = allDevices.filter(d => {
    const matchSearch =
      (d.hostname || "").toLowerCase().includes(search) ||
      (d.ip_address || "").toLowerCase().includes(search) ||
      (d.mac_address || "").toLowerCase().includes(search) ||
      (d.manufacturer || "").toLowerCase().includes(search);

    const matchCat = !cat || d.device_type === cat;
    const matchStatus = !status || d.status === status;

    return matchSearch && matchCat && matchStatus;
  });

  renderDeviceInventory(filtered);
}

/* =========================================================================
   4. DEVICE CLASSIFICATION PAGE
   ========================================================================= */
async function loadClassificationData() {
  try {
    // 1. Load classified devices
    const resDevs = await fetch("/api/classification/devices", { headers: getAuthHeaders() });
    if (resDevs.ok) {
      allClassifiedDevices = await resDevs.json();
      const tbody = document.getElementById("classification-table-body");
      tbody.innerHTML = "";

      if (allClassifiedDevices.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No devices classified yet.</td></tr>`;
      } else {
        allClassifiedDevices.forEach(d => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td><strong>${escapeHtml(d.hostname || "Device")}</strong> (${escapeHtml(d.ip_address)})</td>
            <td><code>${escapeHtml(d.oui_prefix)}</code> <span style="font-size: 0.75rem; color: var(--text-muted);">(${escapeHtml(d.mac_address)})</span></td>
            <td><strong>${escapeHtml(d.manufacturer)}</strong></td>
            <td><small>${escapeHtml(d.rationale)}</small></td>
            <td><span class="type-tag">${getCategoryIcon(d.device_type)} ${escapeHtml(d.device_type)}</span></td>
            <td><span class="badge ${d.confidence.includes('High') ? 'badge-low' : (d.confidence.includes('Moderate') ? 'badge-medium' : 'badge-high')}">${escapeHtml(d.confidence)}</span></td>
          `;
          tbody.appendChild(tr);
        });
      }
    }

    // 2. Load system rules reference
    const resRules = await fetch("/api/classification/rules", { headers: getAuthHeaders() });
    if (resRules.ok) {
      const rules = await resRules.json();
      const tbodyRules = document.getElementById("rules-table-body");
      tbodyRules.innerHTML = "";

      rules.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><span class="type-tag">${getCategoryIcon(r.category)} <strong>${escapeHtml(r.category)}</strong></span></td>
          <td><small>${r.oui_vendors.join(", ")}</small></td>
          <td><code>${r.ports_services.join(", ")}</code></td>
          <td><small>${r.hostname_patterns.join(", ")}</small></td>
          <td><small style="color: var(--text-muted);">${escapeHtml(r.description)}</small></td>
        `;
        tbodyRules.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Classification page error:", err);
  }
}

/* =========================================================================
   5. RISK ASSESSMENT PAGE
   ========================================================================= */
async function loadRiskAssessmentData() {
  try {
    const res = await fetch("/api/devices", { headers: getAuthHeaders() });
    if (!res.ok) throw new Error("Could not load devices for risk view");
    const devices = await res.json();
    const tbody = document.getElementById("risk-table-body");
    tbody.innerHTML = "";

    if (devices.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 2rem;">No risk assessments available.</td></tr>`;
      return;
    }

    for (const d of devices) {
      // Fetch device detail to get factor breakdown
      const detailRes = await fetch(`/api/devices/${d.id}`, { headers: getAuthHeaders() });
      if (!detailRes.ok) continue;
      const detail = await detailRes.json();
      const risk = detail.risk_assessment || {
        risk_score: 0,
        risk_level: "Low",
        factor_unknown: 0,
        factor_firmware: 0,
        factor_credential: 0,
        factor_exposure: 0,
        factor_config: 0
      };

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>
          <strong>${escapeHtml(d.hostname || "Device")}</strong>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(d.ip_address)} | ${escapeHtml(d.device_type)}</div>
        </td>
        <td><strong style="color: ${risk.factor_unknown > 0 ? 'var(--danger)' : 'var(--success)'}">${risk.factor_unknown}</strong> / 25</td>
        <td><strong style="color: ${risk.factor_firmware > 15 ? 'var(--danger)' : (risk.factor_firmware > 0 ? 'var(--warning)' : 'var(--success)')}">${risk.factor_firmware}</strong> / 25</td>
        <td><strong style="color: ${risk.factor_credential > 0 ? 'var(--danger)' : 'var(--success)'}">${risk.factor_credential}</strong> / 25</td>
        <td><strong style="color: ${risk.factor_exposure > 8 ? 'var(--danger)' : (risk.factor_exposure > 0 ? 'var(--warning)' : 'var(--success)')}">${risk.factor_exposure}</strong> / 15</td>
        <td><strong style="color: ${risk.factor_config > 5 ? 'var(--danger)' : (risk.factor_config > 0 ? 'var(--warning)' : 'var(--success)')}">${risk.factor_config}</strong> / 10</td>
        <td>
          <div style="font-size: 1.1rem; font-weight: 700;">${risk.risk_score} <span style="font-size: 0.8rem; font-weight: 400; color: var(--text-muted);">/ 100</span></div>
        </td>
        <td>
          <span class="badge ${getRiskBadgeClass(risk.risk_level)}">${escapeHtml(risk.risk_level)}</span>
        </td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="inspectDevice(${d.id})">📊 Explain Findings</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
  } catch (err) {
    console.error("Risk assessment error:", err);
  }
}

/* =========================================================================
   6. ALERTS SECTION
   ========================================================================= */
async function loadAlerts() {
  const unresolvedOnly = document.getElementById("unresolved-alerts-check")?.checked || false;
  try {
    const res = await fetch(`/api/alerts?unresolved_only=${unresolvedOnly}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error("Failed to load alerts");
    const alerts = await res.json();
    const container = document.getElementById("alerts-feed-container");
    container.innerHTML = "";

    if (alerts.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 3rem;">No security alerts recorded.</div>`;
      return;
    }

    const currentUser = getCurrentUser();
    const isAdmin = currentUser && currentUser.role === "admin";

    alerts.forEach(a => {
      const card = document.createElement("div");
      card.className = `alert-card ${a.severity.toLowerCase()} ${a.is_resolved ? 'resolved' : ''}`;
      card.innerHTML = `
        <div class="alert-content">
          <h4>${escapeHtml(a.title)}</h4>
          <p style="font-size: 0.9rem; color: #cbd5e1;">${escapeHtml(a.description)}</p>
          <div class="alert-meta">
            Type: <strong>${escapeHtml(a.alert_type)}</strong> | 
            Severity: <span class="badge ${getRiskBadgeClass(a.severity)}">${a.severity}</span> | 
            Status: <strong>${a.is_resolved ? '✓ Resolved' : '⚠️ Active'}</strong> |
            Logged: ${a.created_at}
          </div>
        </div>
        ${isAdmin ? `
          <div style="margin-left: 1rem;">
            <button class="btn btn-secondary btn-sm" onclick="toggleAlertResolution(${a.id}, ${!a.is_resolved})">
              ${a.is_resolved ? 'Reopen' : '✓ Resolve'}
            </button>
          </div>
        ` : ''}
      `;
      container.appendChild(card);
    });

    loadUnresolvedAlertBadge();
  } catch (err) {
    console.error("Alerts load error:", err);
  }
}

async function toggleAlertResolution(alertId, newStatus) {
  try {
    const res = await fetch(`/api/alerts/${alertId}/resolve`, {
      method: "PUT",
      headers: getAuthHeaders(),
      body: JSON.stringify({ is_resolved: newStatus })
    });
    if (!res.ok) throw new Error("Could not update alert status");
    loadAlerts();
  } catch (err) {
    alert(err.message);
  }
}

async function loadUnresolvedAlertBadge() {
  try {
    const res = await fetch("/api/alerts?unresolved_only=true", { headers: getAuthHeaders() });
    if (res.ok) {
      const alerts = await res.json();
      const badge = document.getElementById("unresolved-alert-count");
      if (badge) {
        if (alerts.length > 0) {
          badge.innerText = alerts.length;
          badge.style.display = "inline-block";
        } else {
          badge.style.display = "none";
        }
      }
    }
  } catch (e) {}
}

/* =========================================================================
   7. AUDIT LOG VIEW
   ========================================================================= */
async function loadAuditLogs() {
  try {
    const res = await fetch("/api/audit", { headers: getAuthHeaders() });
    if (!res.ok) throw new Error("Could not fetch audit records");
    const logs = await res.json();
    const tbody = document.getElementById("audit-table-body");
    tbody.innerHTML = "";

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No audit records available.</td></tr>`;
      return;
    }

    logs.forEach(l => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><small>${escapeHtml(l.timestamp)}</small></td>
        <td><code>${escapeHtml(l.event_type)}</code></td>
        <td><strong>${escapeHtml(l.username)}</strong></td>
        <td>${escapeHtml(l.description)}</td>
        <td><small>${escapeHtml(l.ip_source)}</small></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Audit load error:", err);
  }
}

/* =========================================================================
   8. DEVICE DETAIL & EXPLAINABLE RISK MODAL
   ========================================================================= */
async function inspectDevice(deviceId) {
  try {
    const res = await fetch(`/api/devices/${deviceId}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error("Could not fetch device details");
    const dev = await res.json();

    document.getElementById("modal-device-name").innerText = `${dev.hostname || "Device"} (${dev.ip_address})`;
    document.getElementById("modal-device-meta").innerText = `MAC: ${dev.mac_address} | Vendor: ${dev.manufacturer} | Category: ${dev.device_type}`;

    const risk = dev.risk_assessment || {
      risk_score: 0,
      risk_level: "Low",
      factor_unknown: 0,
      factor_firmware: 0,
      factor_credential: 0,
      factor_exposure: 0,
      factor_config: 0,
      details: []
    };

    const riskBadgeClass = getRiskBadgeClass(risk.risk_level);

    let html = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; background-color: rgba(255, 255, 255, 0.02); padding: 1rem; border-radius: var(--radius);">
        <div>
          <span style="font-size: 0.85rem; color: var(--text-muted);">Composite Risk Score:</span>
          <div style="font-size: 1.75rem; font-weight: 700;">${risk.risk_score} <span style="font-size: 1rem; font-weight: 400; color: var(--text-muted);">/ 100</span></div>
        </div>
        <div>
          <span class="badge ${riskBadgeClass}" style="font-size: 0.9rem; padding: 0.4rem 0.8rem;">${risk.risk_level} Risk</span>
        </div>
      </div>

      <h4 style="font-size: 0.95rem; margin-bottom: 0.75rem; color: #fff;">Risk Factor Contribution Breakdown (Proposal Chapter 10)</h4>
      <div style="margin-bottom: 1.5rem;">
        <div class="factor-row">
          <div class="factor-header">
            <span>Unknown Device Status (Weight 25):</span>
            <strong>${risk.factor_unknown} / 25</strong>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: ${(risk.factor_unknown / 25) * 100}%; background-color: ${risk.factor_unknown > 0 ? 'var(--danger)' : 'var(--success)'};"></div></div>
        </div>

        <div class="factor-row">
          <div class="factor-header">
            <span>Firmware Vulnerability (Weight 25):</span>
            <strong>${risk.factor_firmware} / 25</strong>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: ${(risk.factor_firmware / 25) * 100}%; background-color: ${risk.factor_firmware > 15 ? 'var(--danger)' : (risk.factor_firmware > 0 ? 'var(--warning)' : 'var(--success)')};"></div></div>
        </div>

        <div class="factor-row">
          <div class="factor-header">
            <span>Credential Security (Weight 25):</span>
            <strong>${risk.factor_credential} / 25</strong>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: ${(risk.factor_credential / 25) * 100}%; background-color: ${risk.factor_credential > 0 ? 'var(--danger)' : 'var(--success)'};"></div></div>
        </div>

        <div class="factor-row">
          <div class="factor-header">
            <span>Network Exposure (Weight 15):</span>
            <strong>${risk.factor_exposure} / 15</strong>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: ${(risk.factor_exposure / 15) * 100}%; background-color: ${risk.factor_exposure > 8 ? 'var(--danger)' : (risk.factor_exposure > 0 ? 'var(--warning)' : 'var(--success)')};"></div></div>
        </div>

        <div class="factor-row">
          <div class="factor-header">
            <span>Security Configuration (Weight 10):</span>
            <strong>${risk.factor_config} / 10</strong>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: ${(risk.factor_config / 10) * 100}%; background-color: ${risk.factor_config > 5 ? 'var(--danger)' : 'var(--success)'};"></div></div>
        </div>
      </div>

      <h4 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: #fff;">Explainable Security Findings</h4>
      <div style="background-color: var(--bg-main); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 0.75rem; margin-bottom: 1.5rem; font-size: 0.85rem;">
        ${risk.details && risk.details.length > 0 ? 
          risk.details.map(f => `<div style="margin-bottom: 0.35rem;">• <strong>${escapeHtml(f.factor)}:</strong> ${escapeHtml(f.detail)}</div>`).join("") :
          `<div style="color: var(--success);">✓ No critical risk indicators flagged for this device.</div>`
        }
      </div>

      <h4 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: #fff;">Hardware & Observed Network Metadata</h4>
      <div style="font-size: 0.85rem; display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1.5rem;">
        <div><strong>Firmware Version:</strong> ${escapeHtml(dev.firmware_version || "Unknown")}</div>
        <div><strong>Credential Status:</strong> ${escapeHtml(dev.credential_status || "Unknown")}</div>
        <div><strong>Open Ports:</strong> ${dev.open_ports && dev.open_ports.length > 0 ? dev.open_ports.join(", ") : "None Detected"}</div>
        <div><strong>Observed Services:</strong> ${dev.services && dev.services.length > 0 ? dev.services.join(", ") : "None"}</div>
        <div><strong>First Seen:</strong> ${dev.first_seen}</div>
        <div><strong>Last Seen:</strong> ${dev.last_seen}</div>
      </div>
    `;

    const currentUser = getCurrentUser();
    if (currentUser && currentUser.role === "admin") {
      html += `
        <div style="display: flex; gap: 0.5rem; border-top: 1px solid var(--border-color); padding-top: 1rem;">
          <button class="btn btn-secondary btn-sm" onclick="recalculateRisk(${dev.id})">🔄 Recalculate Risk</button>
          <button class="btn btn-secondary btn-sm" onclick="toggleKnownDevice(${dev.id}, ${!dev.is_known_device})">
            ${dev.is_known_device ? "Mark as Rogue/Unknown" : "Authorize as Known Device"}
          </button>
        </div>
      `;
    }

    document.getElementById("modal-content").innerHTML = html;
    document.getElementById("detail-modal").classList.add("open");
  } catch (err) {
    alert(err.message);
  }
}

function closeDetailModal() {
  document.getElementById("detail-modal").classList.remove("open");
}

async function recalculateRisk(deviceId) {
  try {
    const res = await fetch(`/api/risk/evaluate/${deviceId}`, {
      method: "POST",
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error("Recalculation failed");
    inspectDevice(deviceId);
    loadRiskAssessmentData();
    loadDashboardOverview();
  } catch (err) {
    alert(err.message);
  }
}

async function toggleKnownDevice(deviceId, newStatus) {
  try {
    const res = await fetch(`/api/devices/${deviceId}`, {
      method: "PUT",
      headers: getAuthHeaders(),
      body: JSON.stringify({ is_known_device: newStatus })
    });
    if (!res.ok) throw new Error("Update failed");
    await fetch(`/api/risk/evaluate/${deviceId}`, {
      method: "POST",
      headers: getAuthHeaders()
    });
    inspectDevice(deviceId);
    loadRiskAssessmentData();
    loadDashboardOverview();
  } catch (err) {
    alert(err.message);
  }
}

/* =========================================================================
   9. HELPER UTILITIES
   ========================================================================= */
function getRiskBadgeClass(level) {
  switch ((level || "").toLowerCase()) {
    case "high":
    case "critical": return "badge-high";
    case "medium": return "badge-medium";
    default: return "badge-low";
  }
}

function getCategoryIcon(type) {
  switch (type) {
    case "CCTV Camera": return "📹";
    case "Printer": return "🖨️";
    case "Smart Lock": return "🔒";
    case "Sensor": return "🌡️";
    case "Smart Plug": return "🔌";
    case "Network Device": return "📡";
    default: return "❓";
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
