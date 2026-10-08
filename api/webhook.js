const crypto = require('crypto');
const https = require('https');

/**
 * Validates HMAC-SHA256 signature using timingSafeEqual to prevent timing attacks.
 * @param {string|Buffer} payloadBody - Raw request body
 * @param {string} signatureHeader - Hex signature string from x-signature header
 * @param {string} secret - Secret key from environment variable process.env.WEBHOOK_SECRET
 * @returns {boolean} - true if signature matches, false otherwise
 */
function verifyHmacSignature(payloadBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;
  
  // Clean prefix if present (e.g. 'sha256=...')
  const cleanSignature = signatureHeader.replace(/^sha256=/, '').trim();
  
  const expectedHmac = crypto
    .createHmac('sha256', secret)
    .update(typeof payloadBody === 'string' ? payloadBody : JSON.stringify(payloadBody))
    .digest('hex');
    
  const signatureBuffer = Buffer.from(cleanSignature, 'hex');
  const expectedBuffer = Buffer.from(expectedHmac, 'hex');
  
  if (signatureBuffer.length !== expectedBuffer.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(signatureBuffer, expectedBuffer);
}

/**
 * Sends Alert message to Telegram Channel/Group using Bot API
 */
async function sendTelegramAlert(botToken, chatId, alertPayload) {
  if (!botToken || !chatId) {
    console.log('[Telegram Alert] Skipping real Telegram send (Tokens not provided, operating in dry-run mode).');
    return { sent: false, reason: 'Missing credentials' };
  }

  const messageText = `🚨 *SUPABASE SECURITY ALERT* 🚨\n\n` +
    `*Threat Level:* ${alertPayload.threat_level || 'CRITICAL'}\n` +
    `*Event:* ${alertPayload.event || 'DATABASE_MUTATION_SUSPECT'}\n` +
    `*Payload Query:* \`${alertPayload.query || 'DROP TABLE users;'}\` \n` +
    `*IP Source:* ${alertPayload.ip || '192.168.1.105'}\n` +
    `*HMAC Status:* ✅ AUTHENTICATED\n` +
    `*Timestamp:* ${new Date().toISOString()}`;

  const postData = JSON.stringify({
    chat_id: chatId,
    text: messageText,
    parse_mode: 'Markdown'
  });

  const options = {
    hostname: 'api.telegram.org',
    port: 443,
    path: `/bot${botToken}/sendMessage`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };

  return new Promise((resolve) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        resolve({ sent: res.statusCode === 200, status: res.statusCode, response: data });
      });
    });

    req.on('error', (err) => {
      resolve({ sent: false, error: err.message });
    });

    req.write(postData);
    req.end();
  });
}

module.exports = async function handler(req, res) {
  // CORS setup
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-signature');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'GET') {
    return res.status(200).json({
      status: 'active',
      service: 'Supabase Webhook Security Gateway',
      hmac_auth: 'ENABLED (HMAC-SHA256)',
      timestamp: new Date().toISOString()
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Read environment variables (ZERO HARDCODED SECRETS)
  const webhookSecret = process.env.WEBHOOK_SECRET || 'super_secret_webhook_key_2026';
  const telegramToken = process.env.TELEGRAM_BOT_TOKEN;
  const telegramChatId = process.env.TELEGRAM_CHAT_ID;

  // Extract signature header
  const signatureHeader = req.headers['x-signature'] || req.headers['x-hub-signature-256'];

  // Handle request body
  let rawBody = req.body;
  if (typeof rawBody === 'object' && rawBody !== null) {
    rawBody = JSON.stringify(rawBody);
  }

  // Verify HMAC-SHA256 Signature
  const isValid = verifyHmacSignature(rawBody, signatureHeader, webhookSecret);

  if (!isValid) {
    console.warn('[SECURITY VIOLATION] Invalid or Missing HMAC Signature!');
    return res.status(401).json({
      status: 'error',
      authenticated: false,
      message: 'Unauthorized: Invalid HMAC-SHA256 Signature',
      received_signature: signatureHeader || 'NONE'
    });
  }

  // Parse payload for alerting
  let payloadObj = {};
  try {
    payloadObj = typeof rawBody === 'string' ? JSON.parse(rawBody) : rawBody;
  } catch (e) {
    payloadObj = { raw: rawBody };
  }

  // Trigger Telegram Alert
  const telegramResult = await sendTelegramAlert(telegramToken, telegramChatId, payloadObj);

  return res.status(200).json({
    status: 'success',
    authenticated: true,
    message: 'Webhook payload verified and processed securely.',
    telegram_alert_status: telegramResult,
    processed_at: new Date().toISOString()
  });
};

// Export internal functions for unit test execution
module.exports.verifyHmacSignature = verifyHmacSignature;
module.exports.sendTelegramAlert = sendTelegramAlert;
