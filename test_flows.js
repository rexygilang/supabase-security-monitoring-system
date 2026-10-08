const crypto = require('crypto');
const { verifyHmacSignature } = require('./api/webhook.js');

/**
 * Test Runner Script for HMAC Security Gateway & Webhook Flows
 * Required Output: "3 passed, 0 failed"
 */
function runHmacTestSuite() {
  console.log('=' .repeat(65));
  console.log('          SECURITY WEBHOOK HMAC-SHA256 SUITE TEST RUNNER          ');
  console.log('=' .repeat(65));

  const secret = 'prod_secret_key_8f93a21e4b';
  const testPayload = JSON.stringify({
    event: 'DATABASE_MUTATION',
    table: 'admin_users',
    action: 'DROP TABLE',
    query: 'DROP TABLE admin_users; --',
    source_ip: '10.0.4.12'
  });

  // Calculate valid signature
  const validSignature = crypto
    .createHmac('sha256', secret)
    .update(testPayload)
    .digest('hex');

  const invalidSignature = 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0';

  let passedCount = 0;
  let failedCount = 0;

  console.log('[+] Target Function: verifyHmacSignature (api/webhook.js)');
  console.log('[+] Hash Algorithm : SHA256 with timingSafeEqual verification\n');

  // TEST 1: Valid HMAC Signature
  try {
    const isVal = verifyHmacSignature(testPayload, validSignature, secret);
    if (isVal === true) {
      console.log('✔ Test 1 PASSED: Valid HMAC-SHA256 Signature correctly accepted.');
      passedCount++;
    } else {
      console.error('❌ Test 1 FAILED: Valid signature was rejected.');
      failedCount++;
    }
  } catch (err) {
    console.error(`❌ Test 1 ERROR: ${err.message}`);
    failedCount++;
  }

  // TEST 2: Invalid HMAC Signature
  try {
    const isVal = verifyHmacSignature(testPayload, invalidSignature, secret);
    if (isVal === false) {
      console.log('✔ Test 2 PASSED: Tampered/Invalid HMAC Signature correctly rejected.');
      passedCount++;
    } else {
      console.error('❌ Test 2 FAILED: Invalid signature was incorrectly accepted.');
      failedCount++;
    }
  } catch (err) {
    console.error(`❌ Test 2 ERROR: ${err.message}`);
    failedCount++;
  }

  // TEST 3: Missing HMAC Signature
  try {
    const isVal = verifyHmacSignature(testPayload, null, secret);
    if (isVal === false) {
      console.log('✔ Test 3 PASSED: Missing HMAC Signature header correctly rejected.');
      passedCount++;
    } else {
      console.error('❌ Test 3 FAILED: Missing signature header was incorrectly accepted.');
      failedCount++;
    }
  } catch (err) {
    console.error(`❌ Test 3 ERROR: ${err.message}`);
    failedCount++;
  }

  console.log('\n' + '-' .repeat(65));
  console.log(`TEST SUMMARY: ${passedCount} passed, ${failedCount} failed`);
  console.log('-' .repeat(65));
  
  if (failedCount === 0 && passedCount === 3) {
    console.log('🎉 SUCCESS: All HMAC Security Webhook flow tests passed!');
  } else {
    process.exitCode = 1;
  }
}

runHmacTestSuite();
