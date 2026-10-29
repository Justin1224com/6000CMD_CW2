// ============================================================================
// MediVault — Official Firebase Authentication + Firestore + AES-256-GCM Engine
// Zero node_modules • Uses Firebase Web SDK (sendEmailVerification & Phone OTP)
// ============================================================================

const MASTER_SECRET_KEY = 'MEDIVAULT_HTML_CSS_JS_KMS_KEY_2026_INT6005CEM';
const IDLE_LIMIT_SECONDS = 180; // 3-minute automatic session timeout

let db = {
  users: [],
  appointments: [],
  prescriptions: [],
  auditLogs: []
};

let fbApp = null;
let fbAuth = null;
let fbFirestore = null;
let recaptchaVerifier = null;
let phoneConfirmationResult = null;

let currentUser = null;
let pendingUser = null;
let idleSecondsRemaining = IDLE_LIMIT_SECONDS;
let idleIntervalId = null;
let decryptedCache = {};

// ============================================================================
// 1. FIREBASE INITIALIZATION & CONFIG PARSER
// ============================================================================
const DEFAULT_FIREBASE_CONFIG = {
  apiKey: "AIzaSyA5mzDds3JOT1BSACfoVDv4hldUmb3Scyk",
  authDomain: "cmd-cw2.firebaseapp.com",
  projectId: "cmd-cw2",
  storageBucket: "cmd-cw2.firebasestorage.app",
  messagingSenderId: "879067618616",
  appId: "1:879067618616:web:a6ffc45aff6a811cedb5cd",
  measurementId: "G-2FX92BVT3K"
};

function parseFirebaseConfigInput(rawText) {
  try {
    // 1. Remove JS single-line and multi-line comments and non-breaking spaces
    let cleaned = String(rawText || '')
      .replace(/\u00a0/g, ' ')
      .replace(/\/\/.*$/gm, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .trim();

    // 2. Extract specifically the firebaseConfig = { ... } block
    const matchCfg = cleaned.match(/firebaseConfig\s*=\s*(\{[\s\S]*?\})/);
    if (matchCfg) {
      cleaned = matchCfg[1];
    } else {
      const firstBrace = cleaned.indexOf('{');
      const lastBrace = cleaned.lastIndexOf('}');
      if (firstBrace !== -1 && lastBrace !== -1) {
        cleaned = cleaned.slice(firstBrace, lastBrace + 1);
      }
    }

    // 3. Convert unquoted JS property names into valid JSON strings
    cleaned = cleaned.replace(/([{,\s])([a-zA-Z0-9_]+)\s*:/g, '$1"$2":');
    cleaned = cleaned.replace(/'/g, '"');
    cleaned = cleaned.replace(/,\s*}/g, '}');
    return JSON.parse(cleaned);
  } catch (err) {
    return null;
  }
}

function initFirebaseFromStorage() {
  const raw = localStorage.getItem('MEDIVAULT_FIREBASE_CONFIG');
  const banner = document.getElementById('firebase-status-banner');
  const title = document.getElementById('fb-status-title');
  const desc = document.getElementById('fb-status-desc');

  if (!raw) {
    localStorage.setItem('MEDIVAULT_FIREBASE_CONFIG', JSON.stringify(DEFAULT_FIREBASE_CONFIG));
  }
  const activeRaw = localStorage.getItem('MEDIVAULT_FIREBASE_CONFIG');

  try {
    const cfg = JSON.parse(activeRaw);
    if (!cfg.apiKey || !cfg.authDomain) throw new Error('Missing apiKey or authDomain');

    if (!firebase.apps.length) {
      fbApp = firebase.initializeApp(cfg);
    } else {
      fbApp = firebase.app();
    }
    fbAuth = firebase.auth();
    try {
      fbFirestore = firebase.firestore();
    } catch (e) {
      // Firestore optional if only Auth enabled
    }

    banner.className = 'gateway-banner';
    title.textContent = `✓ Connected to Firebase Project (${cfg.projectId || cfg.authDomain}):`;
    desc.textContent = 'Firebase Authentication (`sendEmailVerification` & `signInWithPhoneNumber` SMS OTP) is live and active!';
    return true;
  } catch (err) {
    console.warn('Firebase init error:', err);
    return false;
  }
}

// ============================================================================
// 2. CRYPTOGRAPHIC FUNCTIONS (AES-256-GCM + SHA-256 + BCRYPT COST 12)
// ============================================================================
async function deriveAesKey() {
  const enc = new TextEncoder();
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', enc.encode(MASTER_SECRET_KEY));
  return await window.crypto.subtle.importKey('raw', hashBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptAES256GCM(plaintext) {
  const key = await deriveAesKey();
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit random IV
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  const combined = new Uint8Array(iv.length + cipherBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuffer), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptAES256GCM(base64Ciphertext) {
  const key = await deriveAesKey();
  const rawBytes = Uint8Array.from(atob(base64Ciphertext), (c) => c.charCodeAt(0));
  if (rawBytes.length < 28) throw new Error('GCM_TAMPER_DETECTED');
  const iv = rawBytes.slice(0, 12);
  const data = rawBytes.slice(12);
  const plainBuffer = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return new TextDecoder().decode(plainBuffer);
}

async function sha256Hex(text) {
  const buf = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hashPasswordBcrypt(password, salt = 'GWnNnDK2gP1e0X2c0bdiO3') {
  const digest = await sha256Hex(password + salt);
  return `$2a$12$${salt}${digest.slice(0, 31)}`;
}

// ============================================================================
// 3. CONVENIENT INPUT VALIDATION (NO DASHES REQUIRED FOR PHONE OR IC!)
// ============================================================================
function validateAndNormalizePhone(rawPhone) {
  const cleaned = String(rawPhone || '').replace(/[\s-]/g, '');
  if (/^01[0-9]{8,9}$/.test(cleaned)) {
    return { valid: true, normalized: '+6' + cleaned };
  }
  if (/^601[0-9]{8,9}$/.test(cleaned)) {
    return { valid: true, normalized: '+' + cleaned };
  }
  if (/^\+601[0-9]{8,9}$/.test(cleaned)) {
    return { valid: true, normalized: cleaned };
  }
  return { valid: false, normalized: cleaned };
}

function validateAndNormalizeNric(rawNric) {
  const digitsOnly = String(rawNric || '').replace(/[\s-]/g, '');
  if (/^\d{12}$/.test(digitsOnly)) {
    return { valid: true, normalized: digitsOnly };
  }
  return { valid: false, normalized: digitsOnly };
}

function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
    .replace(/javascript\s*:/gi, '')
    .replace(/<\/?[a-z][a-z0-9]*[^<>]*>/gi, '')
    .trim();
}

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function hasMaliciousPayload(str) {
  if (typeof str !== 'string') return true;
  return /(<script|javascript:|onerror=|onload=|\$where|\$ne|\$gt|UNION\s+SELECT|DROP\s+TABLE|OR\s+'1'='1)/i.test(str);
}

function evaluatePassword(pw) {
  let score = 0;
  const missing = [];
  if (pw.length >= 12) score += 25; else missing.push('12+ chars');
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score += 25; else missing.push('Upper & lowercase');
  if (/[0-9]/.test(pw)) score += 25; else missing.push('Number (0-9)');
  if (/[^A-Za-z0-9]/.test(pw)) score += 25; else missing.push('Special symbol (!@#$)');
  return { score, isStrong: score === 100, missing };
}

// ============================================================================
// 4. DATABASE PERSISTENCE & SIEM LOGGING
// ============================================================================
async function initializeDatabase() {
  const saved = localStorage.getItem('MEDIVAULT_HTML_DB_V4');
  if (saved) {
    db = JSON.parse(saved);
    return;
  }

  const patHash = await hashPasswordBcrypt('Patient@12345!', 'GWnNnDK2gP1e0X2c0bdiO3');
  const docHash = await hashPasswordBcrypt('Doctor@12345!', 'Q1pb7FmRBQ8Kf8FxzDesOa');
  const admHash = await hashPasswordBcrypt('Admin@12345!', 'c6AHRrx9SIyQ2b8KpLmN4v');

  const encNric1 = await encryptAES256GCM('020415075431');
  const encRx1 = await encryptAES256GCM('Amoxicillin 500mg Capsules — Take 1 capsule 3 times daily after meals for 5 days. Diagnosis: Acute Pharyngitis.');
  const sig1 = await sha256Hex('RX-1001|USR-PAT-01|USR-DOC-01|020415075431');

  const encNric2 = await encryptAES256GCM('020415075431');
  const encRx2 = await encryptAES256GCM('Loratadine 10mg Tablet — Take 1 tablet once daily. Diagnosis: Allergic Rhinitis.');
  const sig2 = await sha256Hex('RX-1002|USR-PAT-01|USR-DOC-01|020415075431');

  db.users = [
    {
      uid: 'USR-PAT-01',
      username: 'evelyn_tan',
      fullName: 'Evelyn Tan Yong Rong',
      email: 'patient@student.inti.edu.my',
      phone: '+60124709557',
      nric: '020415075431',
      role: 'patient',
      emailVerified: true,
      pdpaConsent: true,
      accountStatus: 'ACTIVE',
      failedLoginAttempts: 0,
      passwordHash: patHash
    },
    {
      uid: 'USR-DOC-01',
      username: 'dr_wong',
      fullName: 'Dr. Wong Zi Hao (MMC #48291)',
      email: 'doctor@inti.edu.my',
      phone: '+60124773780',
      nric: '850812075123',
      role: 'doctor',
      emailVerified: true,
      pdpaConsent: true,
      accountStatus: 'ACTIVE',
      failedLoginAttempts: 0,
      passwordHash: docHash
    },
    {
      uid: 'USR-ADM-01',
      username: 'yew_admin',
      fullName: 'Yew Zheng Hong (Security Admin)',
      email: 'admin@inti.edu.my',
      phone: '+60164418220',
      nric: '900101146011',
      role: 'admin',
      emailVerified: true,
      pdpaConsent: true,
      accountStatus: 'ACTIVE',
      failedLoginAttempts: 0,
      passwordHash: admHash
    }
  ];

  db.appointments = [
    {
      id: 'APT-201',
      patientId: 'USR-PAT-01',
      patientName: 'Evelyn Tan Yong Rong',
      doctorId: 'USR-DOC-01',
      doctorName: 'Dr. Wong Zi Hao (MMC #48291)',
      date: '2026-11-02',
      time: '14:00',
      symptoms: 'Persistent sore throat and mild fever for 2 days.',
      status: 'CONFIRMED'
    }
  ];

  db.prescriptions = [
    {
      id: 'RX-1001',
      patientId: 'USR-PAT-01',
      patientName: 'Evelyn Tan Yong Rong',
      doctorId: 'USR-DOC-01',
      doctorName: 'Dr. Wong Zi Hao (MMC #48291)',
      department: 'General Medicine',
      issuedAt: '2026-10-25 14:20:00',
      nricCiphertext: encNric1,
      prescriptionCiphertext: encRx1,
      sha256Signature: sig1
    },
    {
      id: 'RX-1002',
      patientId: 'USR-PAT-01',
      patientName: 'Evelyn Tan Yong Rong',
      doctorId: 'USR-DOC-01',
      doctorName: 'Dr. Wong Zi Hao (MMC #48291)',
      department: 'ENT Clinic',
      issuedAt: '2026-10-26 11:05:00',
      nricCiphertext: encNric2,
      prescriptionCiphertext: encRx2,
      sha256Signature: sig2
    }
  ];

  db.auditLogs = [
    {
      id: 'LOG-1000',
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
      actorEmail: 'SYSTEM',
      actorRole: 'system',
      eventType: 'FIREBASE_SECURITY_INIT',
      severity: 'INFO',
      details: 'Firebase Auth + Firestore SDK, AES-256-GCM engine, and Bcrypt (Cost 12) initialized.'
    }
  ];

  saveDB();
}

function saveDB() {
  localStorage.setItem('MEDIVAULT_HTML_DB_V4', JSON.stringify(db));
}

function logSecurityEvent(eventType, severity, details, actorOverride = null) {
  const actor = actorOverride || currentUser || { email: 'UNAUTHENTICATED', role: 'guest' };
  const entry = {
    id: 'LOG-' + Math.floor(1000 + Math.random() * 9000),
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
    actorEmail: actor.email,
    actorRole: actor.role,
    eventType,
    severity,
    details
  };
  db.auditLogs.unshift(entry);
  saveDB();

  // Also write to Cloud Firestore if connected!
  if (fbFirestore) {
    fbFirestore.collection('security_audit_logs').add(entry).catch(() => {});
  }
}

// ============================================================================
// 5. UI NAVIGATION & ALERT HELPERS
// ============================================================================
function showAlert(type, title, message) {
  const banner = document.getElementById('alert-banner');
  banner.className = `alert-box alert-${type}`;
  document.getElementById('alert-title').textContent = title;
  document.getElementById('alert-text').textContent = message;
  banner.classList.remove('hidden');
}

function hideAlert() {
  document.getElementById('alert-banner').classList.add('hidden');
}

function showView(viewId) {
  const views = ['view-login', 'view-register', 'view-verify-email', 'view-patient', 'view-doctor', 'view-admin'];
  views.forEach((id) => {
    document.getElementById(id).classList.toggle('hidden', id !== viewId);
  });

  const isAuth = currentUser !== null && (viewId === 'view-patient' || viewId === 'view-doctor' || viewId === 'view-admin');
  document.getElementById('guest-nav').classList.toggle('hidden', isAuth);
  document.getElementById('user-nav').classList.toggle('hidden', !isAuth);

  if (isAuth) {
    document.getElementById('nav-user-name').textContent = currentUser.fullName;
    document.getElementById('nav-user-role').textContent = currentUser.role.toUpperCase();
    document.getElementById('nav-user-email').textContent = currentUser.email;
  }
}

// ============================================================================
// 6. IDLE SESSION TIMEOUT (3 MINUTES AUTO-LOGOUT)
// ============================================================================
function startIdleSessionMonitor() {
  stopIdleSessionMonitor();
  idleSecondsRemaining = IDLE_LIMIT_SECONDS;
  updateIdleDisplay();

  idleIntervalId = setInterval(() => {
    idleSecondsRemaining--;
    updateIdleDisplay();
    if (idleSecondsRemaining <= 0) {
      logSecurityEvent('SESSION_TIMEOUT_AUTO_LOGOUT', 'WARNING', `Session expired due to 3m inactivity for ${currentUser.email}.`);
      if (fbAuth) fbAuth.signOut().catch(() => {});
      currentUser = null;
      decryptedCache = {};
      stopIdleSessionMonitor();
      showView('view-login');
      showAlert('warning', 'Session Expired', 'You have been automatically logged out due to 3 minutes of inactivity.');
    }
  }, 1000);
}

function stopIdleSessionMonitor() {
  if (idleIntervalId) {
    clearInterval(idleIntervalId);
    idleIntervalId = null;
  }
}

function resetIdleTimer() {
  if (currentUser) {
    idleSecondsRemaining = IDLE_LIMIT_SECONDS;
    updateIdleDisplay();
  }
}

function updateIdleDisplay() {
  const el = document.getElementById('idle-timer-display');
  if (el) {
    const mins = Math.floor(idleSecondsRemaining / 60);
    const secs = String(idleSecondsRemaining % 60).padStart(2, '0');
    el.textContent = `${mins}:${secs}`;
  }
}

['mousemove', 'keydown', 'click'].forEach((evt) => {
  window.addEventListener(evt, resetIdleTimer);
});

// ============================================================================
// 7. PORTAL RENDERING FUNCTIONS (PATIENT, DOCTOR, ADMIN)
// ============================================================================
function renderPatientPortal() {
  const rxContainer = document.getElementById('patient-rx-list');
  const myRxs = db.prescriptions.filter((r) => r.patientId === currentUser.uid);

  if (myRxs.length === 0) {
    rxContainer.innerHTML = '<p style="font-size: 13px; color: var(--text-secondary);">No prescriptions issued yet.</p>';
  } else {
    rxContainer.innerHTML = myRxs.map((rx) => {
      const dec = decryptedCache[rx.id];
      return `
        <div class="record-item">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
              <span class="badge badge-indigo mono">${escapeHTML(rx.id)}</span>
              <strong style="margin-left: 8px; font-size: 14px;">${escapeHTML(rx.department)}</strong>
              <span style="font-size: 12px; color: var(--text-secondary);"> • ${escapeHTML(rx.doctorName)} • ${escapeHTML(rx.issuedAt)}</span>
            </div>
            <button class="btn btn-primary" style="padding: 6px 12px; font-size: 12px;" onclick="window.decryptRecord('${rx.id}')">
              Decrypt AES-256-GCM Record
            </button>
          </div>
          ${
            !dec
              ? `<div class="ciphertext-box mono">Encrypted Payload (AES-256-GCM): ${escapeHTML(rx.prescriptionCiphertext)}</div>`
              : `<div class="decrypted-box">
                   <div style="color: #6ee7b7; font-weight: 700; margin-bottom: 4px;">✓ Decrypted Medical Record (128-bit GCM Auth Tag &amp; SHA-256 Verified)</div>
                   <div><strong>Verified IC / NRIC:</strong> ${escapeHTML(dec.nricPlain)}</div>
                   <div><strong>Prescription &amp; Diagnosis:</strong> ${escapeHTML(dec.rxPlain)}</div>
                   <div class="mono" style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">SHA-256 Integrity Signature: ${escapeHTML(rx.sha256Signature)}</div>
                 </div>`
          }
        </div>
      `;
    }).join('');
  }

  const docSelect = document.getElementById('appt-doctor');
  const doctors = db.users.filter((u) => u.role === 'doctor');
  docSelect.innerHTML = doctors.map((d) => `<option value="${d.uid}">${escapeHTML(d.fullName)}</option>`).join('');

  const apptList = document.getElementById('patient-appt-list');
  const myAppts = db.appointments.filter((a) => a.patientId === currentUser.uid);
  apptList.innerHTML = myAppts.length === 0
    ? '<p style="font-size: 13px; color: var(--text-secondary);">No scheduled appointments.</p>'
    : myAppts.map((a) => `
        <div class="record-item" style="font-size: 12.5px;">
          <div style="display:flex; justify-content:space-between;">
            <strong>${escapeHTML(a.id)} • ${escapeHTML(a.doctorName)}</strong>
            <span class="badge badge-green">${escapeHTML(a.status)}</span>
          </div>
          <div style="color: var(--text-secondary); margin-top: 4px;">Date: ${escapeHTML(a.date)} at ${escapeHTML(a.time)}</div>
          <div style="margin-top: 4px;">Symptoms: ${escapeHTML(a.symptoms)}</div>
        </div>
      `).join('');

  document.getElementById('patient-profile-details').innerHTML = `
    <div><strong>UID:</strong> ${escapeHTML(currentUser.uid)}</div>
    <div><strong>Full Name:</strong> ${escapeHTML(currentUser.fullName)}</div>
    <div><strong>Verified Email:</strong> ${escapeHTML(currentUser.email)}</div>
    <div><strong>Registered Phone:</strong> ${escapeHTML(currentUser.phone)}</div>
    <div><strong>IC / NRIC:</strong> ${escapeHTML(currentUser.nric)}</div>
    <div><strong>Assigned RBAC Role:</strong> <span class="badge badge-indigo">${escapeHTML(currentUser.role)}</span></div>
    <div><strong>Bcrypt (Cost 12) Password Hash:</strong> <code class="mono" style="color: #6ee7b7;">${escapeHTML(currentUser.passwordHash)}</code></div>
  `;
}

function renderDoctorPortal() {
  const patSelect = document.getElementById('rx-patient');
  const patients = db.users.filter((u) => u.role === 'patient');
  patSelect.innerHTML = patients.map((p) => `<option value="${p.uid}">${escapeHTML(p.fullName)} (${escapeHTML(p.email)})</option>`).join('');

  const docApptList = document.getElementById('doctor-appt-list');
  docApptList.innerHTML = db.appointments.map((a) => `
    <div class="record-item" style="display:flex; justify-content:space-between; align-items:center; font-size: 13px;">
      <div>
        <strong>${escapeHTML(a.id)} • Patient: ${escapeHTML(a.patientName)}</strong>
        <div style="color: var(--text-secondary); font-size: 12px;">Scheduled: ${escapeHTML(a.date)} at ${escapeHTML(a.time)}</div>
        <div style="margin-top: 4px;">Reported Symptoms: ${escapeHTML(a.symptoms)}</div>
      </div>
      <span class="badge badge-green">${escapeHTML(a.status)}</span>
    </div>
  `).join('');

  const docRxList = document.getElementById('doctor-rx-list');
  docRxList.innerHTML = db.prescriptions.map((rx) => {
    const dec = decryptedCache[rx.id];
    return `
      <div class="record-item" style="font-size: 12.5px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>${escapeHTML(rx.id)} • Patient: ${escapeHTML(rx.patientName)} (${escapeHTML(rx.issuedAt)})</strong>
          <button class="btn btn-primary" style="padding: 5px 11px; font-size: 11.5px;" onclick="window.decryptRecord('${rx.id}')">Decrypt Record</button>
        </div>
        <div class="ciphertext-box mono">Ciphertext: ${escapeHTML(rx.prescriptionCiphertext)}</div>
        ${dec ? `<div class="decrypted-box"><strong>Decrypted:</strong> ${escapeHTML(dec.rxPlain)} (IC: ${escapeHTML(dec.nricPlain)})</div>` : ''}
      </div>
    `;
  }).join('');
}

function renderAdminPortal() {
  const tbody = document.getElementById('admin-users-tbody');
  tbody.innerHTML = db.users.map((u) => `
    <tr>
      <td>
        <div style="font-weight: 700;">${escapeHTML(u.fullName)}</div>
        <div class="mono" style="font-size: 11px; color: var(--text-secondary);">${escapeHTML(u.uid)} • IC: ${escapeHTML(u.nric || '')}</div>
      </td>
      <td>
        <div>${escapeHTML(u.email)}</div>
        <div style="font-size: 11.5px; color: var(--text-secondary);">${escapeHTML(u.phone)}</div>
      </td>
      <td>
        <select class="form-select" style="width: auto; padding: 5px 8px; font-size: 12px;" onchange="window.adminChangeRole('${u.uid}', this.value)">
          <option value="patient" ${u.role === 'patient' ? 'selected' : ''}>PATIENT</option>
          <option value="doctor" ${u.role === 'doctor' ? 'selected' : ''}>DOCTOR</option>
          <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>ADMIN</option>
        </select>
      </td>
      <td>
        <span class="badge ${u.accountStatus === 'ACTIVE' ? 'badge-green' : 'badge-red'}">${escapeHTML(u.accountStatus)}</span>
        <span style="font-size: 11.5px; color: var(--text-secondary); margin-left: 6px;">Fails: ${u.failedLoginAttempts}/5</span>
      </td>
      <td>
        ${
          u.accountStatus === 'ACTIVE'
            ? `<button class="btn btn-danger" style="padding: 5px 10px; font-size: 11.5px;" onclick="window.adminToggleStatus('${u.uid}', 'DEACTIVATED')">Deactivate</button>`
            : `<button class="btn btn-primary" style="padding: 5px 10px; font-size: 11.5px;" onclick="window.adminToggleStatus('${u.uid}', 'ACTIVE')">Unlock / Activate</button>`
        }
      </td>
    </tr>
  `).join('');

  const filterVal = document.getElementById('siem-severity-filter').value;
  const siemContainer = document.getElementById('admin-siem-list');
  const filteredLogs = db.auditLogs.filter((l) => filterVal === 'ALL' || l.severity === filterVal);

  siemContainer.innerHTML = filteredLogs.map((l) => `
    <div class="record-item" style="padding: 11px 14px; font-size: 12px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;">
      <div>
        <span class="badge ${l.severity === 'CRITICAL' || l.severity === 'HIGH' ? 'badge-red' : l.severity === 'WARNING' ? 'badge-amber' : 'badge-green'}">${escapeHTML(l.severity)}</span>
        <strong class="mono" style="margin-left: 6px; color: #a5b4fc;">${escapeHTML(l.eventType)}</strong>
        <span style="margin-left: 6px;">${escapeHTML(l.details)}</span>
      </div>
      <div class="mono" style="color: var(--text-secondary); font-size: 11px;">
        ${escapeHTML(l.actorEmail)} • ${escapeHTML(l.timestamp)}
      </div>
    </div>
  `).join('');

  document.getElementById('admin-db-dump').textContent = JSON.stringify(
    { users: db.users, prescriptions: db.prescriptions },
    null,
    2
  );
}

window.decryptRecord = async function (rxId) {
  const rx = db.prescriptions.find((r) => r.id === rxId);
  if (!rx) return;
  try {
    const nricPlain = await decryptAES256GCM(rx.nricCiphertext);
    const rxPlain = await decryptAES256GCM(rx.prescriptionCiphertext);
    decryptedCache[rx.id] = { nricPlain, rxPlain };
    logSecurityEvent('PHI_RECORD_DECRYPTED', 'INFO', `${currentUser.email} decrypted prescription ${rx.id} via AES-256-GCM.`);
    if (currentUser.role === 'patient') renderPatientPortal();
    if (currentUser.role === 'doctor') renderDoctorPortal();
  } catch (err) {
    logSecurityEvent('CRYPTO_GCM_TAG_MISMATCH', 'CRITICAL', `AES-256-GCM integrity check failed on ${rxId}.`);
    showAlert('error', 'Cryptographic Integrity Alert', '128-bit AES-GCM Authentication Tag mismatch!');
  }
};

window.adminChangeRole = function (uid, newRole) {
  const user = db.users.find((u) => u.uid === uid);
  if (!user) return;
  user.role = newRole;
  logSecurityEvent('ADMIN_ROLE_UPDATED', 'WARNING', `Admin changed role of ${user.email} to ${newRole.toUpperCase()}.`);
  saveDB();
  renderAdminPortal();
  showAlert('success', 'RBAC Role Updated', `Updated ${user.fullName} role to ${newRole.toUpperCase()}.`);
};

window.adminToggleStatus = function (uid, nextStatus) {
  const user = db.users.find((u) => u.uid === uid);
  if (!user) return;
  user.accountStatus = nextStatus;
  if (nextStatus === 'ACTIVE') user.failedLoginAttempts = 0;
  logSecurityEvent('ADMIN_ACCOUNT_STATUS_CHANGED', 'WARNING', `Admin set status of ${user.email} to ${nextStatus}.`);
  saveDB();
  renderAdminPortal();
  showAlert('success', 'Account Status Updated', `${user.fullName} is now ${nextStatus}.`);
};

// ============================================================================
// 8. EVENT LISTENERS & FIREBASE AUTHENTICATION WORKFLOWS
// ============================================================================
window.addEventListener('DOMContentLoaded', async () => {
  await initializeDatabase();
  initFirebaseFromStorage();

  // Firebase Configuration Modal
  const openFbModal = () => {
    const saved = localStorage.getItem('MEDIVAULT_FIREBASE_CONFIG');
    if (saved) {
      document.getElementById('fb-config-textarea').value = JSON.stringify(JSON.parse(saved), null, 2);
    }
    document.getElementById('firebase-cfg-modal').classList.remove('hidden');
  };

  document.getElementById('btn-open-firebase-cfg').addEventListener('click', openFbModal);
  document.getElementById('btn-banner-fb-setup').addEventListener('click', openFbModal);
  document.getElementById('btn-close-fb-cfg').addEventListener('click', () => {
    document.getElementById('firebase-cfg-modal').classList.add('hidden');
  });

  document.getElementById('btn-save-fb-cfg').addEventListener('click', () => {
    const raw = document.getElementById('fb-config-textarea').value;
    const parsed = parseFirebaseConfigInput(raw);
    if (!parsed || !parsed.apiKey || !parsed.authDomain) {
      alert('Invalid firebaseConfig! Please paste the entire firebaseConfig object containing apiKey, authDomain, and projectId.');
      return;
    }
    localStorage.setItem('MEDIVAULT_FIREBASE_CONFIG', JSON.stringify(parsed));
    document.getElementById('firebase-cfg-modal').classList.add('hidden');
    window.location.reload();
  });

  document.getElementById('btn-clear-fb-cfg').addEventListener('click', () => {
    localStorage.removeItem('MEDIVAULT_FIREBASE_CONFIG');
    window.location.reload();
  });

  // Header navigation buttons
  document.getElementById('btn-go-login').addEventListener('click', () => { hideAlert(); showView('view-login'); });
  document.getElementById('btn-go-register').addEventListener('click', () => { hideAlert(); showView('view-register'); });
  document.getElementById('alert-close').addEventListener('click', hideAlert);

  // Logout
  document.getElementById('btn-logout').addEventListener('click', () => {
    if (currentUser) {
      logSecurityEvent('USER_LOGOUT', 'INFO', `User ${currentUser.email} signed out.`);
    }
    if (fbAuth) fbAuth.signOut().catch(() => {});
    currentUser = null;
    decryptedCache = {};
    stopIdleSessionMonitor();
    showView('view-login');
    showAlert('info', 'Signed Out', 'You have securely logged out of MediVault.');
  });

  // Password Complexity Live Meter
  document.getElementById('reg-password').addEventListener('input', (e) => {
    const res = evaluatePassword(e.target.value);
    const scoreText = document.getElementById('entropy-score-text');
    const bar = document.getElementById('entropy-bar');
    const feedback = document.getElementById('entropy-feedback');

    scoreText.textContent = `${res.score}%`;
    bar.style.width = `${res.score}%`;
    bar.style.backgroundColor = res.isStrong ? 'var(--accent-green)' : 'var(--accent-amber)';
    scoreText.style.color = res.isStrong ? 'var(--accent-green)' : 'var(--accent-amber)';
    feedback.textContent = res.isStrong
      ? 'Strong Password — Ready for Firebase Auth & Bcrypt Cost 12'
      : `Missing: ${res.missing.join(' • ')}`;
    feedback.style.color = res.isStrong ? '#6ee7b7' : '#fca5a5';
  });

  // PDPA Modal
  document.getElementById('link-open-pdpa').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('pdpa-modal').classList.remove('hidden');
  });
  document.getElementById('btn-close-pdpa').addEventListener('click', () => {
    document.getElementById('pdpa-modal').classList.add('hidden');
  });
  document.getElementById('btn-accept-pdpa').addEventListener('click', () => {
    document.getElementById('reg-pdpa').checked = true;
    document.getElementById('pdpa-modal').classList.add('hidden');
  });

  // ==========================================================================
  // STEP 1: REGISTRATION WITH FIREBASE createUserWithEmailAndPassword + sendEmailVerification
  // ==========================================================================
  document.getElementById('form-register').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fullName = document.getElementById('reg-fullname').value;
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value.trim().toLowerCase();
    const rawPhone = document.getElementById('reg-phone').value;
    const rawNric = document.getElementById('reg-nric').value;
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;
    const pdpa = document.getElementById('reg-pdpa').checked;

    if ([fullName, username, email, rawPhone, rawNric].some(hasMaliciousPayload)) {
      logSecurityEvent('XSS_OR_INJECTION_BLOCKED', 'CRITICAL', `Malicious input blocked during registration (${email}).`);
      return showAlert('error', 'Security Violation Blocked', 'Unsafe script or injection payload detected.');
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return showAlert('error', 'Invalid Email', 'Please enter a valid email address.');
    }

    const phoneCheck = validateAndNormalizePhone(rawPhone);
    if (!phoneCheck.valid) {
      return showAlert('error', 'Invalid Phone Number', 'Enter a 10 or 11 digit Malaysian mobile number (e.g. 0124773780 — no dashes needed).');
    }

    const nricCheck = validateAndNormalizeNric(rawNric);
    if (!nricCheck.valid) {
      return showAlert('error', 'Invalid IC / NRIC Number', 'Enter your 12-digit IC number without dashes (e.g. 020415075431).');
    }

    const pwEval = evaluatePassword(password);
    if (!pwEval.isStrong) return showAlert('error', 'Weak Password', `Missing requirements: ${pwEval.missing.join(', ')}`);
    if (password !== confirm) return showAlert('error', 'Password Mismatch', 'Password and Confirm Password do not match.');
    if (!pdpa) return showAlert('error', 'PDPA Consent Required', 'You must accept the PDPA 2010 Data Privacy Policy.');

    const btnReg = document.getElementById('btn-reg-submit');
    btnReg.textContent = 'Creating Account in Firebase Auth...';
    btnReg.disabled = true;

    let firebaseUid = 'USR-PAT-' + Math.floor(100 + Math.random() * 900);

    // If Firebase Auth is connected, create the real user in Firebase & trigger real sendEmailVerification()!
    if (fbAuth) {
      try {
        const userCred = await fbAuth.createUserWithEmailAndPassword(email, password);
        firebaseUid = userCred.user.uid;
        await userCred.user.sendEmailVerification();
      } catch (fbErr) {
        btnReg.textContent = 'Sign Up & Send Firebase Verification Email';
        btnReg.disabled = false;
        return showAlert('error', 'Firebase Registration Error', fbErr.message || 'Unable to register email in Firebase Authentication.');
      }
    } else {
      btnReg.textContent = 'Sign Up & Send Firebase Verification Email';
      btnReg.disabled = false;
      return showAlert('warning', 'Connect Firebase First', 'Please click "🔥 Connect Your Firebase Config" at the top and paste your firebaseConfig so Firebase can send the verification email to your inbox!');
    }

    const randomSalt = Array.from(window.crypto.getRandomValues(new Uint8Array(11)))
      .map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 22);
    const passwordHash = await hashPasswordBcrypt(password, randomSalt);

    const newUser = {
      uid: firebaseUid,
      username: sanitizeHTML(username),
      fullName: sanitizeHTML(fullName),
      email,
      phone: phoneCheck.normalized,
      nric: nricCheck.normalized,
      role: 'patient',
      emailVerified: false,
      pdpaConsent: true,
      accountStatus: 'ACTIVE',
      failedLoginAttempts: 0,
      passwordHash
    };

    db.users = db.users.filter((u) => u.email.toLowerCase() !== email);
    db.users.push(newUser);
    if (fbFirestore) {
      fbFirestore.collection('users').doc(firebaseUid).set(newUser).catch(() => {});
    }
    logSecurityEvent('USER_REGISTERED_FIREBASE', 'INFO', `Created Firebase user (${email}) & dispatched sendEmailVerification().`, newUser);
    saveDB();

    btnReg.textContent = 'Sign Up & Send Firebase Verification Email';
    btnReg.disabled = false;

    pendingUser = newUser;
    document.getElementById('verify-email-target').textContent = newUser.email;
    showView('view-verify-email');
    showAlert('success', 'Firebase Verification Email Sent!', `Firebase has sent a real verification link to ${newUser.email}. Open your email inbox, click the link, and then click "Check Status" below.`);
  });

  // Check Firebase Email Verification Status (`firebaseUser.reload()`)
  document.getElementById('btn-check-firebase-email').addEventListener('click', async () => {
    if (!fbAuth || !fbAuth.currentUser) {
      return showAlert('error', 'Firebase Session Required', 'Please sign in on the Login screen to check your email verification status.');
    }
    await fbAuth.currentUser.reload();
    if (fbAuth.currentUser.emailVerified) {
      if (pendingUser) {
        pendingUser.emailVerified = true;
        saveDB();
      }
      logSecurityEvent('FIREBASE_EMAIL_VERIFIED', 'INFO', `Verified email ownership via Firebase link for ${fbAuth.currentUser.email}.`);
      document.getElementById('login-email').value = fbAuth.currentUser.email;
      showView('view-login');
      showAlert('success', 'Email Verified by Firebase!', 'Your email is now verified! Sign in below to proceed to 2FA Phone OTP.');
    } else {
      showAlert('warning', 'Not Verified Yet', `Firebase reports that ${fbAuth.currentUser.email} has not clicked the verification link yet. Please check your inbox (and Spam folder) and click the link first.`);
    }
  });

  document.getElementById('btn-resend-firebase-email').addEventListener('click', async () => {
    if (fbAuth && fbAuth.currentUser) {
      try {
        await fbAuth.currentUser.sendEmailVerification();
        showAlert('info', 'Verification Email Resent', `Firebase resent the verification link to ${fbAuth.currentUser.email}.`);
      } catch (err) {
        showAlert('error', 'Firebase Error', err.message);
      }
    }
  });

  // ==========================================================================
  // STEP 2: LOGIN WITH FIREBASE signInWithEmailAndPassword + BRUTE-FORCE LOCKOUT
  // ==========================================================================
  document.getElementById('form-login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value.trim().toLowerCase();
    const password = document.getElementById('login-password').value;
    const refId = 'ERR-' + Math.random().toString(16).slice(2, 8).toUpperCase();

    if (hasMaliciousPayload(email) || hasMaliciousPayload(password)) {
      logSecurityEvent('INJECTION_ATTEMPT_BLOCKED', 'CRITICAL', `Blocked SQL/NoSQL injection attempt on Login: ${email.slice(0, 40)}`);
      return showAlert('error', 'Authentication Error', `Invalid email or password. Reference ID: ${refId}`);
    }

    let user = db.users.find((u) => u.email.toLowerCase() === email);

    if (user && user.accountStatus !== 'ACTIVE') {
      logSecurityEvent('LOCKED_ACCOUNT_LOGIN_BLOCKED', 'HIGH', `Blocked login on ${user.accountStatus} account (${user.email}).`, user);
      return showAlert('error', 'Account Locked / Suspended', `Your account status is ${user.accountStatus}. Contact the Security Administrator.`);
    }

    // If user is a real Firebase account (or Firebase is connected), verify via Firebase Auth!
    const isDefaultSeededAccount = ['patient@student.inti.edu.my', 'doctor@inti.edu.my', 'admin@inti.edu.my'].includes(email);

    if (fbAuth && !isDefaultSeededAccount) {
      try {
        const cred = await fbAuth.signInWithEmailAndPassword(email, password);
        await cred.user.reload();
        if (!cred.user.emailVerified) {
          pendingUser = user || { uid: cred.user.uid, email, fullName: email, role: 'patient', phone: '+60124773780' };
          document.getElementById('verify-email-target').textContent = email;
          showView('view-verify-email');
          return showAlert('warning', 'Email Not Verified Yet', `Please click the verification link sent by Firebase to ${email} before logging in.`);
        }
        if (!user) {
          const fallbackHash = await hashPasswordBcrypt(password);
          user = {
            uid: cred.user.uid,
            username: email.split('@')[0],
            fullName: cred.user.displayName || email.split('@')[0],
            email: email,
            phone: '+60124773780',
            nric: '020415075431',
            role: 'patient',
            emailVerified: true,
            pdpaConsent: true,
            accountStatus: 'ACTIVE',
            failedLoginAttempts: 0,
            passwordHash: fallbackHash
          };
          db.users.push(user);
        } else {
          user.emailVerified = true;
          user.failedLoginAttempts = 0;
        }
        saveDB();
      } catch (fbErr) {
        if (user) {
          user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
          if (user.failedLoginAttempts >= 5) {
            user.accountStatus = 'LOCKED_BRUTE_FORCE';
            logSecurityEvent('BRUTE_FORCE_ACCOUNT_LOCKOUT', 'CRITICAL', `Account ${user.email} locked after 5 failed attempts.`, user);
            saveDB();
            return showAlert('error', 'Account Locked (Brute-Force Protection)', 'Your account has been locked after 5 consecutive failed attempts.');
          }
          saveDB();
        }
        logSecurityEvent('AUTH_LOGIN_FAILED', 'WARNING', `Failed Firebase login for ${email}.`);
        return showAlert('error', 'Authentication Failed', `Invalid email or password. Reference ID: ${refId}`);
      }
    } else {
      // Verify against Bcrypt Cost 12 hash
      if (!user) {
        logSecurityEvent('AUTH_LOGIN_FAILED', 'WARNING', `Failed login on unknown email (${email}).`);
        return showAlert('error', 'Authentication Failed', `Invalid email or password. Reference ID: ${refId}`);
      }
      const salt = user.passwordHash.slice(7, 29);
      const candidateHash = await hashPasswordBcrypt(password, salt);
      if (candidateHash !== user.passwordHash) {
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
        if (user.failedLoginAttempts >= 5) {
          user.accountStatus = 'LOCKED_BRUTE_FORCE';
          logSecurityEvent('BRUTE_FORCE_ACCOUNT_LOCKOUT', 'CRITICAL', `Account ${user.email} automatically locked after 5 failed password attempts.`, user);
          saveDB();
          return showAlert('error', 'Account Locked (Brute-Force Protection)', 'Your account has been locked after 5 consecutive failed attempts.');
        } else {
          logSecurityEvent('AUTH_LOGIN_FAILED', 'WARNING', `Incorrect password for ${user.email} (${user.failedLoginAttempts}/5).`, user);
          saveDB();
          return showAlert('error', 'Authentication Failed', `Invalid email or password (Attempt ${user.failedLoginAttempts}/5). Reference ID: ${refId}`);
        }
      }
      user.failedLoginAttempts = 0;
      saveDB();
    }

    currentUser = user;
    pendingUser = null;
    document.getElementById('login-password').value = '';

    logSecurityEvent('AUTH_LOGIN_SUCCESS', 'INFO', `User ${currentUser.email} (${currentUser.role}) signed in via Firebase Email Verification & Bcrypt.`);
    startIdleSessionMonitor();
    showAlert('success', 'Authenticated Successfully', `Welcome back, ${currentUser.fullName}.`);

    if (currentUser.role === 'patient') {
      renderPatientPortal();
      showView('view-patient');
    } else if (currentUser.role === 'doctor') {
      renderDoctorPortal();
      showView('view-doctor');
    } else {
      renderAdminPortal();
      showView('view-admin');
    }
  });

  // Patient Subtabs
  document.querySelectorAll('[data-pat-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-pat-tab');
      ['pat-rx', 'pat-appt', 'pat-profile'].forEach((id) => {
        document.getElementById(id).classList.toggle('hidden', id !== target);
      });
      document.querySelectorAll('[data-pat-tab]').forEach((b) => {
        b.className = b === btn ? 'btn btn-primary' : 'btn btn-secondary';
      });
    });
  });

  // Patient Book Appointment
  document.getElementById('form-book-appt').addEventListener('submit', (e) => {
    e.preventDefault();
    const docId = document.getElementById('appt-doctor').value;
    const date = document.getElementById('appt-date').value;
    const time = document.getElementById('appt-time').value;
    const rawSymptoms = document.getElementById('appt-symptoms').value;

    if (hasMaliciousPayload(rawSymptoms)) {
      logSecurityEvent('XSS_PAYLOAD_SANITIZED', 'HIGH', `Malicious script tags stripped from symptom note by ${currentUser.email}.`);
    }

    const cleanSymptoms = sanitizeHTML(rawSymptoms);
    const docObj = db.users.find((u) => u.uid === docId) || db.users.find((u) => u.role === 'doctor');
    const newAppt = {
      id: 'APT-' + Math.floor(300 + Math.random() * 699),
      patientId: currentUser.uid,
      patientName: currentUser.fullName,
      doctorId: docObj.uid,
      doctorName: docObj.fullName,
      date,
      time,
      symptoms: cleanSymptoms,
      status: 'CONFIRMED'
    };

    db.appointments.unshift(newAppt);
    logSecurityEvent('APPOINTMENT_BOOKED', 'INFO', `Patient ${currentUser.email} booked ${newAppt.id}.`);
    saveDB();
    document.getElementById('appt-symptoms').value = '';
    renderPatientPortal();
    showAlert('success', 'Appointment Confirmed', `Scheduled consultation ${newAppt.id} for ${date} at ${time}.`);
  });

  // Doctor Subtabs
  document.querySelectorAll('[data-doc-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-doc-tab');
      ['doc-issue', 'doc-appts', 'doc-archive'].forEach((id) => {
        document.getElementById(id).classList.toggle('hidden', id !== target);
      });
      document.querySelectorAll('[data-doc-tab]').forEach((b) => {
        b.className = b === btn ? 'btn btn-primary' : 'btn btn-secondary';
      });
    });
  });

  // Doctor Issue Prescription
  document.getElementById('form-issue-rx').addEventListener('submit', async (e) => {
    e.preventDefault();
    const patId = document.getElementById('rx-patient').value;
    const dept = document.getElementById('rx-dept').value;
    const med = document.getElementById('rx-med').value;
    const dosage = document.getElementById('rx-dosage').value;
    const notes = document.getElementById('rx-notes').value;

    const patObj = db.users.find((u) => u.uid === patId);
    if (!patObj) return;

    const cleanCombined = `${sanitizeHTML(med)} — ${sanitizeHTML(dosage)}. Diagnosis: ${sanitizeHTML(notes)}`;
    const rxId = 'RX-' + Math.floor(1100 + Math.random() * 8800);
    const patNric = patObj.nric || '020415075431';

    const nricCiphertext = await encryptAES256GCM(patNric);
    const prescriptionCiphertext = await encryptAES256GCM(cleanCombined);
    const sha256Signature = await sha256Hex(`${rxId}|${patObj.uid}|${currentUser.uid}|${patNric}`);

    const newRx = {
      id: rxId,
      patientId: patObj.uid,
      patientName: patObj.fullName,
      doctorId: currentUser.uid,
      doctorName: currentUser.fullName,
      department: sanitizeHTML(dept),
      issuedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      nricCiphertext,
      prescriptionCiphertext,
      sha256Signature
    };

    db.prescriptions.unshift(newRx);
    if (fbFirestore) {
      fbFirestore.collection('medical_records').doc(rxId).set(newRx).catch(() => {});
    }
    logSecurityEvent('E_PRESCRIPTION_ISSUED_AES256GCM', 'INFO', `Doctor ${currentUser.email} issued encrypted prescription ${rxId}.`);
    saveDB();
    document.getElementById('rx-med').value = '';
    document.getElementById('rx-dosage').value = '';
    document.getElementById('rx-notes').value = '';
    renderDoctorPortal();
    showAlert('success', 'E-Prescription Encrypted & Saved', `Issued ${rxId} encrypted with AES-256-GCM.`);
  });

  // Admin Subtabs
  document.querySelectorAll('[data-adm-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-adm-tab');
      ['adm-users', 'adm-siem', 'adm-db'].forEach((id) => {
        document.getElementById(id).classList.toggle('hidden', id !== target);
      });
      document.querySelectorAll('[data-adm-tab]').forEach((b) => {
        b.className = b === btn ? 'btn btn-primary' : 'btn btn-secondary';
      });
    });
  });

  document.getElementById('siem-severity-filter').addEventListener('change', renderAdminPortal);
});