// ============================================================================
// MediVault — Official Firebase Authentication + Firestore + AES-256-GCM Engine
// Original HTML/CSS/JavaScript application; Firebase is the authority for real accounts.
// ============================================================================

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

let currentUser = null;
let loadVersion = 0;
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
    fbFirestore = firebase.firestore();

    banner.className = 'gateway-banner';
    title.textContent = `Firebase project configured (${cfg.projectId || cfg.authDomain}):`;
    desc.textContent = 'Use your registered Firebase email. Account access and database permissions are checked when you sign in.';
    return true;
  } catch (err) {
    title.textContent = 'Firebase unavailable';
    desc.textContent = 'Check the Firebase web configuration and internet connection.';
    return false;
  }
}

// ============================================================================
// 2. CRYPTOGRAPHIC FUNCTIONS (AES-256-GCM authenticated encryption)
// ============================================================================
function newKey() {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
}
async function importAesKey(encoded) {
  return crypto.subtle.importKey('raw', Uint8Array.from(atob(encoded), c => c.charCodeAt(0)), 'AES-GCM', false, ['encrypt','decrypt']);
}
async function encryptAES256GCM(plaintext, encodedKey, context) {
  const key = await importAesKey(encodedKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:new TextEncoder().encode(context)}, key, new TextEncoder().encode(plaintext));
  const bytes = new Uint8Array(12 + cipher.byteLength);
  bytes.set(iv); bytes.set(new Uint8Array(cipher),12);
  return btoa(String.fromCharCode(...bytes));
}
async function decryptAES256GCM(ciphertext, encodedKey, context) {
  const bytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
  if (bytes.length < 28) throw Error('INTEGRITY');
  const key = await importAesKey(encodedKey);
  const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv:bytes.slice(0,12), additionalData:new TextEncoder().encode(context)}, key, bytes.slice(12));
  return new TextDecoder().decode(plain);
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

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
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
// Separate clinic collections leave earlier coursework documents untouched.
const clinicCollection = name => fbFirestore.collection('medivault_'+name);
const serverRead = {source:'server'};
const stamp = () => firebase.firestore.FieldValue.serverTimestamp();
const keyRef = ref => ref.collection('private').doc('key');
const rows = snapshot => snapshot.docs.map(doc => ({...doc.data(), id:doc.id, uid:doc.id}));
const emptyDB = () => ({users:[], appointments:[], prescriptions:[], auditLogs:[]});
function requireRole(role) {
  if (!currentUser || currentUser.role !== role) throw Error('ACCESS');
}
function requireSecureContext() {
  if (!window.isSecureContext || !crypto.subtle) throw Error('HTTPS');
}
function auditEntry(eventType, target) {
  return {actorId:fbAuth.currentUser.uid, eventType, target, timestamp:stamp()};
}
function addAudit(batch, eventType, target) {
  const ref = clinicCollection('security_audit_logs').doc();
  batch.set(ref, auditEntry(eventType,target));
}
async function logSecurityEvent(eventType, target = '') {
  if (currentUser) await clinicCollection('security_audit_logs').add(auditEntry(eventType,target));
}
async function encryptedFields(ref, fields) {
  const key = newKey(), result = {};
  for (const [name, value] of Object.entries(fields)) result[name] = await encryptAES256GCM(value,key,ref.path+'/'+name);
  return {key, fields:result};
}
async function readEncrypted(ref, name, ciphertext) {
  const secret = await keyRef(ref).get(serverRead);
  return decryptAES256GCM(ciphertext,secret.data().key,ref.path+'/'+name);
}
async function saveProfile(user, fullName, username, phone, nric) {
  const ref = clinicCollection('users').doc(user.uid);
  const existing = await ref.get(serverRead);
  if (existing.exists) throw Error('EXISTS');
  const privateProfile = ref.collection('private').doc('profile');
  const batch = fbFirestore.batch();
  batch.set(ref,{fullName,email:user.email,role:'patient',accountStatus:'ACTIVE',consentAt:stamp()});
  batch.set(privateProfile,{username,phone,nric});
  await batch.commit();
}
async function loadClinic() {
  const revision = ++loadVersion;
  const user = fbAuth.currentUser;
  if (!user?.emailVerified) throw Error('VERIFY');
  const ownRef = clinicCollection('users').doc(user.uid);
  const own = await ownRef.get(serverRead);
  if (!own.exists) throw Error('PROFILE');
  const account = {...own.data(),uid:user.uid};
  if (account.accountStatus !== 'ACTIVE' || !['patient','doctor','admin'].includes(account.role)) throw Error('ACCESS');
  const next = emptyDB();
  if (account.role === 'admin') {
    const [users,logs,records] = await Promise.all([
      clinicCollection('users').get(serverRead),
      clinicCollection('security_audit_logs').orderBy('timestamp','desc').limit(100).get(serverRead),
      clinicCollection('medical_records').orderBy('issuedAt','desc').limit(50).get(serverRead)
    ]);
    next.users = rows(users);
    next.prescriptions = rows(records);
    next.auditLogs = rows(logs).map(log => ({...log,actorEmail:log.actorId,details:log.target,
      severity:log.eventType === 'ACCOUNT_UPDATED' ? 'WARNING' : log.eventType === 'CRYPTO_FAILURE' ? 'HIGH' : 'INFO',
      timestamp:log.timestamp?.toDate().toLocaleString() || ''}));
  } else {
    const field = account.role === 'patient' ? 'patientId' : 'doctorId';
    const [appointments,records] = await Promise.all([
      clinicCollection('appointments').where(field,'==',user.uid).get(serverRead),
      clinicCollection('medical_records').where(field,'==',user.uid).get(serverRead)
    ]);
    next.appointments = rows(appointments);
    next.prescriptions = rows(records).map(rx => ({...rx,issuedAt:rx.issuedAt.toDate().toLocaleString()}));
    for (const appointment of next.appointments) {
      const ref = clinicCollection('appointments').doc(appointment.id);
      // Read earlier encrypted test documents without changing or copying them.
      if (appointment.detailsCiphertext) {
        const {symptoms,nric}=JSON.parse(await readEncrypted(ref,'detailsCiphertext',appointment.detailsCiphertext));
        Object.assign(appointment,{symptoms,nric});
      }
      const local = new Date(appointment.startsAt.toMillis()+8*3600000).toISOString();
      appointment.date=local.slice(0,10); appointment.time=local.slice(11,16);
    }
    if (account.role === 'patient') {
      next.users = rows(await clinicCollection('users').where('role','==','doctor').where('accountStatus','==','ACTIVE').get(serverRead));
      const profileRef = ownRef.collection('private').doc('profile');
      const profile = await profileRef.get(serverRead);
      const personal = profile.data();
      const {username,phone,nric}=personal.personalCiphertext ? JSON.parse(await readEncrypted(profileRef,'personalCiphertext',personal.personalCiphertext)) : personal;
      Object.assign(account,{username,phone,nric});
    } else {
      next.users = [...new Map(next.appointments.map(a => [a.patientId,{uid:a.patientId,fullName:a.patientName,role:'patient'}])).values()];
    }
  }
  if (revision !== loadVersion) return false;
  db = next; currentUser = account;
  return true;
}
function renderPortal() {
  if (currentUser.role === 'patient') renderPatientPortal();
  if (currentUser.role === 'doctor') renderDoctorPortal();
  if (currentUser.role === 'admin') renderAdminPortal();
  showView('view-'+currentUser.role);
}
async function refreshClinic() {
  if (await loadClinic()) renderPortal();
}
async function endSession() {
  const wasLoggedIn = !!currentUser;
  if (wasLoggedIn) logSecurityEvent('USER_LOGOUT').catch(() => {});
  ++loadVersion; currentUser=null; db=emptyDB(); decryptedCache={}; stopIdleSessionMonitor();
  ['patient-rx-list','patient-appt-list','patient-profile-details','doctor-appt-list','doctor-rx-list','admin-users-tbody','admin-siem-list','admin-db-dump','appt-doctor','rx-patient','admin-log-summary','nav-user-name','nav-user-email','nav-user-role'].forEach(id => document.getElementById(id).textContent='');
  document.querySelectorAll('form').forEach(form => form.reset());
  showView('view-login');
  if (fbAuth) await fbAuth.signOut();
  // A fresh page also releases Firestore's in-memory documents on shared computers.
  if (wasLoggedIn) window.location.reload();
}
function reportError(err) {
  const code=err?.code || err?.message;
  const messages={
    'INPUT':'Enter a value within the field length limit and leave out HTML tags.',
    'SETUP':'Check the Firebase configuration before continuing.',
    'HTTPS':'Open this application using localhost or HTTPS to protect account and medical data.',
    'EXISTS':'This account already has a clinic profile. Sign in using its existing password.',
    'PROFILE':'Your Firebase account has no clinic profile yet. Select Create Account and complete your details using the same email and password.',
    'VERIFY':'Open the verification link in your email before signing in.',
    'ACCESS':'This action is not permitted. Contact the clinic administrator.',
    'auth/email-already-in-use':'Account creation could not be completed. Try signing in or use Forgot password to recover your account.',
    'auth/invalid-credential':'Sign-in failed. Check your email and password, or use Forgot password.',
    'auth/wrong-password':'Sign-in failed. Check your email and password, or use Forgot password.',
    'auth/user-not-found':'Sign-in failed. Check your email and password, or use Forgot password.',
    'auth/too-many-requests':'Too many requests. Wait before trying again.',
    'auth/operation-not-allowed':'Email/password sign-in is unavailable. Ask the project owner to check Firebase Authentication.',
    'auth/invalid-email':'Enter a complete, valid email address.',
    'auth/network-request-failed':'The authentication service could not be reached. Check your internet connection.',
    'permission-denied':'Database access was denied. Ask the project owner to check your account and publish the supplied Firestore rules.',
    'unavailable':'The database could not be reached. Check your connection and Firebase setup.'
  };
  showAlert('error','Request could not be completed',Object.prototype.hasOwnProperty.call(messages,code) ? messages[code] : 'Please try again. If the problem continues, contact the project administrator.');
}
function handle(id,event,action) {
  document.getElementById(id).addEventListener(event,async e => {
    e.preventDefault();
    const button=e.submitter || (e.currentTarget.tagName==='BUTTON' ? e.currentTarget : null);
    if (button) button.disabled=true;
    try { await action(e); } catch (err) { reportError(err); }
    finally { if (button) button.disabled=false; }
  });
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
      endSession().catch(reportError);
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
  requireRole('patient');
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
            <button class="btn btn-primary" style="padding: 6px 12px; font-size: 12px;" data-decrypt="${escapeHTML(rx.id)}">
              Decrypt AES-256-GCM Record
            </button>
          </div>
          ${
            !dec
              ? `<div class="ciphertext-box mono">Encrypted Payload (AES-256-GCM): ${escapeHTML(rx.prescriptionCiphertext)}</div>`
              : `<div class="decrypted-box">
                   <div style="color: #6ee7b7; font-weight: 700; margin-bottom: 4px;">✓ Decrypted Medical Record (128-bit GCM Authentication Tag Verified)</div>
                   <div><strong>Verified IC / NRIC:</strong> ${escapeHTML(dec.nricPlain)}</div>
                   <div><strong>Prescription &amp; Diagnosis:</strong> ${escapeHTML(dec.rxPlain)}</div>
                 </div>`
          }
        </div>
      `;
    }).join('');
  }

  const docSelect = document.getElementById('appt-doctor');
  const doctors = db.users.filter((u) => u.role === 'doctor' && u.accountStatus === 'ACTIVE');
  docSelect.innerHTML = doctors.map((d) => `<option value="${escapeHTML(d.uid)}">${escapeHTML(d.fullName)}</option>`).join('');

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
    <div><strong>Password protection:</strong> Managed by Firebase Authentication; passwords are not stored in this application.</div>
  `;
}

function renderDoctorPortal() {
  requireRole('doctor');
  const patSelect = document.getElementById('rx-patient');
  patSelect.innerHTML = db.users.map(p => `<option value="${escapeHTML(p.uid)}">${escapeHTML(p.fullName)}</option>`).join('');

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
          <button class="btn btn-primary" style="padding: 5px 11px; font-size: 11.5px;" data-decrypt="${escapeHTML(rx.id)}">Decrypt Record</button>
        </div>
        <div class="ciphertext-box mono">Ciphertext: ${escapeHTML(rx.prescriptionCiphertext)}</div>
        ${dec ? `<div class="decrypted-box"><strong>Decrypted:</strong> ${escapeHTML(dec.rxPlain)} (IC: ${escapeHTML(dec.nricPlain)})</div>` : ''}
      </div>
    `;
  }).join('');
}

function renderAdminPortal() {
  requireRole('admin');
  const tbody = document.getElementById('admin-users-tbody');
  tbody.innerHTML = db.users.map((u) => `
    <tr>
      <td>
        <div style="font-weight: 700;">${escapeHTML(u.fullName)}</div>
        <div class="mono" style="font-size: 11px; color: var(--text-secondary);">${escapeHTML(u.uid)}</div>
      </td>
      <td>
        <div>${escapeHTML(u.email)}</div>
        <div style="font-size: 11.5px; color: var(--text-secondary);">Clinic role and account access</div>
      </td>
      <td>
        <select class="form-select" style="width: auto; padding: 5px 8px; font-size: 12px;" data-role-user="${escapeHTML(u.uid)}">
          <option value="patient" ${u.role === 'patient' ? 'selected' : ''}>PATIENT</option>
          <option value="doctor" ${u.role === 'doctor' ? 'selected' : ''}>DOCTOR</option>
          <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>ADMIN</option>
        </select>
      </td>
      <td>
        <span class="badge ${u.accountStatus === 'ACTIVE' ? 'badge-green' : 'badge-red'}">${escapeHTML(u.accountStatus)}</span>

      </td>
      <td>
        ${
          u.accountStatus === 'ACTIVE'
            ? `<button class="btn btn-danger" style="padding: 5px 10px; font-size: 11.5px;" data-status-user="${escapeHTML(u.uid)}" data-status="DEACTIVATED">Deactivate</button>`
            : `<button class="btn btn-primary" style="padding: 5px 10px; font-size: 11.5px;" data-status-user="${escapeHTML(u.uid)}" data-status="ACTIVE">Activate</button>`
        }
      </td>
    </tr>
  `).join('');

  document.getElementById('admin-log-summary').textContent = `Recent ${db.auditLogs.length} events • Sign-ins: ${db.auditLogs.filter(l => l.eventType === 'AUTH_LOGIN_SUCCESS').length} • Appointments: ${db.auditLogs.filter(l => l.eventType === 'APPOINTMENT_BOOKED').length} • Prescriptions: ${db.auditLogs.filter(l => l.eventType === 'E_PRESCRIPTION_ISSUED').length} • Account changes: ${db.auditLogs.filter(l => l.eventType === 'ACCOUNT_UPDATED').length}`;
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

async function decryptRecord(rxId) {
  if (!currentUser || !['patient','doctor'].includes(currentUser.role)) throw Error('ACCESS');
  const revision=loadVersion;
  const rx=db.prescriptions.find(r => r.id===rxId);
  if (!rx || (rx.patientId!==currentUser.uid && rx.doctorId!==currentUser.uid)) throw Error('ACCESS');
  try {
    const ref=clinicCollection('medical_records').doc(rxId);
    const secret=(await keyRef(ref).get(serverRead)).data().key;
    const nricPlain=await decryptAES256GCM(rx.nricCiphertext,secret,ref.path+'/nricCiphertext');
    const rxPlain=await decryptAES256GCM(rx.prescriptionCiphertext,secret,ref.path+'/prescriptionCiphertext');
    await logSecurityEvent('PHI_RECORD_DECRYPTED',rxId);
    if (revision!==loadVersion || !currentUser) return;
    decryptedCache[rxId]={nricPlain,rxPlain};
    renderPortal();
  } catch (err) {
    if (err.name==='OperationError' || err.message==='INTEGRITY') {
      logSecurityEvent('CRYPTO_FAILURE',rxId).catch(() => {});
      return showAlert('error','Record could not be verified','The encrypted record failed its integrity check. Contact the clinic administrator.');
    }
    throw err;
  }
}
async function updateAccount(uid, changes) {
  requireRole('admin');
  if (uid===currentUser.uid) return showAlert('warning','Keep administrator access','Ask another administrator to change your role or status.');
  const ref=clinicCollection('users').doc(uid), batch=fbFirestore.batch();
  addAudit(batch,'ACCOUNT_UPDATED',uid);
  batch.update(ref,changes);
  await batch.commit();
  await refreshClinic();
  showAlert('success','Account updated','The role and account status are enforced by the database.');
}
function checkedText(id,max) {
  const value=document.getElementById(id).value.trim();
  if (!value || value.length>max || /[<>]/.test(value)) throw Error('INPUT');
  return value;
}
function verificationView(user) {
  document.getElementById('verify-email-target').textContent=user.email;
  showView('view-verify-email');
}

// Original navigation, forms and dashboards; all account and clinical operations use Firebase.
window.addEventListener('DOMContentLoaded', async () => {
  initFirebaseFromStorage();
  if (fbAuth) await fbAuth.setPersistence(firebase.auth.Auth.Persistence.SESSION).catch(reportError);
  document.getElementById('appt-date').min=new Date().toLocaleDateString('en-CA',{timeZone:'Asia/Kuala_Lumpur'});
  document.getElementById('appt-date').value=document.getElementById('appt-date').min;
  const openFbModal=() => {
    document.getElementById('fb-config-textarea').value=localStorage.getItem('MEDIVAULT_FIREBASE_CONFIG') || '';
    document.getElementById('firebase-cfg-modal').classList.remove('hidden');
  };
  document.getElementById('btn-open-firebase-cfg').addEventListener('click',openFbModal);
  document.getElementById('btn-banner-fb-setup').addEventListener('click',openFbModal);
  document.getElementById('btn-close-fb-cfg').addEventListener('click',() => document.getElementById('firebase-cfg-modal').classList.add('hidden'));
  handle('btn-save-fb-cfg','click',async () => {
    const parsed=parseFirebaseConfigInput(document.getElementById('fb-config-textarea').value);
    if (!parsed?.apiKey || !parsed.authDomain || !parsed.projectId) return showAlert('warning','Invalid configuration','Paste the complete Firebase web configuration.');
    if (fbAuth) await fbAuth.signOut();
    localStorage.setItem('MEDIVAULT_FIREBASE_CONFIG',JSON.stringify(parsed));
    window.location.reload();
  });
  handle('btn-clear-fb-cfg','click',async () => {
    if (fbAuth) await fbAuth.signOut();
    localStorage.removeItem('MEDIVAULT_FIREBASE_CONFIG'); window.location.reload();
  });
  document.getElementById('btn-go-login').addEventListener('click',() => {hideAlert(); showView('view-login');});
  document.getElementById('btn-go-register').addEventListener('click',() => {hideAlert(); showView('view-register');});
  document.getElementById('alert-close').addEventListener('click',hideAlert);
  handle('btn-logout','click',endSession);
  handle('btn-refresh-clinic','click',refreshClinic);
  document.getElementById('reg-password').addEventListener('input',e => {
    const res=evaluatePassword(e.target.value);
    document.getElementById('entropy-score-text').textContent=`${res.score}%`;
    document.getElementById('entropy-bar').style.width=`${res.score}%`;
    document.getElementById('entropy-bar').style.backgroundColor=res.isStrong ? 'var(--accent-green)' : 'var(--accent-amber)';
    document.getElementById('entropy-feedback').textContent=res.isStrong ? 'All four password requirements met.' : `Missing: ${res.missing.join(' • ')}`;
  });
  document.getElementById('link-open-pdpa').addEventListener('click',e => {e.preventDefault();document.getElementById('pdpa-modal').classList.remove('hidden');});
  document.getElementById('btn-close-pdpa').addEventListener('click',() => document.getElementById('pdpa-modal').classList.add('hidden'));
  document.getElementById('btn-accept-pdpa').addEventListener('click',() => {document.getElementById('reg-pdpa').checked=true;document.getElementById('pdpa-modal').classList.add('hidden');});

  handle('form-register','submit',async () => {
    requireSecureContext();
    if (!fbAuth || !fbFirestore) throw Error('SETUP');
    const fullName=checkedText('reg-fullname',80), username=checkedText('reg-username',40);
    const email=document.getElementById('reg-email').value.trim().toLowerCase();
    const phone=validateAndNormalizePhone(document.getElementById('reg-phone').value);
    const nric=validateAndNormalizeNric(document.getElementById('reg-nric').value);
    const password=document.getElementById('reg-password').value;
    if (!phone.valid || !nric.valid) return showAlert('warning','Invalid details','Enter a valid Malaysian mobile number and 12-digit NRIC.');
    if (!evaluatePassword(password).isStrong || password!==document.getElementById('reg-confirm').value) return showAlert('warning','Check password','Meet all four requirements and enter the same password twice.');
    if (!document.getElementById('reg-pdpa').checked) return showAlert('warning','Consent required','Read and accept the privacy notice.');
    // An unfinished account resumes only after a successful sign-in, never silently after a duplicate-email error.
    const result=fbAuth.currentUser?.email===email
      ? await fbAuth.signInWithEmailAndPassword(email,password)
      : await fbAuth.createUserWithEmailAndPassword(email,password);
    await saveProfile(result.user,fullName,username,phone.normalized,nric.normalized);
    document.getElementById('form-register').reset();
    document.getElementById('login-email').value=email;
    if (result.user.emailVerified) {
      await fbAuth.signOut(); showView('view-login');
      return showAlert('success','Registration completed','Sign in using your verified email and password.');
    }
    verificationView(result.user);
    await result.user.sendEmailVerification();
    showAlert('success','Verification email sent','Open the link in your inbox, then select Check Status. Check Spam/Junk if necessary.');
  });
  handle('btn-check-firebase-email','click',async () => {
    const user=fbAuth?.currentUser;
    if (!user) return showAlert('info','Sign in again','Enter your email and password to resume verification.');
    await user.reload();
    if (!user.emailVerified) return showAlert('warning','Not verified yet','Open the newest verification email link and check again.');
    await user.getIdToken(true);
    document.getElementById('login-email').value=user.email;
    await fbAuth.signOut(); showView('view-login');
    showAlert('success','Email verified','Sign in with your email and password.');
  });
  handle('btn-resend-firebase-email','click',async () => {
    if (!fbAuth?.currentUser) return showAlert('info','Sign in again','Enter your email and password to resume verification.');
    await fbAuth.currentUser.sendEmailVerification();
    showAlert('info','Verification email requested','Check your inbox and spam folder.');
  });
  handle('btn-forgot-password','click',async () => {
    requireSecureContext();
    const email=document.getElementById('login-email').value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return showAlert('warning','Enter your email','Fill in your registered email address above first.');
    try { await fbAuth.sendPasswordResetEmail(email); }
    catch (err) { if (err.code!=='auth/user-not-found') throw err; }
    showAlert('info','Password reset requested','If this address has an eligible account, a reset email will arrive. Check your inbox and spam folder.');
  });
  handle('form-login','submit',async () => {
    requireSecureContext();
    if (!fbAuth || !fbFirestore) throw Error('SETUP');
    const email=document.getElementById('login-email').value.trim().toLowerCase();
    const password=document.getElementById('login-password').value;
    await fbAuth.signOut();
    const {user}=await fbAuth.signInWithEmailAndPassword(email,password);
    document.getElementById('login-password').value='';
    const profile=await clinicCollection('users').doc(user.uid).get(serverRead);
    if (!profile.exists) {
      document.getElementById('reg-email').value=email; showView('view-register');
      return showAlert('info','Complete your registration','Your sign-in succeeded. Fill in your clinic details and enter the same password to finish creating your profile.');
    }
    if (!user.emailVerified) {verificationView(user);return showAlert('warning','Verify your email','Open the email verification link, or request another email below.');}
    await user.getIdToken(true);
    if (await loadClinic()) {
      await logSecurityEvent('AUTH_LOGIN_SUCCESS');
      startIdleSessionMonitor(); renderPortal();
      showAlert('success','Signed in',`Welcome, ${currentUser.fullName}.`);
    }
  });
  handle('form-book-appt','submit',async () => {
    requireRole('patient');
    const doctorId=document.getElementById('appt-doctor').value;
    const doctor=db.users.find(u => u.uid===doctorId && u.role==='doctor' && u.accountStatus==='ACTIVE');
    if (!doctor) return showAlert('warning','No doctor selected','An administrator must assign an active doctor before booking.');
    const date=document.getElementById('appt-date').value, time=document.getElementById('appt-time').value;
    const dateTime=new Date(`${date}T${time}:00+08:00`);
    if (!Number.isFinite(dateTime.getTime()) || dateTime<=new Date()) return showAlert('warning','Invalid appointment time','Choose a future date and time (Malaysia time).');
    const symptoms=checkedText('appt-symptoms',2000);
    const ref=clinicCollection('appointments').doc();
    const batch=fbFirestore.batch();
    addAudit(batch,'APPOINTMENT_BOOKED',ref.id);
    batch.set(ref,{patientId:currentUser.uid,patientName:currentUser.fullName,doctorId,doctorName:doctor.fullName,
      startsAt:firebase.firestore.Timestamp.fromDate(dateTime),status:'CONFIRMED',symptoms,nric:currentUser.nric});
    await batch.commit();
    document.getElementById('appt-symptoms').value=''; await refreshClinic();
    showAlert('success','Appointment confirmed',`Consultation booked for ${date} at ${time} (Malaysia time).`);
  });
  handle('form-issue-rx','submit',async () => {
    requireRole('doctor');
    const appointment=db.appointments.find(a => a.patientId===document.getElementById('rx-patient').value && a.doctorId===currentUser.uid);
    if (!appointment) return showAlert('warning','No patient selected','Select a patient with an appointment assigned to you.');
    const department=checkedText('rx-dept',80), med=checkedText('rx-med',200), dosage=checkedText('rx-dosage',500), notes=checkedText('rx-notes',2000);
    const ref=clinicCollection('medical_records').doc();
    const encrypted=await encryptedFields(ref,{nricCiphertext:appointment.nric,prescriptionCiphertext:`${med} — ${dosage}. Diagnosis: ${notes}`});
    const batch=fbFirestore.batch();
    addAudit(batch,'E_PRESCRIPTION_ISSUED',ref.id);
    batch.set(ref,{appointmentId:appointment.id,patientId:appointment.patientId,patientName:appointment.patientName,
      doctorId:currentUser.uid,doctorName:currentUser.fullName,department,issuedAt:stamp(),...encrypted.fields});
    batch.set(keyRef(ref),{key:encrypted.key}); await batch.commit();
    ['rx-med','rx-dosage','rx-notes'].forEach(id => document.getElementById(id).value='');
    await refreshClinic();showAlert('success','Prescription issued','The encrypted prescription is available to the patient and prescribing doctor.');
  });
  for (const [attribute,panels] of [['data-pat-tab',['pat-rx','pat-appt','pat-profile']],['data-doc-tab',['doc-issue','doc-appts','doc-archive']],['data-adm-tab',['adm-users','adm-siem','adm-db']]]) {
    document.querySelectorAll(`[${attribute}]`).forEach(button => button.addEventListener('click',() => {
      panels.forEach(id => document.getElementById(id).classList.toggle('hidden',id!==button.getAttribute(attribute)));
      document.querySelectorAll(`[${attribute}]`).forEach(b => b.className=b===button ? 'btn btn-primary' : 'btn btn-secondary');
    }));
  }
  document.addEventListener('click',async e => {
    const button=e.target.closest('[data-decrypt],[data-status-user]');
    if (!button) return;
    button.disabled=true;
    try {
      if (button.dataset.decrypt) await decryptRecord(button.dataset.decrypt);
      else await updateAccount(button.dataset.statusUser,{accountStatus:button.dataset.status});
    } catch (err) {reportError(err);} finally {button.disabled=false;}
  });
  document.addEventListener('change',async e => {
    if (!e.target.dataset.roleUser) return;
    e.target.disabled=true;
    try {await updateAccount(e.target.dataset.roleUser,{role:e.target.value});}
    catch (err) {reportError(err);} finally {e.target.disabled=false;}
  });
  document.getElementById('siem-severity-filter').addEventListener('change',() => {requireRole('admin');renderAdminPortal();});
});

// Show password for Login, Sign Up and Confirm Password.
window.addEventListener('DOMContentLoaded', () => {
  ['login-password', 'reg-password', 'reg-confirm'].forEach(id => {
    const input = document.getElementById(id);
    if (!input) return;

    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    label.style.cssText = 'display:flex;align-items:center;gap:6px;margin-top:8px;font-size:12px;';
    label.append(checkbox, 'Show password');
    input.after(label);

    checkbox.addEventListener('change', () => {
      input.type = checkbox.checked ? 'text' : 'password';
    });

    input.form.addEventListener('reset', () => {
      input.type = 'password';
      checkbox.checked = false;
    });
  });
});