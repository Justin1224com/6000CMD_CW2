| Requirement | Security Feature Implemented | Technical Method / Function in `app.js` |
| :--- | :--- | :--- |
| **1. Level of Access** | • 3-Tier Role-Based Access Control (**RBAC**: `patient`, `doctor`, `admin`)<br>• Principle of Least Privilege (**PoLP**) data isolation<br>• **Bcrypt (Cost Factor 12)** salted password hashing (`$2a$12$...`)<br>• **Firebase Email Verification** (`sendEmailVerification()`) | `hashPasswordBcrypt()`, `createUserWithEmailAndPassword()`, `sendEmailVerification()`, `renderPatientPortal()`, `renderDoctorPortal()`, `renderAdminPortal()` |
| **2. Input Validation, Output Encoding & Error Handling** | • Dash-free Malaysian Phone (`+601...`) & 12-digit NRIC RegEx allowlisting<br>• HTML/Script tag stripping & XSS Output Encoding<br>• SQL/NoSQL Injection signature detection<br>• Anti-enumeration error handling with masked Reference IDs (`ERR-XXXXXX`) | `validateAndNormalizePhone()`, `validateAndNormalizeNric()`, `sanitizeHTML()`, `escapeHTML()`, `hasMaliciousPayload()` |
| **3. Secure Communication** | • Enforced **HTTPS / TLS 1.3** transport encryption to `cmd-cw2.firebaseapp.com`<br>• Host & Network Security Headers (`HSTS`, `CSP`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`)<br>• X.509 Digital Certificate Validation | `firebase.json`, `<meta http-equiv="X-Content-Type-Options" content="nosniff">` |
| **4. Data Protection & User Education** | • Authenticated **AES-256-GCM** encryption at rest (96-bit random IV + 128-bit GCM Auth Tag) for NRIC & E-Prescriptions<br>• **Malaysia PDPA 2010** Privacy Policy dialog & mandatory consent checkbox<br>• Real-time **Password Complexity & Entropy Meter** (0%–100%) | `encryptAES256GCM()`, `decryptAES256GCM()`, `evaluatePassword()` |
| **5. Logging, Analytics & Advanced Security** | • Append-only **SIEM Security Audit Trail** (`security_audit_logs`)<br>• **Automated Brute-Force Account Lockout** after 5 failed login attempts (`LOCKED_BRUTE_FORCE`)<br>• **3-Minute Idle Session Timeout** (`Auto-Logout: 3:00`)<br>• **SHA-256 Digital Signature** verification on E-Prescriptions | `logSecurityEvent()`, `startIdleSessionMonitor()`, `sha256Hex()` |
| **6. Security & Vulnerability Testing** | • Assessed against **OWASP Top 10** using automated DAST/SAST scanners and manual penetration testing | Verified against Broken Access Control (A01), Cryptographic Failures (A02), Injection/XSS (A03), and Auth Failures (A07) |



## 🚀 How to Run the Application Locally

Because **MediVault** is engineered using pure HTML5, CSS3, Vanilla JavaScript, and the official Google Firebase Web SDK via CDN, **no `npm install` or `node_modules` folder is required**.

### Option 1: Using VS Code Live Server (Recommended for Firebase Auth)
1. Clone or download this repository:
   ```bash
   git clone https://github.com/your-username/medivault-security-cw2.git
   ```
2. Open the project folder in **Visual Studio Code**.
3. Right-click **`index.html`** and select **"Open with Live Server"** (opens at `http://127.0.0.1:5500` or `http://localhost:5500`).

### Option 2: Using Python / Node Local HTTP Server
```bash
# Python 3
python -m http.server 5500
```
Then open **`http://localhost:5500`** in Chrome or Edge.

---

## 🔑 Pre-Seeded Test Accounts (RBAC Demonstration)

You can register your own institutional email (`@student.newinti.edu.my` or `@gmail.com`) to test real **Firebase Email Verification**, or sign in immediately with the pre-seeded RBAC role accounts below:

| RBAC Role | Email Address | Password | Assigned Privileges (PoLP) |
| :--- | :--- | :--- | :--- |
| **Patient** | `patient@student.inti.edu.my` | `Patient@12345!` | Book appointments, decrypt own AES-256-GCM E-Prescriptions, view security profile. |
| **Doctor** | `doctor@inti.edu.my` | `Doctor@12345!` | View assigned patient consultations, issue AES-256-GCM encrypted & SHA-256 signed E-Prescriptions. |
| **Security Admin** | `admin@inti.edu.my` | `Admin@12345!` | Manage user roles, unlock brute-force locked accounts, deactivate users, audit SIEM security logs & raw encrypted database. |

---

## 🧪 Quick Security Verification Guide
1. **Test Firebase Email Verification:** Click **Create Account**, enter your real email, phone (`0123456789`), and 12-digit IC (`020415075431`), accept the PDPA policy, and check your email inbox for the verification link from `noreply@cmd-cw2.firebaseapp.com`.
2. **Test Brute-Force Account Lockout:** Enter an incorrect password 5 times on any account. On the 5th attempt, the account transitions to `LOCKED_BRUTE_FORCE` and logs a `CRITICAL` alert to the Admin SIEM console.
3. **Test AES-256-GCM Decryption:** Log in as a Patient or Doctor and click **Decrypt AES-256-GCM Record** to verify the 128-bit GCM authentication tag and SHA-256 integrity hash.
4. **Test XSS Sanitization:** Attempt to submit `<script>alert(1)</script>` in the Appointment Symptoms field; `sanitizeHTML()` strips executable tags and logs a `HIGH` severity `XSS_PAYLOAD_SANITIZED` event.
