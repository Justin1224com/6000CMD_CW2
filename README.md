# MediVault — Secure Healthcare Portal (CW2)

MediVault is a university coursework application for patient appointments, doctor-issued electronic prescriptions and administrator oversight. The frontend is built with HTML, CSS and vanilla JavaScript; Firebase Authentication and Cloud Firestore provide identity and data services.

**Live website:** https://cmd-cw2.web.app/
**Source repository:** https://github.com/Justin1224com/6000CMD_CW2

## Main features and security controls

- **Patient:** register, verify email, sign in, book appointments and view/decrypt prescriptions associated with the account.
- **Doctor:** view assigned appointments and issue encrypted prescriptions.
- **Administrator:** review user accounts, manage permitted roles/account statuses and view selected security audit events.
- **Access control:** Firestore Security Rules check authentication, email verification, account status, roles and clinical-document ownership. The interface alone is not the security boundary.
- **Data protection:** the Web Cryptography API uses AES-256-GCM for prescription content and the NRIC field **within medical records**, with random record keys, per-field IVs, AAD and separately restricted `private/key` documents. Profile and appointment fields are **not** additionally encrypted by this application; they depend on Firebase-managed storage protections and authorization rules.
- **Other measures:** registration consent check, input validation, HTML output encoding, controlled error messages, a browser-based three-minute inactivity logout, selected application audit logs and Firebase Hosting response headers.

## Project files

```text
README.md
app.js
index.html
styles.css
firestore.rules
firebase.json
public/
  app.js
  index.html
  styles.css
```

The `public/` copies are the files served by Firebase Hosting. They should match their root-level counterparts. Do **not** commit `.firebase/` caches, real patient data, passwords or test-report exports.

## How to run

1. Open the project folder in VS Code. Run root-level `index.html` with the **Live Server** extension, or visit the live HTTPS website. No application server or `npm install` is required.
2. Use a Firebase project with **Email/Password Authentication** and Cloud Firestore enabled. The frontend is configured for the coursework project `cmd-cw2`; the project owner must configure authorized authentication domains and publish the appropriate `firestore.rules`. Frontend password-composition checks do **not**, by themselves, prove that an equivalent Firebase server-side password policy is enabled.
3. Register with an email address you control and **fictional** identity and medical data. Open the verification email, confirm your email, then sign in. Use **Forgot password** for account recovery.
4. Newly registered accounts start as **Patient**. An authorized Firebase project owner may bootstrap the first Administrator by setting the appropriate `medivault_users/{uid}` role in Firestore. Authorized administrators can subsequently assign Doctor roles through the application.
5. As Patient, make an appointment. As the assigned Doctor, issue a prescription. The related Patient and Doctor can access/decrypt that record; unauthorized users should receive `permission-denied` on restricted Firestore requests.

Do not publish working test-account passwords in this README. Firebase project web configuration is not an administrator credential; database access is controlled by Authentication and Firestore Security Rules.

## Firebase Hosting deployment

Firebase Hosting uses `public/` as configured in `firebase.json`. After confirming the files and project permissions, an authorized project owner can deploy the website with:

```powershell
npx firebase-tools login
npx firebase-tools deploy --only hosting --project cmd-cw2
```

If Firestore Rules have deliberately changed and have been reviewed, deploy them separately with `npx firebase-tools deploy --only firestore:rules --project cmd-cw2`. A GitHub push alone does **not** deploy either Hosting or Firestore Rules.

## Security testing and known limitations

Coursework evaluation included manual authentication and workflow checks (T1–T30); direct Firestore authorization tests for Patient, Doctor and Administrator; function-level AES-GCM tampering and input-validation tests; HTTPS/TLS/response-header inspection; and a mobile-browser deployment smoke test.

An **OWASP ZAP Baseline Scan on 12 November 2026** of the hosted site discovered six URLs and reported **59 PASS checks, nine warning rules and zero FAIL-classified checks**. The warning findings included CSP allowing inline styles and missing Subresource Integrity for external JavaScript dependencies. This was primarily a passive, unauthenticated scan; it does not establish that the application is vulnerability-free. Automated Firebase Emulator rules tests were not completed.

Audit events are partly created by the browser and do not constitute a complete trusted, tamper-proof SIEM. Browser inactivity logout is not a universal Firebase token-expiration policy. This coursework system is not presented as a clinically certified production healthcare service or as proof of full PDPA compliance.

## Development evolution

The final coursework build retains the original three-role clinic interface and clinical workflows while refining the supporting security architecture. The revised codebase includes managed Firebase Authentication, database-enforced Firestore permissions, AES-256-GCM record encryption with randomly generated keys and protected key documents, privacy consent and separated private profiles, restricted application audit records, browser inactivity logout, and verified Firebase Hosting security configuration. The report provides implementation extracts and test evidence. This section describes the **final design**, not a line-by-line Git comparison or exclusive attribution of every code change.

## Team security development responsibilities

| Member | Main development and security workstream | Report section |
| --- | --- | --- |
| **Low Justin** | Initial MediVault application development, including the core patient, doctor and administrator interfaces/workflows; authentication, cryptography and input-security workstream (Firebase Authentication, email verification, AES-256-GCM, validation, output encoding and error handling). | **3.1** — Authentication, AES-256-GCM and input security. |
| **Yew Wen Jun** | Security hardening and system integration; Firestore RBAC and least-privilege authorization, administrator privilege restrictions, privacy consent, separated private profiles and direct authorization testing. | **3.2–3.3** — Data protection, privacy, RBAC and administrator security. |
| **Tan Yien Win** | Security monitoring, session and deployment-protection workstream; audit logging and analytics, inactivity logout, Firebase Hosting security headers, HTTPS verification and automated-scan analysis. | **3.4–3.5** — Monitoring, session management and HTTPS security. |

The team collaborated on integration, evaluation and documentation. These workstreams indicate principal responsibilities, not exclusive authorship of all code in a section. Each member should be able to explain the changes they personally implemented or tested during the individual viva.
