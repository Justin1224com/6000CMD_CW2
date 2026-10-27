# MediVault — Full-Stack Secure Healthcare Portal (6000CMD Security)

It includes:
1. **Real Backend Server (`backend/server.js`)**:
   - **Express.js** with **Helmet** (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).
   - **Real Password Hashing**: `bcryptjs` with **Cost Factor 12** (`$2a$12$...`).
   - **Real Authenticated Encryption at Rest**: Node `crypto` **AES-256-GCM** with cryptographically random 96-bit (12-byte) IV and 128-bit Authentication Tag verification (detects 1-byte database tampering).
   - **Real Digital Signatures**: `SHA-256` HMAC/Hash verification on every E-Prescription.
   - **Real 2FA / OTP Engine & Email Verification Tokens**: Generates time-bound 6-digit OTPs and email verification links.
   - **Real RBAC & PoLP Middleware**: Server-enforced JWT role checks (`patient`, `doctor`, `admin`) and resource ownership validation.
   - **Real Brute-Force Account Lockout**: Automatically locks accounts (`LOCKED_BRUTE_FORCE`) after 5 failed password attempts and writes to the immutable SIEM Audit Log.
   - **Persistent Database (`backend/database.json`)**: Automatically created and updated in real time on disk so you can open `backend/database.json` in VS Code to screenshot real Bcrypt hashes and AES-256-GCM ciphertexts!

2. **Real React Frontend (`frontend/`)**:
   - Connects to the real Express backend API (`http://localhost:5000/api`) with automatic fallback to the built-in Web Crypto API engine if run standalone.
   - Interactive **Patient Portal**, **Doctor AES-256-GCM E-Prescription Console**, **Admin SIEM Security Audit Dashboard**, and **Live Vulnerability & Tamper Testing Suite**.

## Quick Start (Run in 2 Minutes)

Run Both Backend & Frontend Together
Open **Terminal 1 (Backend API Server)**:

cd backend
npm install
npm start

The secure backend server will start on **`http://localhost:5000`** and generate `backend/database.json` with real Bcrypt hashes and AES-256-GCM encrypted records.

Open **Terminal 2 (React Frontend)**:

cd frontend
npm install
npm run dev

Open **`http://localhost:5173`** in your browser!

---

## Default Test Accounts (Pre-seeded in Database)
| Role | Email | Password | 2FA Demo OTP |
| :--- | :--- | :--- | :--- |
| **Patient** | `patient@student.inti.edu.my` | `Patient@12345!` | `773082` (or check backend terminal / UI toast) |
| **Doctor** | `doctor@inti.edu.my` | `Doctor@12345!` | `773082` |
| **Security Admin** | `admin@inti.edu.my` | `Admin@12345!` | `773082` |
