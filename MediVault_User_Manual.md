# MediVault — Simple User Manual

**Website:** https://cmd-cw2.web.app/  
**Project:** MediVault Secure Healthcare Portal (6000CMD CW2)

## 1. Getting Started

1. Open the MediVault website and select **Create Account**.
2. Enter the required registration details and use fictional personal/medical data for coursework testing.
3. Read the privacy notice, tick the consent checkbox, and complete registration.
4. Open the verification email and verify your account before signing in.
5. Sign in with your registered email and password.

**Important:** Every newly registered account is assigned the **Patient** role by default. Users cannot promote themselves to Doctor or Administrator through the website.

## 2. First-Time Administrator Setup (Authorized Firebase Editor Access Required)

MediVault requires a one-time manual setup to establish the first Administrator. **To manually change a user’s `role` in Firestore, you must first receive Editor access to our Firebase project (or equivalent Firestore write permission) from our project owner/team. Without this authorization, you cannot edit user roles in the Firebase Console.** Ordinary MediVault users cannot access the project database or edit their own roles.

1. Register and verify the account that will be used as the first Administrator.
2. Sign in to the **Firebase Console** for the MediVault project (`cmd-cw2`) using an account with the required Firestore editing permissions. If you do not have access, request authorization from the project owner.
3. Open **Firestore Database → Data → `medivault_users`**.
4. Find the account document with the matching **Firebase Authentication UID**.
5. Edit only its `role` field from `patient` to `admin`. Keep `accountStatus` as `ACTIVE`.
6. Save the change, then sign out of MediVault and sign in again.
7. The **Administrator Portal** should now be available.

**Note:** This is a bootstrap step for the first Administrator. Only trusted, authorized project members should be granted Firestore editing access. Ordinary users must not be granted permissions to change their own role.

## 3. Assigning a Doctor Account

1. Ask the intended Doctor to register and verify a normal account. It will initially be a Patient account.
2. Sign in with an Administrator account.
3. Open **User & RBAC Management** in the Administrator Portal.
4. Locate the intended user's account and change its role from **PATIENT** to **DOCTOR** using the role dropdown.
5. Ask the Doctor to sign out and sign in again to load the updated role.

Administrators may also activate or deactivate user access. Administrators cannot change their own role or account status through the application.

## 4. Patient Guide

1. Sign in with a verified Patient account.
2. Open **Book & View Appointments**.
3. Select an active Doctor, choose a future appointment date and time, and enter symptoms.
4. Click **Submit Appointment**.
5. Open **My Encrypted E-Prescriptions** to view and decrypt any prescriptions issued for your account.

If the Doctor list is empty, an Administrator must assign an active Doctor first.

## 5. Doctor Guide

1. Sign in with a verified Doctor account.
2. Open **Assigned Patient Appointments** to review consultations assigned to you.
3. Open **Issue Encrypted E-Prescription**.
4. Select a patient with an appointment assigned to your account, complete the prescription fields, and click **Encrypt with AES-256-GCM & Issue Prescription**.
5. Open **Issued Prescriptions Archive** to review your issued records.

## 6. Administrator Guide

After signing in, the Administrator can:

- Use **User & RBAC Management** to assign roles or activate/deactivate accounts.
- Use **SIEM Security Audit Trail** to review recorded activity and filter events.
- Review the available dashboard and security information.

Audit records are selected application events, not a complete record of every action.

## 7. Basic Security and Troubleshooting

- Use only **fictional patient and identity data** when testing the coursework system.
- New accounts require **email verification** before clinical access.
- Use **Forgot password** on the sign-in page if you need to reset your password.
- The application signs out an inactive browser session after approximately **three minutes**.
- Only the relevant Patient and assigned Doctor can retrieve the protected decryption key for a prescription.
- If access is denied after a role change, sign out and sign back in; ask the Administrator to confirm the role and `accountStatus`.
- A GitHub code update does not automatically redeploy Firebase Hosting or Firestore Security Rules.

**Coursework note:** MediVault is a demonstration application, not a certified production healthcare system.
