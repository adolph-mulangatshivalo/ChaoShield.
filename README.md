# Automated SMS & Digital Document Scam Detection Platform

> **Cybersecurity Platform for Automatic Threat Detection in Digital Documents, Payment Notifications, and SMS Communications**

---

## 🛡️ Executive Summary

This platform automatically detects suspicious SMS messages, fraudulent payment notifications, and potentially manipulated digital documents immediately upon upload.

**Core Design Mandate:**  
Users are **NOT required to manually select which security checks to perform**. As soon as any file (PDF, screenshot, bank slip, or SMS) is selected or dropped, the automated pipeline runs through every forensic check instantaneously.

---

## 📋 Comprehensive Specification Compliance

### 1. Automatic File Upload & Detection
- **Supported Formats:**
  - PDF documents (`.pdf`)
  - SMS screenshots (`.png`, `.jpg`, `.jpeg`, `.webp`)
  - Payment confirmation screenshots & slips
  - Bank notification screenshots
  - Other digital documents & raw SMS exports (`.txt`, `.sms`, `.json`)
- **Zero-Click Ingestion:**
  - Drag-and-drop & normal file selection triggers immediate automated processing.
  - No checkboxes or manual configuration steps required.

### 2. Automatic Metadata Extraction
- **For PDFs:**
  - Creation date (`/CreationDate`)
  - Modification date (`/ModDate`)
  - Author (`/Author`)
  - Software used to create the PDF (`/Producer` & `/Creator`)
  - Embedded image count (`/Subtype /Image`)
  - Document properties (Title, Subject, Version)
  - Digital signature information (`/ByteRange`, `/SigFlags`)
  - PDF structural history and incremental revisions count (`xref` checks)
- **For Screenshots & Images:**
  - Creation & modification timestamps
  - Device/hardware profiles (Apple iOS screenshot, Android, Samsung, etc.)
  - Real dimensions ($W \times H$ pixels) and color depth
  - EXIF metadata presence and editing tool signatures (Adobe Photoshop, Canva, GIMP)
- **For SMS:**
  - Sender name or number, timestamp, full message body, extracted URLs, and phone references.
- **Explicit Missing Metadata Tags:**
  - Clear visual callout highlighting when critical metadata has been stripped or omitted.

### 3. File Integrity Verification (SHA-256 Engine)
- **Immediate Hash Generation:** Cryptographic SHA-256 calculated using Web Crypto API.
- **Persistence:** Hash, timestamp, filename, and format category stored securely in local database (`localStorage`).
- **Registration Comparison:**
  - `File integrity verified`: Matches previously registered version and timestamp.
  - `File integrity mismatch`: Alerts when a file with the same name has been modified post-registration.
  - `No previous integrity record available`: Registers fresh fingerprint for future change tracking.
- **Mandatory Cryptographic Disclosure:**
  - Explicitly states: *"IMPORTANT: Generation of a new SHA-256 hash registers a verifiable fingerprint for change detection, but does not inherently prove that the original uploaded document was authentic or unmanipulated prior to upload."*

### 4. Automatic Image and Screenshot Forensic Analysis
- **Canvas-Powered Visual Inspection:**
  - **Error Level Analysis (ELA):** High-pass recompression transform isolating high-frequency compression anomalies.
  - **Luminance Noise Map:** Detects spliced background blocks and artificial luminance gradients around amounts.
  - Inconsistent font baseline and text geometry detection.
  - Cloned and duplicated image region detection.
  - Calibrated scoring: Does not automatically classify every compression artifact as fraud; outputs nuanced weighted evidence.

### 5. Automatic PDF Forensic Analysis
- Flags unexpected disparity between `CreationDate` and `ModDate`.
- Identifies suspicious producer software (e.g., Photoshop or Canva masquerading as automated banking engines).
- Detects multiple incremental revisions (`startxref` / `xref` counts indicating post-signing document edits).
- Verifies digital signature dictionary presence and `/ByteRange` validity.

### 6. AI-Powered SMS Scam Detection
- Automated natural language parsing identifying:
  - Phishing attempts and fake banking notifications (Capitec, FNB, Standard Bank, Nedbank, Absa, PayShap).
  - Urgent threats, intimidation, and countdowns ("within 24 hours", "immediate suspension").
  - Requests for secret PINs, passwords, or OTPs.
  - Fraudulent prize, lottery, and customs fee schemes.
  - Highlights dangerous phrases directly in the text view and details why each tactic is manipulative.

### 7. Suspicious Link & Threat Intelligence Analysis
- Passive syntactic extraction of all hyperlinks and target domains.
- **Strict Safety:** Never automatically executes or navigates to dangerous links.
- Evaluates:
  - Domain lookalikes & typosquatting (`capitec-security-verify.cc`, `standardbnk-portal.xyz`).
  - URL shorteners (`bit.ly`, `tinyurl.com`, `is.gd`, `t.co`, etc.).
  - High-risk Top Level Domains (`.xyz`, `.top`, `.cc`, `.click`, `.buzz`).
  - Protocol security (absence of HTTPS / raw IP addresses).

---

## 🤖 FEATURE: Multilingual WhatsApp AI Assistant & Voice Note Engine

The platform includes an intelligent multilingual WhatsApp chatbot supporting:
1. **Tshivenda (Venda)**
2. **isiZulu (Zulu)**
3. **Sepedi (Northern Sotho)**
4. **English**

### WhatsApp Messaging Capabilities
- Send normal text messages in any of the 4 supported South African languages.
- Ask questions regarding:
  - How to identify fake Proof of Payment (POP) slips.
  - How to verify suspicious SMS messages.
  - How to upload and analyze PDFs & digital documents.
  - How to inspect suspicious links & phishing domains.
  - How to interpret composite risk scores and SHA-256 integrity dockets.
- Automated instant replies 24/7.

### Two-Way WhatsApp Voice Note Support (STT & TTS)
- **Voice Ingestion**: Users can speak naturally via WhatsApp voice notes without typing.
- **Speech Recognition (STT)**: Transcribes incoming voice notes.
- **Automatic Language Identification (LID)**: Determines whether the speaker is using Venda, Zulu, Sepedi, or English.
- **AI Processing**: Resolves the question using the scam detection knowledge base.
- **Speech Synthesis (TTS)**: Converts the AI response into natural audio speech in the matching language.
- **Audio Voice Note Bubble**: Generates an interactive voice message bubble with audio waveforms, playback progress, and speech output.

### Official Meta WhatsApp Cloud API Webhook
- Backend webhook server: `whatsapp-cloud-api-backend.js`
- Graph API verification: `GET /webhook/whatsapp` (`hub.verify_token`, `hub.challenge`)
- Inbound handler: `POST /webhook/whatsapp` (supports text and `audio/ogg; codecs=opus`)
- Outbound dispatcher: `POST https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages`

---

## 🏃 Quick Start Guide

Open [index.html](file:///c:/Users/lufuno/maitele/index.html) in your browser:

```powershell
# Open directly in Windows default browser
Start-Process "c:\Users\lufuno\maitele\index.html"
```

Or serve locally with Python:
```powershell
cd c:\Users\lufuno\maitele
python -m http.server 3000
# Then visit http://localhost:3000
```


---

## 🇿🇦 POPIA Act (Act 4 of 2013) & In-Memory Privacy Architecture

SafeCheck Sentinel is built with **zero persistent server retention** of sensitive bank receipts or payment documents.

### 100% Client-Side Privacy Guarantee
- When a user uploads a PDF or screenshot, all binary stream parsing, metadata extraction (/Info, XMP packets), font inspection, canvas rendering, and SHA-256 integrity calculation occur **entirely within the user's web browser RAM**.
- No document files, account numbers, or personal identifying information are transmitted to or stored on external cloud servers.
- Fully compliant with the **8 Lawful Processing Conditions** of the South African Protection of Personal Information Act (Act No. 4 of 2013).
- Designated Information Officer contact: `compliance@safesentinelsa.co.za`
- Information Regulator of South Africa complaints channel: `POPIAComplaints@inforegulator.org.za`

---

## 💳 Transparent Pricing & Fair Use Tiers

| Tier | Price | Verification Scans | Features |
| :--- | :---: | :---: | :--- |
| **Normal Person Free Trial** | **R0** | **Up to 5 Free Scans** | Full PDF metadata extraction, timestamp disparity checks, visual ELA viewer, instant scam score. No credit card required. |
| **SME Business Plan** *(Featured)* | **R50 / month** | **Unlimited Scans** | Comprehensive fraud shield for retailers, contractors & shops. PayShap / BankServAfrica validation, ECTA Sec 86 court-ready audit certificates, multi-user team access, 24/7 priority WhatsApp AI. |
| **Individual Pro** | **R25 / month** | **Unlimited Scans** | Continuous personal verification for frequent marketplace buyers, peer-to-peer sellers, and freelancers. Cancel anytime. |

*Note: Free trial scan counter is persisted client-side in `localStorage` (`sentinel_free_scans_left`). A "Reset Demo Scans" button is provided for easy testing and demonstration.*

---

## 🚀 GitHub Pages & Production Deployment

The entire frontend engine is completely static and serverless, requiring **zero backend infrastructure** to run document forensics.

1. **Deploying to GitHub Pages:**
   - Commit all repository files, including `.nojekyll` and `404.html`.
   - In your GitHub repository, navigate to **Settings > Pages**.
   - Under **Build and deployment > Source**, select **Deploy from a branch** (select `main` or `master` and root `/`).
   - Click **Save**. GitHub Pages will serve the platform globally with SSL/TLS encryption.
2. **Local Testing:**
   ```powershell
   python -m http.server 8080
   # Open http://localhost:8080/index.html in your browser
   ```
