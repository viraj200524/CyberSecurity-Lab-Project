# Digital Signature & Trust Forensic Agent (DSTFA)

DSTFA is a cyber-forensics lab project that analyzes email authenticity, hashing behavior, trust chains, and cryptographic vulnerabilities through an interactive dashboard.

## Monorepo Layout

- `backend/`: FastAPI service for upload, analysis, and forensic APIs.
- `frontend/`: Next.js app for upload and analysis visualization.

## Local Setup

### 1) Backend

1. Go to `backend/`.
2. Create and activate a Python virtual environment.
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Configure environment:
   - Copy `.env.example` to `.env`
   - Fill `GEMINI_API_KEY`
5. Run API:
   - `uvicorn main:app --reload --port 8000`

### 2) Frontend

1. Go to `frontend/`.
2. Install dependencies:
   - `npm install`
3. Configure environment in `.env.local`:
   - `NEXT_PUBLIC_API_BASE_URL=http://localhost:8000`
4. Run app:
   - `npm run dev`

## Environment Variables

### Backend (`backend/.env`)

- `GEMINI_API_KEY` (optional until Phase 5 LLM; may be empty for Phase 1–4)
- `APP_ENV`
- `ALLOWED_ORIGINS`
- `MAX_FILE_SIZE_MB`
- `SANDBOX_TIMEOUT_SECONDS`
- `DNS_RESOLVER`

### Frontend (`frontend/.env.local`)

- `NEXT_PUBLIC_API_BASE_URL`
