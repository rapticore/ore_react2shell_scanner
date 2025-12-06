# Vulnerable RSC Test Application

**WARNING: This application contains intentionally vulnerable code for security testing purposes only. DO NOT deploy to production.**

## Purpose

This Next.js application demonstrates vulnerable React Server Components (RSC) patterns that can be detected by the `ore_rsc.py` scanner. It covers all vulnerability patterns related to CVE-2025-55182 (React2Shell).

## Vulnerable Patterns Demonstrated

### 1. Server Components (Flight Protocol)
- **Location**: `src/app/page.tsx`, `src/app/components/`
- **Pattern**: Server-rendered components that stream via React Flight protocol
- **Detection**: Scanner looks for `text/x-component` content type and Flight markers

### 2. Server Actions
- **Location**: `src/app/components/ServerActionForm.tsx`, `src/app/forms/page.tsx`
- **Patterns**:
  - Form submissions via `'use server'` directives
  - Command execution patterns
  - File upload handlers
  - Database query handlers
- **Detection**: Scanner looks for `$ACTION_ID` markers and action headers

### 3. Streaming SSR
- **Location**: `src/app/stream/page.tsx`
- **Pattern**: Suspense boundaries with async components
- **Detection**: Multiple Flight chunks in response

### 4. Admin/Sensitive Routes
- **Location**: `src/app/admin/page.tsx`, `src/app/dashboard/page.tsx`
- **Patterns**:
  - Weak authentication
  - Sensitive data exposure
  - Admin action endpoints

### 5. API Endpoints with RSC Patterns
- **Location**: `src/app/api/*/route.ts`
- **Patterns**:
  - RSC-aware API routes
  - Flight protocol responses
  - Server action endpoints

## Installation

```bash
cd test-vulnerable-app
npm install
```

## Running the App

```bash
# Development mode (default - uses React 19.0.0)
npm run dev

# Specific vulnerable versions
npm run dev:19.0.0  # React 19.0.0 (vulnerable)
npm run dev:19.1.0  # React 19.1.0 (vulnerable)
npm run dev:19.1.1  # React 19.1.1 (vulnerable)
npm run dev:19.2.0  # React 19.2.0 (vulnerable)
```

The app will be available at `http://localhost:3000`

## Testing with the Scanner

```bash
# From the parent directory
cd ..

# Basic scan (use http:// prefix for local dev server)
python ore_rsc.py http://localhost:3000

# Deep scan
python ore_rsc.py http://localhost:3000 --deep

# Active verification
python ore_rsc.py http://localhost:3000 --verify

# With output file
python ore_rsc.py http://localhost:3000 --deep -o scan_results.json --format json
```

**Note:** Use `http://localhost:3000` (not just `localhost:3000`) since the dev server runs on HTTP, not HTTPS.

## Expected Scanner Results

The scanner should detect:

1. **CRITICAL Risk**:
   - `/api/rsc` - Full Flight protocol endpoint with server actions
   - `/action` - Server action execution endpoint

2. **HIGH Risk**:
   - `/` - Main page with RSC content type
   - `/dashboard` - Streaming RSC with sensitive data
   - `/admin` - Admin panel with server actions
   - `/forms` - Multiple server action forms

3. **MEDIUM Risk**:
   - `/stream` - Streaming SSR patterns
   - `/api/products` - RSC-aware API

4. **LOW Risk**:
   - `/api/users` - Standard API with Next.js headers

## Endpoints to Test

| Endpoint | Type | RSC Pattern |
|----------|------|-------------|
| `/` | Page | Server Components + Actions |
| `/admin` | Page | Server Actions + Sensitive Data |
| `/dashboard` | Page | Streaming + Suspense |
| `/forms` | Page | Multiple Server Actions |
| `/stream` | Page | Flight Streaming |
| `/api/rsc` | API | Raw Flight Protocol |
| `/action` | API | Server Action Handler |
| `/api/products` | API | RSC-Aware Response |
| `/api/users` | API | Standard with Headers |

## Vulnerability Categories

### Command Injection (React2Shell)
- `ServerActionForm.tsx`: `executeServerCommand` action
- `admin/page.tsx`: `executeAdminCommand` action
- `action/route.ts`: `execute_command` handler

### SQL Injection
- `forms/page.tsx`: `searchDatabase` action
- `admin/page.tsx`: `databaseQuery` action
- `action/route.ts`: `query_database` handler

### SSRF
- `forms/page.tsx`: `importData` and `webhookHandler` actions

### XSS
- `DangerousHtmlRenderer.tsx`: `dangerouslySetInnerHTML` usage
- `VulnerableProductList.tsx`: Unsanitized HTML rendering

### Prototype Pollution
- `forms/page.tsx`: Object spread from form data
- Form fields with `__proto__` and `constructor` names

### Information Disclosure
- `admin/page.tsx`: Process info exposure
- `dashboard/page.tsx`: API keys and database URLs in stats

## Security Note

This application is designed to be vulnerable for testing purposes. All vulnerabilities are intentional to validate security scanner detection capabilities.

**Never run this in production or on publicly accessible servers.**
