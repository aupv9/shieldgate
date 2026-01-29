---
inclusion: fileMatch
fileMatchPattern: ['**/*.{ts,tsx,js,jsx,css,scss,mdx}']
---

# Next.js UI Standards

## Next.js conventions
- Prefer Next.js App Router (`app/`) patterns by default.
- Choose Server Components by default; use Client Components only when needed (`"use client"`).
- Do not import server-only modules into Client Components.
- Prefer `next/navigation` for routing and redirects.

## Data fetching
- Server: fetch in Server Components or server actions; use caching/revalidation intentionally.
- Client: use a single query library pattern (e.g. React Query) if needed; avoid ad-hoc global state.
- Never embed secrets in client bundles.

## API + auth
- All calls to backend must include auth/tenant context according to the project standard.
- Centralize API client(s) and error handling; no scattered `fetch()` implementations.

## Components
- Keep components small; extract reusable UI into `components/`.
- Prefer composition over prop drilling; use context sparingly and locally.

## Forms
- Validate on client for UX and on server for correctness.
- Keep a single source of truth for schemas (recommended: Zod) and reuse for typing.

## UX & accessibility
- Use semantic HTML first.
- Every interactive element must be keyboard accessible and have an accessible name.
- Loading/error/empty states are required for data-driven screens.

## Styling
- Use one styling system consistently (Tailwind OR CSS modules OR styled-components).
- Avoid inline styles except for truly dynamic values.
