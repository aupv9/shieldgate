---
inclusion: fileMatch
fileMatchPattern: ['**/*.{ts,tsx}']
---

# Frontend Quality Bar (Tech Lead Level)

## UX & accessibility
- Every data view must have loading, error, and empty states.
- Interactive elements must be keyboard-accessible and labeled; use semantic HTML first.

## State & data flow
- Prefer server components; use client components only when interaction/state is required.
- Avoid duplicating server state into client/global state; keep a single source of truth.
- Co-locate data fetching with the boundary (page/route) and keep derived state minimal.

## Error handling
- Surface friendly messages; always preserve `request_id` in UI error details for support.
- Handle API error codes explicitly for business cases (e.g., not_found, forbidden, conflict).

## Performance
- Avoid unnecessary client bundles (`"use client"` only when needed).
- Code-split by route; defer heavy components when offscreen.
- Prefer streaming and incremental rendering where appropriate.

## Testing
- Behavior-first tests with React Testing Library; avoid implementation-detail tests.
- For forms and flows, cover happy path + primary validation failures.
