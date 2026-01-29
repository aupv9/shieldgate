---
inclusion: fileMatch
fileMatchPattern: ['**/*.{ts,tsx}']
---

# React + TypeScript Conventions

## TypeScript
- Prefer explicit types at module boundaries (props, API responses, public functions).
- Avoid `any`; use `unknown` with narrowing when needed.
- Use discriminated unions for UI states (loading/error/success).

## React
- Prefer function components and hooks.
- Do not start effects from render; side-effects belong in `useEffect`/handlers/server actions.
- Memoization (`useMemo`, `useCallback`) only when there is a measured need.

## State
- Local state first; avoid global state unless multiple distant consumers need it.
- Server state (data fetching) should not be duplicated into global UI state.

## Errors
- Use error boundaries for page-level failures.
- Map backend error schema `{code,message,request_id}` into user-friendly UI messages.

## Testing
- Prefer React Testing Library for UI behavior tests; avoid implementation-detail tests.
