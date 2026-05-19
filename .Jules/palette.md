## 2026-05-16 - Add ARIA live region for dynamic form validation
**Learning:** For multi-step wizard forms or dynamic client-side validation, screen readers need explicit context when errors appear. Using a hidden error div without `role="alert"` and `aria-live="polite"` prevents the error from being announced.
**Action:** Always link the input field to its error container using `aria-describedby` and dynamically toggle `aria-invalid="true"` on the input when it fails validation.

## 2026-05-19 - Make empty states actionable
**Learning:** Empty states that simply say "No data" or "No history yet" represent a missed opportunity to guide the user. Providing actionable guidance or calls-to-action reduces friction and improves usability.
**Action:** When designing empty states for arrays or lists, always include a call to action or an explanation of how the user can populate the list (e.g., "Click 'Scan Now' to run your first scan").
