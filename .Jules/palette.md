## 2026-05-16 - Add ARIA live region for dynamic form validation
**Learning:** For multi-step wizard forms or dynamic client-side validation, screen readers need explicit context when errors appear. Using a hidden error div without `role="alert"` and `aria-live="polite"` prevents the error from being announced.
**Action:** Always link the input field to its error container using `aria-describedby` and dynamically toggle `aria-invalid="true"` on the input when it fails validation.

## 2026-05-21 - Actionable Empty States and Destructive Actions
**Learning:** Empty states should provide actionable guidance rather than just stating a lack of data. Destructive actions like 'Revoke' should use the '.btn-danger' class to clearly communicate their severity.
**Action:** Always include a call-to-action in empty states and use '.btn-danger' for destructive buttons.
