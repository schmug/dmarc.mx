## 2026-05-16 - Add ARIA live region for dynamic form validation
**Learning:** For multi-step wizard forms or dynamic client-side validation, screen readers need explicit context when errors appear. Using a hidden error div without `role="alert"` and `aria-live="polite"` prevents the error from being announced.
**Action:** Always link the input field to its error container using `aria-describedby` and dynamically toggle `aria-invalid="true"` on the input when it fails validation.
