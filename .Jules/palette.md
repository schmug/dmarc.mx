## 2026-05-08 - Accessible Form Validation
**Learning:** For accessible dynamic form validation in multi-step wizards, it's crucial to link the input to its corresponding error container using `aria-describedby`. The error container itself needs `role="alert"` and `aria-live="polite"` so screen readers announce errors immediately as they appear, without the user needing to lose focus or manually search for the error text.
**Action:** Always apply `aria-describedby`, `role="alert"`, and `aria-live="polite"` when building dynamic error containers for forms or inputs.
