## 2026-05-16 - Add ARIA live region for dynamic form validation
**Learning:** For multi-step wizard forms or dynamic client-side validation, screen readers need explicit context when errors appear. Using a hidden error div without `role="alert"` and `aria-live="polite"` prevents the error from being announced.
**Action:** Always link the input field to its error container using `aria-describedby` and dynamically toggle `aria-invalid="true"` on the input when it fails validation.
## 2024-05-19 - Actionable Empty States
**Learning:** Generic empty states ("No X found") create dead ends for users. Providing a clear "Next Step" or CTA directly inside the empty state message drastically improves usability.
**Action:** When creating or reviewing list/table empty states, ensure the text explicitly tells the user *how* to populate the list or *why* it's empty.
