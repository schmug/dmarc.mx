## 2026-05-16 - Add ARIA live region for dynamic form validation
**Learning:** For multi-step wizard forms or dynamic client-side validation, screen readers need explicit context when errors appear. Using a hidden error div without `role="alert"` and `aria-live="polite"` prevents the error from being announced.
**Action:** Always link the input field to its error container using `aria-describedby` and dynamically toggle `aria-invalid="true"` on the input when it fails validation.
## 2024-05-22 - Actionable Empty States
**Learning:** Empty states that simply state a lack of data (e.g., "No scan history yet.") are unhelpful. Providing actionable guidance or a direct call-to-action (e.g., "Trigger a scan from the domain overview.") significantly improves the user experience by guiding them on what to do next.
**Action:** Always include actionable guidance or clear calls-to-action in empty states across the application.
