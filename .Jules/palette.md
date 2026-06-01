## 2026-05-16 - Add ARIA live region for dynamic form validation
**Learning:** For multi-step wizard forms or dynamic client-side validation, screen readers need explicit context when errors appear. Using a hidden error div without `role="alert"` and `aria-live="polite"` prevents the error from being announced.
**Action:** Always link the input field to its error container using `aria-describedby` and dynamically toggle `aria-invalid="true"` on the input when it fails validation.
## 2024-05-19 - Actionable Empty States
**Learning:** Generic empty states ("No X found") create dead ends for users. Providing a clear "Next Step" or CTA directly inside the empty state message drastically improves usability.
**Action:** When creating or reviewing list/table empty states, ensure the text explicitly tells the user *how* to populate the list or *why* it's empty.

## 2025-05-19 - Inline Workflows for Empty States
**Learning:** Forcing users to navigate to a new page from an empty state can break flow and feel disjointed.
**Action:** When empty states provide a CTA, prefer triggering inline components (like modals or wizards) over full page navigations to reduce friction.
## 2026-05-31 - Custom Accordion A11y Pattern
**Learning:** In dmarc.mx, the SPF tree components use custom spans functioning as buttons. While they correctly employed `role="button"`, `tabindex="0"`, and `aria-controls`, the target collapsible elements lacked the required `role="region"` and `aria-labelledby` properties to complete the WAI-ARIA Accordion pattern.
**Action:** When implementing or auditing custom accordions (like `.spf-node.include` controls or `.card` headers), verify that the control has an `id`, `role="button"`, `aria-expanded`, and `aria-controls`, and that the target container has an `id`, `role="region"`, and `aria-labelledby` pointing back to the control.

## 2024-05-18 - ARIA Accordion Pattern for Client-Rendered Elements
**Learning:** When client-side scripts dynamically render interactive components like accordions (e.g. `protocolRowEl` in `src/views/scripts.ts`), you have to manually generate predictable IDs to wire up the WAI-ARIA `aria-controls`, `role="region"`, and `aria-labelledby` attributes, since you are generating the DOM elements directly without a framework like React.
**Action:** When creating inline/JS-rendered expandable sections, always pass or generate unique IDs (e.g. `protocol-${name.toLowerCase()}`) to correctly wire the WAI-ARIA accordion pattern between the toggle button and the expanding content panel.
