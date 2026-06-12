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
## 2026-06-01 - Add aria-sort to sortable headers
**Learning:** Sortable headers should be marked with the aria-sort attribute so that screen readers are aware of the order.
**Action:** When creating sortable headers, ensure that only the active sorting header is marked with the aria-sort attribute.

## 2026-06-04 - Add generic data-loading-text support for form submission buttons
**Learning:** Implementing visual feedback (like 'Scanning...' or 'Adding...') on submit buttons often requires custom JS per form. By leveraging a centralized, opt-in `data-loading-text` attribute handled by a single global event listener, we can add consistent, accessible loading states across the application without polluting individual views with duplicated scripts.
**Action:** For form submit buttons triggering slow or async operations, prefer adding a `data-loading-text` attribute (e.g., `data-loading-text="Scanning..."`) to the `<button type="submit">`. This hooks into the global form submission listener in `src/views/scripts.ts` to automatically handle disabled states and text updates.

## 2026-06-05 - Add data-loading-text to standard synchronous forms
**Learning:** Using `data-loading-text` isn't just for heavy async processes; standard forms with synchronous POST operations (like settings saves, revokes, or dismissals) also benefit. It provides immediate visual feedback, confirms the click, and disables the button to prevent accidental double-submissions while the server processes the request.
**Action:** Consistently apply `data-loading-text` to all `<button type="submit">` elements in the app (e.g., settings save buttons, destructive actions) to utilize the global form submit listener for consistent UX and protection against double-clicking.

## 2026-06-06 - Multi-step Wizard Keyboard Progression
**Learning:** Standard HTML forms will prematurely submit if a user hits "Enter" on an early step of a multi-step wizard, disrupting the user flow and potentially submitting incomplete data.
**Action:** Intercept the `submit` event on the form and call `e.preventDefault()`. If the user is not on the final step, programmatically advance to the next step (e.g., by simulating a click on the "Next" button). This ensures smooth keyboard navigation through the wizard.
