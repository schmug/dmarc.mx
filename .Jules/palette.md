## 2024-05-18 - A11y: Dynamic Errors in Multi-step Wizards
**Learning:** In a dynamic form wizard (like the 'Add Domain' wizard), injecting error text into a hidden `div` and making it visible requires setting `role="alert"` for immediate screen reader announcement. Additionally, the input itself must reference that `div` via `aria-describedby` so its error state is contextually clear when the input is focused.
**Action:** Always link input fields to their dynamic error containers using `aria-describedby` and ensure the container has `role="alert"`.
