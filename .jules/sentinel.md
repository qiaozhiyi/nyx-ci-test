## 2024-05-18 - Missing path validation in file operations
**Vulnerability:** File operations like `download`, `mv`, and `cp` in the implant did not validate the target paths (or source paths) before executing NT syscalls.
**Learning:** This gap existed because the functions manually built `open_file` calls rather than relying on a centralized abstraction that performed the check automatically, exposing potential path traversal vulnerabilities.
**Prevention:** Always validate all user-controlled paths (both source and destination) against known restricted paths using the provided validation functions (like `allowed()`) before passing them to low-level APIs or syscalls.
