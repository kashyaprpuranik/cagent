## 2024-05-24 - [Avoid subprocess calling "docker" binary inside Python SDK container]
**Vulnerability:** Calling `subprocess.run(["docker", "exec", ...])` fails because the `docker` CLI binary is not installed in the Warden slim Python container (`services/warden/Dockerfile`), raising a `FileNotFoundError`.
**Learning:** Operations targeting Docker from inside Warden should utilize the `docker-py` Python SDK (e.g., `container.exec_run(...)`) instead of subprocess shells.
**Prevention:** Replace `subprocess.run` with `container.exec_run(...)` from the `docker-py` library to execute commands inside containers without needing the Docker CLI.
