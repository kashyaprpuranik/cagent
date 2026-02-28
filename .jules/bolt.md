## 2024-03-24 - [Def instead of Async Def for blocking I/O]
**Learning:** In FastAPI, asynchronous endpoints (`async def`) that run synchronous, blocking I/O code (like `docker-py`'s API calls: `container.stop()`, `container.start()`) block the main event loop and cause massive latency for concurrent async requests.
**Action:** Always define FastAPI endpoints that run blocking code as regular `def` functions. FastAPI will then execute them in an external thread pool automatically, preventing event loop blocking.
