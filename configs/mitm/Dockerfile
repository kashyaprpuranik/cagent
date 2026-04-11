FROM ghcr.io/kashyaprpuranik/mitmproxy:10.4.2
COPY --from=ghcr.io/astral-sh/uv:0.7 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock /tmp/mitm-deps/
RUN cd /tmp/mitm-deps \
    && uv export --frozen --no-dev --no-emit-project -o /tmp/requirements.txt \
    && uv pip install --system --no-cache -r /tmp/requirements.txt \
    && rm -rf /tmp/mitm-deps /tmp/requirements.txt /root/.cache
