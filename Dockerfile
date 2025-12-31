FROM python:3.13-slim

ENV DOCKER=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/tools \
    && git clone --depth 1 "https://github.com/jsvul/js-function-extractor.git" /opt/tools/jsfe \
    && cd /opt/tools/jsfe && npm install --omit=dev \
    && git clone --depth 1 "https://github.com/jsvul/js-minify-helper.git" /opt/tools/jsmh \
    && cd /opt/tools/jsmh && npm install --omit=dev

ENV JSFE_PATH=/opt/tools/jsfe/tool.js
ENV JSMH_PATH=/opt/tools/jsmh/tool.js

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir /work_dir

ENV WORK_DIR=/work_dir

ENTRYPOINT ["python", "tool.py"]

CMD []
