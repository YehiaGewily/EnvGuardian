# VHS plus the tools the demo needs. Build context: docs/demo.
FROM ghcr.io/charmbracelet/vhs
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client \
 && rm -rf /var/lib/apt/lists/*
COPY envguardian /usr/local/bin/envguardian
COPY setup.sh /demo/setup.sh
# Strip CRLF in case a Windows checkout or editor converted the script.
RUN sed -i 's/\r$//' /demo/setup.sh
