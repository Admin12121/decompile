FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' \
    > /etc/apt/apt.conf.d/80-retries

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update --fix-missing && \
    apt-get install -y --fix-missing --no-install-recommends \
      ghidra \
      openjdk-21-jre-headless \
      gh \
      jq \
      file \
      binutils \
      coreutils \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /scripts

COPY DumpAllDecompile.java /scripts/DumpAllDecompile.java
COPY ghidra-dump /usr/local/bin/ghidra-dump
COPY enhance_with_copilot /usr/local/bin/enhance_with_copilot

RUN chmod +x /usr/local/bin/ghidra-dump && \
    chmod +x /usr/local/bin/enhance_with_copilot && \
    ln -s /usr/local/bin/ghidra-dump /usr/local/bin/code && \
    ln -s /usr/local/bin/ghidra-dump /usr/local/bin/decompile

WORKDIR /reverse

ENTRYPOINT ["ghidra-dump"]
