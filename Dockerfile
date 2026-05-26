FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV DOTNET_ROOT=/opt/dotnet
ENV PATH="/opt/dotnet:/usr/local/bin:${PATH}"
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1

ARG DOTNET_CHANNEL=10.0
ARG ILSPYCMD_VERSION=10.0.1.8346

RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' \
    > /etc/apt/apt.conf.d/80-retries

RUN printf 'deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware\n' \
    > /etc/apt/sources.list

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update --fix-missing && \
    apt-get install -y --fix-missing --no-install-recommends \
      ghidra \
      openjdk-21-jre-headless \
      python3 \
      jadx \
      apktool \
      file \
      binutils \
      gcc \
      libc6-dev \
      coreutils \
      curl \
      unzip \
      zip \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update --fix-missing && \
    apt-get install -y --fix-missing --no-install-recommends libicu-dev && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh && \
    chmod +x /tmp/dotnet-install.sh && \
    /tmp/dotnet-install.sh --channel "$DOTNET_CHANNEL" --install-dir "$DOTNET_ROOT" && \
    rm -f /tmp/dotnet-install.sh && \
    DOTNET_CLI_HOME=/tmp/dotnet-home dotnet tool install --tool-path /usr/local/bin ilspycmd --version "$ILSPYCMD_VERSION" && \
    rm -rf /tmp/dotnet-home

ENV DECOMPILE_IN_DOCKER=1
ENV DECOMPILE_NO_AI=1

RUN mkdir -p /tmp/decompile-home/.config && \
    chmod 0777 /tmp/decompile-home /tmp/decompile-home/.config

COPY decompile_tool /usr/local/bin/decompile_tool
COPY decompile /usr/local/bin/decompile

RUN chmod +x /usr/local/bin/decompile && \
    chmod +x /usr/local/bin/decompile_tool/cli.py && \
    chmod +x /usr/local/bin/decompile_tool/enhance_with_copilot

WORKDIR /reverse

ENTRYPOINT ["decompile"]
