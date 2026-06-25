FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV FLUTTER_HOME=/opt/flutter
ENV PUB_CACHE=/home/flutteruser/.pub-cache
ENV PATH=$FLUTTER_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$JAVA_HOME/bin:$PATH
ENV FLUTTER_ALLOW_ENV_PRINTS=true

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk curl git unzip xz-utils wget \
    libglu1-mesa clang cmake ninja-build pkg-config \
    libgtk-3-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -u 1001 -m -s /bin/bash flutteruser

RUN mkdir -p /opt/flutter /opt/android-sdk && \
    chown flutteruser:flutteruser /opt/flutter /opt/android-sdk

USER flutteruser

RUN git clone --depth 1 --branch stable https://github.com/flutter/flutter.git /opt/flutter && \
    flutter doctor --android-licenses || true && \
    flutter precache

USER root

RUN mkdir -p /opt/android-sdk/cmdline-tools && \
    cd /tmp && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O cmdline-tools.zip && \
    unzip -q cmdline-tools.zip -d /opt/android-sdk/cmdline-tools && \
    mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest && \
    rm cmdline-tools.zip && \
    chown -R flutteruser:flutteruser /opt/android-sdk

USER flutteruser

RUN yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager --install \
    "platform-tools" \
    "platforms;android-34" \
    "build-tools;34.0.0" \
    "cmdline-tools;latest" > /dev/null 2>&1

RUN flutter doctor

WORKDIR /app

COPY --chown=flutteruser:flutteruser pubspec.yaml pubspec.lock ./

RUN flutter pub get

COPY --chown=flutteruser:flutteruser . .

CMD ["flutter", "build", "apk", "--release"]
