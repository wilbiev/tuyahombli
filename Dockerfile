FROM mcr.microsoft.com/devcontainers/python:3.13

# Fix the broken Yarn repository key issue that blocks apt-get update
RUN rm -f /etc/apt/sources.list.d/yarn.list

# Pre-install your required system packages here instead of using a feature
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    ffmpeg \
    libturbojpeg0 \
    libpcap-dev \
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*