FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libopenscap8 \
    openscap-scanner \
    openscap-utils \
    ssg-base \
    ssg-debderived \
    ssg-nondebian \
    python3 \
    python3-pip \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages httpx

# Download CIS-CAT Lite if available, or use SCAP Security Guide
# SSG profiles are bundled with the ssg-* packages above.
# For CIS content, download from CIS and place in /content/
RUN mkdir -p /content /results

WORKDIR /app
COPY agent.py .
COPY profiles.yml .

CMD ["python3", "-u", "agent.py"]
