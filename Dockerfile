FROM python:3.9-slim

WORKDIR /app
COPY . /app

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    python3 \
    perl \
    liblzma-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN yes | cpan -i Compress::Raw::Zlib
RUN yes | cpan -i Compress::Raw::Lzma

ENTRYPOINT ["python3", "file2hashcat.py"]