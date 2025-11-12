FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-flask \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*
COPY . /app
WORKDIR /app
RUN pip3 install -e . || true
CMD ["python3", "-m", "src.main"]
