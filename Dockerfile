FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-flask \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*
COPY . /app
WORKDIR /app
CMD ["python3", "app.py"]
