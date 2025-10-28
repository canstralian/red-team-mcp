FROM kalilinux/kali-rolling
RUN apt update && apt install -y python3-flask postgresql-client
COPY . /app
WORKDIR /app
CMD ["python3", "app.py"]
