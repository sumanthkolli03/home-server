FROM python:3.14-slim-trixie

# Standard library only: nothing is installed, so no third-party code sits in front of Jellyfin.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY gate.py /app/gate.py

EXPOSE 8000
CMD ["python", "-I", "/app/gate.py"]
