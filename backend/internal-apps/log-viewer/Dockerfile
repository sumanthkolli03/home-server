# The log viewer and its collector: one image, two containers.
# Standard library only; nothing is installed.
FROM python:3.14-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY main.py helper.py health.py collect.py style.css app.js ./
USER 65534
EXPOSE 8080
CMD ["python", "main.py"]
