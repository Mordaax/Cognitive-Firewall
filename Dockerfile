FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md requirements.lock /app/
RUN pip install --no-cache-dir -r requirements.lock
COPY src /app/src
COPY policies /app/policies
RUN pip install --no-cache-dir --no-deps '.[full]'
RUN useradd --create-home firewall && mkdir -p /data && chown firewall:firewall /data
USER firewall
EXPOSE 8000
CMD ["uvicorn", "cognitive_firewall.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
