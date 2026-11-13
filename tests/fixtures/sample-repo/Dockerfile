FROM python:latest
ARG DEPLOY_TOKEN
ENV APP_ENV=production
ADD https://example.com/install.sh /tmp/install.sh
RUN curl -fsSL https://example.com/setup.sh | sh
COPY . /app
CMD ["python", "/app/main.py"]
