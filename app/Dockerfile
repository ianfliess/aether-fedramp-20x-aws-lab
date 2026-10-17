FROM public.ecr.aws/docker/library/python:3.12-slim

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app
COPY --chown=10001:10001 server.py /app/server.py

USER 10001:10001
EXPOSE 8443

CMD ["python3", "-B", "/app/server.py"]
