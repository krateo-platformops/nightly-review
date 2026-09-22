FROM python:3.12-slim
WORKDIR /app
# Pinned, and deliberately few. This image assembles a corpus and hands it to a model; every extra
# dependency is more code with access to that corpus before it is redacted.
RUN pip install --no-cache-dir \
      requests==2.32.3 \
      jsonschema==4.23.0 \
      kubernetes==31.0.0
COPY *.py .
USER 65532:65532
# Runs once and exits. The schedule lives in the CronJob, not in a loop inside the process, so a run
# that wedges is visible as a Job that never completed rather than a pod that looks healthy.
CMD ["python", "main.py"]
