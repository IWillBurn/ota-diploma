# atheris + python-tuf 7.0.1 (the version of the bench's client contour)
FROM python:3.11-slim-bookworm
RUN pip install --no-cache-dir atheris==2.3.0 tuf==7.0.1 cryptography
COPY fuzz_tuf.py tuf.dict /h/
