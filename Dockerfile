### Multi-stage Dockerfile
# Define the base image only once as a build argument
ARG PYTHON_IMAGE=python:3.11.14-slim
      
### Build stage
FROM ${PYTHON_IMAGE} AS builder
### Install OS dependencies and poetry package manager
RUN apt-get update && \
    apt-get install -y gcc libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --upgrade pip poetry

WORKDIR /usr/src/owaspnettacker

# Copy dependency files first to maximize Docker cache usage for installing dependencies
COPY poetry.lock pyproject.toml ./

# Install dependencies
RUN poetry config virtualenvs.in-project true && \
    poetry install --no-cache --no-root --without dev --without test

# Now copy the rest of the required source code
COPY nettacker nettacker
COPY nettacker.py README.md ./

# Build the project only after all code is present
RUN poetry build

### Runtime stage - start from a clean Python image
FROM ${PYTHON_IMAGE} AS runtime
WORKDIR /usr/src/owaspnettacker

# OCI Labels (attach to final image)
LABEL org.opencontainers.image.title="OWASP Nettacker" \
      org.opencontainers.image.description="Automated Penetration Testing Framework" \
      org.opencontainers.image.url="https://owasp.org/nettacker" \
      org.opencontainers.image.source="https://github.com/OWASP/Nettacker" \
      org.opencontainers.image.licenses="Apache-2.0"
      
### Bring from 'builder' just the virtualenv and the packaged Nettacker as a wheel 
COPY --from=builder /usr/src/owaspnettacker/.venv ./.venv
COPY --from=builder /usr/src/owaspnettacker/dist/*.whl .

ENV PATH=/usr/src/owaspnettacker/.venv/bin:$PATH
### Use pip inside the venv to install just the nettacker wheel saving 50%+ space
RUN pip install --no-deps --no-cache-dir nettacker-*.whl && \
    rm -f nettacker-*.whl

### We now have Nettacker installed in the virtualenv with 'nettacker' command which is the new entrypoint
ENV docker_env=true
ENTRYPOINT [ "nettacker" ]
CMD ["--help"]
