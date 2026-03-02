FROM gcr.io/distroless/static:nonroot
COPY vulnex /usr/local/bin/vulnex
ENTRYPOINT ["vulnex"]
