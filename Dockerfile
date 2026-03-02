FROM gcr.io/distroless/static:nonroot
COPY vulnex /usr/local/bin/vulnex
EXPOSE 8080
ENTRYPOINT ["vulnex"]
CMD ["serve"]
