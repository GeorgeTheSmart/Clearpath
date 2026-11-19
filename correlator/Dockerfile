# Multi-stage: static binary on distroless, non-root. Small attack surface for Trivy.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/correlator ./cmd/correlator

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/correlator /correlator
COPY topology.json /topology.json
# Numeric (distroless "nonroot" = 65532): with a user *name*, Kubernetes'
# runAsNonRoot cannot verify the UID and refuses to start the container.
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/correlator", "-topology", "/topology.json"]
