# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol

# Restore Gap Cloud image. Two stages so the runtime image carries one static
# binary and CA certificates, nothing else: no shell, no package manager, no
# Go toolchain. State lives under /data (mount a volume there).
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/tannernicol/restoregap/internal/cli.Version=${VERSION}" \
      -o /out/restoregap-cloud ./cmd/restoregap-cloud

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/restoregap-cloud /restoregap-cloud
ENV RESTOREGAP_CLOUD_DATA=/data
# Bundle context files are staged under TMPDIR during verification; run with
# `--read-only --tmpfs /tmp` rather than making the root writable.
ENV TMPDIR=/tmp
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/restoregap-cloud"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
