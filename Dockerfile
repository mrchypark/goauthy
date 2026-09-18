FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy ./cmd/goauthy
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-bootstrap-secrets ./cmd/goauthy-bootstrap-secrets
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-backup ./cmd/goauthy-backup
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-backchannel-sink ./cmd/goauthy-backchannel-sink
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-cimd-fixture ./cmd/goauthy-cimd-fixture
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-smtp-sink ./cmd/goauthy-smtp-sink
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-scim-fixture ./cmd/goauthy-scim-fixture
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-upstream-fixture ./cmd/goauthy-upstream-fixture
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-saas-oauth-fixture ./cmd/goauthy-saas-oauth-fixture

FROM scratch AS backchannel-sink

COPY --from=build /goauthy-backchannel-sink /goauthy-backchannel-sink
USER 65532:65532
ENTRYPOINT ["/goauthy-backchannel-sink"]

FROM scratch AS cimd-fixture

COPY --from=build /goauthy-cimd-fixture /goauthy-cimd-fixture
USER 65532:65532
ENTRYPOINT ["/goauthy-cimd-fixture"]

FROM scratch AS smtp-sink

COPY --from=build /goauthy-smtp-sink /goauthy-smtp-sink
USER 65532:65532
ENTRYPOINT ["/goauthy-smtp-sink"]

FROM scratch AS scim-fixture

COPY --from=build /goauthy-scim-fixture /goauthy-scim-fixture
USER 65532:65532
ENTRYPOINT ["/goauthy-scim-fixture"]

FROM scratch AS upstream-fixture

COPY --from=build /goauthy-upstream-fixture /goauthy-upstream-fixture
USER 65532:65532
ENTRYPOINT ["/goauthy-upstream-fixture"]

FROM scratch AS saas-oauth-fixture

COPY --from=build /goauthy-saas-oauth-fixture /goauthy-saas-oauth-fixture
USER 65532:65532
ENTRYPOINT ["/goauthy-saas-oauth-fixture"]

FROM build AS checkpoint-fault-build
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goauthy-checkpoint-fault ./cmd/goauthy-checkpoint-fault

FROM scratch AS checkpoint-fault
COPY --from=checkpoint-fault-build /goauthy-checkpoint-fault /goauthy-checkpoint-fault
USER 65532:65532
ENTRYPOINT ["/goauthy-checkpoint-fault"]

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS journal-test-build
ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
RUN CGO_ENABLED=0 go test -c -o /storage.test ./internal/storage

# Test-only syscall observation; the default runtime stays unchanged below.
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS journal-test
RUN apk add --no-cache strace=6.19-r1
COPY --from=journal-test-build /storage.test /storage.test
USER 65532:65532
ENV GOAUTHY_JOURNAL_STRACE_TEST=1
ENTRYPOINT ["/storage.test", "-test.run=^TestNoPVC(InterruptedJournalInstallationRecovers|JournalTraceCutEvidence)$", "-test.v", "-test.timeout=15m"]

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS journal-fault
RUN apk add --no-cache strace=6.19-r1 jq=1.8.2-r0
COPY --from=build /goauthy /goauthy
COPY --from=build /goauthy-bootstrap-secrets /goauthy-bootstrap-secrets
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0555 scripts/e2e-journal-entrypoint.sh /e2e-journal-entrypoint.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh", "/e2e-journal-entrypoint.sh"]

FROM scratch

COPY --from=build /goauthy /goauthy
COPY --from=build /goauthy-backup /goauthy-backup
COPY --from=build /goauthy-bootstrap-secrets /goauthy-bootstrap-secrets
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/goauthy"]
