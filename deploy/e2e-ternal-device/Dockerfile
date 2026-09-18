# Local test image only. Supply the Ternal checkout as a named BuildKit context:
# --build-context ternal=/absolute/path/to/ternal
FROM golang:1.27-alpine
RUN apk add --no-cache curl openssl iproute2 netcat-openbsd procps chromium
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY test ./test
COPY scripts ./scripts
COPY deploy/k8s/password-reset/email-templates.yaml ./deploy/k8s/password-reset/email-templates.yaml
# Only source inputs, never the checkout's data, .env, Git config or credentials.
COPY --from=ternal go.mod go.sum /ternal/
COPY --from=ternal cmd /ternal/cmd
COPY --from=ternal internal /ternal/internal
RUN cd /ternal && go mod download && go build -mod=readonly -trimpath ./cmd/ternal-api ./cmd/ternalctl
RUN go build -trimpath ./cmd/goauthy ./cmd/goauthy-smtp-sink && go build ./cmd/goauthy-password && go test -mod=readonly ./test/e2e/browser -run '^TestTernalXDGIsolationGuard$'
ENV GOPROXY=off GOSUMDB=off GOAUTHY_E2E_TLS=1 GOAUTHY_E2E_TERNAL_DEVICE=1 GOAUTHY_E2E_TERNAL_PROJECT_DIR=/ternal
ENTRYPOINT ["sh", "scripts/e2e-saas-oauth-isolated.sh"]
