# Test-only runtime. All compilation dependencies are fetched before isolation.
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
RUN go build -trimpath ./cmd/goauthy ./cmd/goauthy-smtp-sink ./cmd/goauthy-saas-oauth-fixture && go build ./cmd/goauthy-password && go test -mod=readonly ./test/e2e/browser -run '^$'
# No downloaded dependencies or external DNS are permitted at runtime.
ENV GOPROXY=off GOSUMDB=off GOAUTHY_E2E_TLS=1 GOAUTHY_E2E_REGISTERED_OAUTH2=1 GOAUTHY_E2E_OAUTH2_GRANT_UI=1
ENTRYPOINT ["sh", "scripts/e2e-saas-oauth-isolated.sh"]
