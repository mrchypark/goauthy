FROM golang:1.27-alpine AS fixture-build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/e2e-saas-isolation-fixture ./cmd/e2e-saas-isolation-fixture
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /fixture ./cmd/e2e-saas-isolation-fixture

FROM alpine:3.22 AS fixture
RUN apk add --no-cache iproute2
COPY --from=fixture-build /fixture /fixture
USER 65532:65532
ENTRYPOINT ["/fixture"]

FROM golang:1.27-alpine AS driver-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test -c -trimpath -o /browser-e2e ./test/e2e/browser

FROM scratch AS driver
COPY --from=driver-build /browser-e2e /browser-e2e
ENTRYPOINT ["/browser-e2e"]
