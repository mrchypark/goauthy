# Build the registered-OAuth runner first from this same GoAuthy commit.
ARG GOAUTHY_E2E_IMAGE
FROM ${GOAUTHY_E2E_IMAGE}
# Named contexts must be reviewed source snapshots, never entire home directories.
COPY --from=beesuh / /beesuh/
COPY --from=rhiza / /rhiza/
COPY test/e2e/browser/testdata/beesuh_oauth_live_test.go /beesuh/goauthy_oauth_live_bridge_test.go
RUN cd /beesuh && GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go test -mod=readonly -run '^$' . && rm goauthy_oauth_live_bridge_test.go
ENV GOAUTHY_E2E_BEESUH_OAUTH_PROJECT_DIR=/beesuh GOAUTHY_E2E_CONSUMER_REFRESH=1
