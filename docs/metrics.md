# Prometheus metrics

Metrics are disabled unless `GOAUTHY_METRICS_LISTEN_ADDR` is set. When
enabled, GoAuthy opens a separate TCP listener serving only:

```text
GET /metrics
```

The application listener never exposes this endpoint, and the metrics
listener does not expose GoAuthy authentication or API routes. Configure a
fixed host and port such as `127.0.0.1:9090` or `:9090`; `:0` is accepted for
development and tests. The address must be a trimmed TCP `host:port` value
with a decimal port from 0 through 65535.

Set `GOAUTHY_METRICS_TOKEN_FILE` when the metrics listener is enabled. The
file contains one non-empty bearer token, with an optional final newline.
Prometheus must send it as `Authorization: Bearer <token>`. Missing,
repeated, malformed, or incorrect credentials return `401`.

The listener is started and shut down independently from the application
server, while either server failure still terminates the process. Database
readiness and request instrumentation are recorded in the private metrics
registry; no process-global Prometheus registry is modified.
