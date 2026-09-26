FROM rclone/rclone:1.72.0
COPY scripts/e2e-s3-client.sh /usr/local/bin/s3-fixture
RUN chmod 0755 /usr/local/bin/s3-fixture
ENTRYPOINT ["/usr/local/bin/s3-fixture"]
