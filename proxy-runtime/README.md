# Proxy runtime image

This image adds only pinned PySocks support to the ARL base image. It is used by Web and Scheduler when ARL HTTP traffic is configured to use the local Xray-core SOCKS5 listener.

The update and rollback scripts recreate only Web and Scheduler with `--no-deps` and persist the selected images in `.env`.
