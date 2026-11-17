# Purple Team Lab

Work in progress. A free, reproducible lab where I attack a vulnerable web app,
write detection rules (Suricata, Sigma), and test them automatically in CI.

## Safety and legal

This lab is intentionally vulnerable. It binds to localhost only and must never
be exposed to a network. Only attack systems you own.

## Quick start

    docker compose up -d
    # open http://localhost:4280  (admin / password), set security level to Low