# Juice Shop E2E report slot

Target profile: OWASP Juice Shop `v20.1.1`  
Expected local target: `http://127.0.0.1:3000`  
Authorized scope: loopback Compose range only  

This repository defines the reproducible target and build-tagged integration
harness, but this report is deliberately marked **not executed**. The phase was
implemented on a host without a Docker CLI/daemon and without enough free disk
to install or pull the lab safely. No public Juice Shop instance was used as a
substitute.

To produce the evidence on a suitable host:

```sh
make lab-up
sentinel engagement create \
  --id juice-shop-local \
  --name "Juice Shop local E2E" \
  --scope http://127.0.0.1:3000
sentinel recon http://127.0.0.1:3000 \
  --engagement juice-shop-local \
  --authorized \
  --out .sentinel-data/juice-shop-recon.json
make lab-down
```

Replace this slot with the redacted generated report only after the complete
Recon → Mapping → Tactical Fuzzing flow runs in the Kali Dev Container. Do not
present a dry-run or invented finding as E2E evidence.
