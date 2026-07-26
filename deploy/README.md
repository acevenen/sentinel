# Isolated local lab

The default Compose service is only the tiny local LLM contract fixture.
Vulnerable web applications are opt-in:

```sh
make lab-up
docker compose -f deploy/compose.yaml --profile web up -d webgoat dvwa
make lab-down
```

All published ports bind to host loopback, and the Compose network is marked
internal so lab containers cannot route to the Internet. `make lab-down`
deletes the disposable lab containers and volumes.

Pinned images:

- OWASP Juice Shop `v20.1.1` on `127.0.0.1:3000`
- WebGoat `v2025.3` on `127.0.0.1:8080` and WebWolf on `:9090`
- the official DVWA continuous image on `127.0.0.1:4280`; DVWA documents this
  as a current-branch image rather than a versioned release, so review its
  digest before a reproducibility-sensitive run
- Sentinel's no-root, read-only LLM echo fixture on `127.0.0.1:4010`

crAPI is intentionally not duplicated here because its official deployment is
a coordinated multi-service stack. Run a reviewed release of the
[official crAPI deployment](https://github.com/OWASP/crAPI) separately, bind it
to loopback, and place only that address in the engagement scope.

Never expose these deliberately vulnerable services on `0.0.0.0`, a shared
LAN, or a public interface.
