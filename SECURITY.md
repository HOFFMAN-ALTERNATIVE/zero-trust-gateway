# Security

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability" button on this repository (Security tab). I aim to reply within 72 hours. Please do not open public issues for exploitable bugs; an auth bypass in a gateway is exploitable by definition.

## Threat model

The full threat model, with the test that covers each mitigation, is in the [README](README.md#threat-model). In short:

- **Assets:** upstream data and actions, session cookies, signing and session keys.
- **Actors:** unauthenticated internet clients, authenticated users reaching beyond their rights, anything else on the internal network.
- **Entry points:** public listener (routed traffic, `/_ztg/*` login endpoints), admin listener (`/metrics`, probes), the IdP's JWKS, configuration and SIGHUP reloads.
- **Top risks:** token forgery and algorithm confusion, login CSRF and open redirects, identity header spoofing, path tricks that escape a route, lateral movement to upstreams. Each is mitigated and tested.

## Deployment expectations

- Terminate public TLS in front of the gateway and set `trusted_proxy: true` only when that hop is the only way in.
- Keep the admin port (metrics, probes) off the public network.
- Session keys and client secrets come from the environment, never from the YAML file in the repository.
- `mockidp` and `devca` are development tools. Never expose them.
- Rate limiting is not built in; put a limiter in front of the gateway.
