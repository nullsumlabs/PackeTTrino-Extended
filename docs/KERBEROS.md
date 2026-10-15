# Kerberos (KRB5) Simulation

PackeTTrino simulates the Kerberos v5 protocol (RFC 4120): AS Exchange, TGS Exchange, and AP Exchange, all over simulated UDP port 88. Default realm: `PACKETTRINO.EDU`.

## Components

- **KDC server** — install `krb5-kdc` on any PC (`apt install krb5-kdc`), then start the service from its advanced options (KDC button / `systemctl start kdc`). Seeded principals: `alice@PACKETTRINO.EDU` (`wonderland`), `bob@PACKETTRINO.EDU` (`buildercar`), and the `HTTP/webserver` service.
- **Kerberos client** — every PC has a ticket cache (`kinit`, `klist`, `kdestroy` in the terminal). `kinit alice@PACKETTRINO.EDU` performs the AS Exchange (wrong password = no session key); the TGT and later service tickets are cached on the device with real validity windows.
- **Nginx web server** — install `nginx` (`apt install nginx`). Its service key is held locally on the server; register `Kerberos Authentication Required` in its advanced options to gate page serving behind a KRB_AP_REQ.

## Usage

1. Start a KDC and enable the service.
2. On a client PC: `kinit alice@PACKETTRINO.EDU` (password `wonderland`), then `klist` to inspect the cache.
3. On the web server: install `nginx`, start it, and toggle `Kerberos Authentication Required`.
4. From the client, fetch the server (browser or `curl`). If a TGT exists, the client automatically performs the TGS Exchange and attaches a KRB_AP_REQ; the server validates SPN, principal, ticket lifetime, client address (`caddr`), and authenticator clock skew (300 s) before serving:
   - Valid → `200 OK` (the packet analyzer shows the authenticated principal).
   - No/expired ticket or bad AP-REQ → `401 Unauthorized: Kerberos` challenge.
5. Skip authentication with `kdestroy` to see the `401` challenge and graceful downgrade to plain HTTP.

## Notes

- Tickets expire per their lease and are never reused past `end_time`; a fresh TGS-REQ is minted on expiry.
- Packets are color-coded and analyzable: watch AS-REQ/AS-REP and TGS-REQ/TGS-REP flow between client, KDC, and server.
- Authenticator replay protection is not yet implemented.
