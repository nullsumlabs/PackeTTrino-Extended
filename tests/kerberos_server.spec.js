import { describe, it, expect, suite, beforeAll } from 'vitest';
import { createWindowWithScripts } from './setup-globals.js';
import vm from 'vm';

describe('Nginx AP exchange (nginx_service.js)', () => {

    const window = createWindowWithScripts(
        './stubs-kerberos.js',
        '../src/env.js',
        '../src/lib/network_lib.js',
        '../src/lib/packets_lib.js',
        '../src/lib/kerberos_lib.js',
        '../src/lib/fileSystem_lib.js',
        '../src/lib/apache2_lib.js',
        '../src/services/kdc_service.js',
        '../src/utilities/kerberos_util.js',
        '../src/packages/nginx_pkg.js',
        '../src/services/nginx_service.js',
    );

    //expose top-level lexical declarations (const/class) to the tests, same trick as the other suites
    beforeAll(() => {
        vm.runInContext(`
            globalThis.__krb = {
                seedKerberosDatabase,
                authenticateKerberos,
                acquireKerberosServiceTicket,
                packageKerberosApReq,
                negotiateKerberosApReq,
                getTicketCache,
                setTicketCache,
                nginx_service,
                validateKerberosApReq,
                toggleNginxKerberosRequired,
                installNginx,
                serializeKerberosPacket,
                deserializeKerberosPacket,
                kerberosSerialize,
                kerberosDeserialize,
                mockKerberosEncrypt,
                mockKerberosDecrypt,
                generateSessionKey,
                httpRequest,
                ApReq,
            };

            //test topology: client PC + running KDC + Nginx web server

            const $client = document.createElement("article");
            $client.id = "pc-test";
            $client.classList.add("item-dropped", "pc");
            $client.setAttribute("ip-enp0s3", "192.168.1.10");
            $client.setAttribute("netmask-enp0s3", "255.255.255.0");
            $client.setAttribute("mac-enp0s3", "aa:bb:cc:dd:ee:01");
            $client.setAttribute("ticket-cache", "[]");
            document.body.appendChild($client);

            const $kdc = document.createElement("article");
            $kdc.id = "dns-server-test";
            $kdc.classList.add("item-dropped", "dns-server");
            $kdc.setAttribute("ip-enp0s3", "192.168.1.1");
            $kdc.setAttribute("netmask-enp0s3", "255.255.255.0");
            $kdc.setAttribute("mac-enp0s3", "aa:bb:cc:dd:ee:02");
            $kdc.setAttribute("kdc", "true"); //<-- systemctl start kdc
            $kdc.setAttribute("krb5-realm", "PACKETTRINO.EDU");
            document.body.appendChild($kdc);

            const $nginx = document.createElement("article");
            $nginx.id = "pc-webserver";
            $nginx.classList.add("item-dropped", "pc");
            $nginx.setAttribute("ip-enp0s3", "192.168.1.50");
            $nginx.setAttribute("netmask-enp0s3", "255.255.255.0");
            $nginx.setAttribute("mac-enp0s3", "aa:bb:cc:dd:ee:50");
            //empty virtual filesystem like a fresh device; the nginx directories are
            //pre-created because the vm harness is cross-realm: instanceof Object fails
            //for object literals minted inside vm scripts, and the installer relies on it
            $nginx.setAttribute("filesystem", JSON.stringify({
                "/": {
                    "bin": {},
                    "dev": {},
                    "etc": {"nginx": {"sites": {}}},
                    "home": {},
                    "var": {"www": {"nginx": {}}}
                }
            }));
            document.body.appendChild($nginx);

            installNginx($nginx); //<-- also registers HTTP/webserver@PACKETTRINO.EDU with the local key
            $nginx.setAttribute("krb5-required", "true"); //<-- the "Kerberos Authentication Required" toggle ON

            //the site config was written by the installer; override the DOMParser-based
            //reader (browser-only) with an equivalent extractor for the vm harness
            parseNginxConf = function (networkObjectId) {
                return {"ip": "0.0.0.0", "port": "80", "documentRoot": "/var/www/nginx", "directoryIndex": "index.html", "serverName": null};
            };

            seedKerberosDatabase("PACKETTRINO.EDU");
        `, window);
    });

    const ctxt = () => window.__krb;
    const NOW = Math.floor(Date.now() / 1000);
    const SPN = 'HTTP/webserver@PACKETTRINO.EDU';

    /**
     * Reads the current session key of the cached service ticket for the SPN (the client's copy).
     */
    const cachedSessionKey = (krb, spn) => {
        const entry = krb.getTicketCache('pc-test').find(t => t.spn === spn);
        if (!entry) throw new Error('no cached ticket for ' + spn);
        return entry.session_key;
    };

    /**
     * Builds an HTTP request packet for the webserver, optionally carrying a serialized AP-REQ.
     */
    const buildHttpRequest = (krb, apRequest = null) => {
        const request = new krb.httpRequest("192.168.1.10", "192.168.1.50", "aa:bb:cc:dd:ee:01", "", 54321, 80, "GET", "webserver", "");
        if (apRequest) request.kerberosApReq = krb.serializeKerberosPacket(apRequest);
        return request;
    };

    suite('server configuration', () => {

        it('installNginx should bind the SPN and hold the private service key locally', () => {
            const $nginx = window.document.getElementById('pc-webserver');
            expect($nginx.getAttribute('krb5-spn')).toBe(SPN);
            expect($nginx.getAttribute('krb5-key')).toBe('nginx-webserver-key');
            expect($nginx.getAttribute('krb5-required')).toBe('true');
        });

        it('toggleNginxKerberosRequired should flip the toggle off and on', async () => {
            const krb = ctxt();

            krb.toggleNginxKerberosRequired('pc-webserver');
            const $nginx = window.document.getElementById('pc-webserver');
            expect($nginx.getAttribute('krb5-required')).toBe('false');

            //with the toggle off, an unauthenticated request is served (no interception)
            const reply = await krb.nginx_service('pc-webserver', buildHttpRequest(krb));
            expect(reply.statusCode).toBe(200);

            krb.toggleNginxKerberosRequired('pc-webserver');
            expect($nginx.getAttribute('krb5-required')).toBe('true');
        });

    });

    suite('AP exchange: unauthenticated interception', () => {

        it('should return a 401 Kerberos challenge for a request without an AP-REQ', async () => {
            const reply = await ctxt().nginx_service('pc-webserver', buildHttpRequest(ctxt()));

            expect(reply.statusCode).toBe(401);
            expect(reply.challenge).toBe('WWW-Authenticate: Kerberos');
            expect(reply.body).toMatch(/kinit/);
        });

        it('should return a 401 challenge for an unparseable or wrong msg-type AP payload', async () => {
            const krb = ctxt();

            const garbage = buildHttpRequest(krb);
            garbage.kerberosApReq = "not-a-kerberos-packet";
            const parseReply = await krb.nginx_service('pc-webserver', garbage);
            expect(parseReply.statusCode).toBe(401);
            expect(parseReply.body).toMatch(/cannot be parsed/);

            //a KRB-ERROR (30) serialized in the attachment is not a KRB_AP_REQ
            const wrongType = buildHttpRequest(krb);
            wrongType.kerberosApReq = JSON.stringify({"krb_msg_type": 30, "error_code": 0, "e_text": "x", "origin_ip": "", "destination_ip": "", "origin_mac": "", "destination_mac": "", "type": "reply"});
            const typeReply = await krb.nginx_service('pc-webserver', wrongType);
            expect(typeReply.statusCode).toBe(401);
            expect(typeReply.body).toMatch(/not a KRB_AP_REQ/);
        });

    });

    suite('AP exchange: ticket decryption & validation', () => {

        it('should reject a ticket that does not decrypt with the server private key', async () => {
            const krb = ctxt();
            const $nginx = window.document.getElementById('pc-webserver');
            const originalKey = $nginx.getAttribute('krb5-key');

            await krb.authenticateKerberos('pc-test', 'alice', 'wonderland');
            const stEntry = await krb.acquireKerberosServiceTicket('pc-test', SPN);
            const apRequest = krb.packageKerberosApReq('pc-test', stEntry, '192.168.1.50');

            $nginx.setAttribute('krb5-key', 'a-different-key'); //<— key-swap tampering scenario

            const validation = krb.validateKerberosApReq('pc-webserver', apRequest, {origin_ip: '192.168.1.10'});

            $nginx.setAttribute('krb5-key', originalKey); //<-- restore

            expect(validation.ok).toBe(false);
            expect(validation.reason).toMatch(/decrypted/);
        });

        it('should reject a ticket minted for a different SPN', async () => {
            const krb = ctxt();
            const $nginx = window.document.getElementById('pc-webserver');

            await krb.authenticateKerberos('pc-test', 'alice', 'wonderland');
            const stEntry = await krb.acquireKerberosServiceTicket('pc-test', SPN);
            const apRequest = krb.packageKerberosApReq('pc-test', stEntry, '192.168.1.50');

            $nginx.setAttribute('krb5-spn', 'HTTP/ghost@PACKETTRINO.EDU');
            const validation = krb.validateKerberosApReq('pc-webserver', apRequest, {origin_ip: '192.168.1.10'});
            $nginx.setAttribute('krb5-spn', SPN); //<-- restore

            expect(validation.ok).toBe(false);
            expect(validation.reason).toMatch(/HTTP\/ghost/);
        });

        it('should reject a ticket whose network address does not match the client', async () => {
            const krb = ctxt();

            await krb.authenticateKerberos('pc-test', 'alice', 'wonderland');
            const stEntry = await krb.acquireKerberosServiceTicket('pc-test', SPN);
            const apRequest = krb.packageKerberosApReq('pc-test', stEntry, '192.168.1.50');

            const validation = krb.validateKerberosApReq('pc-webserver', apRequest, {origin_ip: '10.9.9.9'}); //<-- ticket was issued to 192.168.1.10

            expect(validation.ok).toBe(false);
            expect(validation.reason).toMatch(/network address/);
        });

        it('should reject an expired ticket and an authenticator outside the clock-skew window', async () => {
            const krb = ctxt();
            const sessionKey = krb.generateSessionKey();

            const expiredTicket = {
                "version": 1,
                "cname": "alice@PACKETTRINO.EDU",
                "sname": SPN,
                "session_key": sessionKey,
                "issued": NOW - 7200,
                "expiry": NOW - 3600, //<-- expired an hour ago
                "caddr": "192.168.1.10"
            };

            const apRequest = new krb.ApReq("192.168.1.10", "192.168.1.50", "", "",
                krb.mockKerberosEncrypt(krb.kerberosSerialize(expiredTicket), 'nginx-webserver-key'),
                krb.mockKerberosEncrypt(krb.kerberosSerialize({"version": 1, "cname": "alice@PACKETTRINO.EDU", "timestamp": NOW}), sessionKey),
                "PACKETTRINO.EDU"
            );

            const validation = krb.validateKerberosApReq('pc-webserver', apRequest, {origin_ip: '192.168.1.10'}, NOW);

            expect(validation.ok).toBe(false);
            expect(validation.reason).toMatch(/validity window/);

            //fresh ticket but ancient authenticator (over the 300s skew) must also fail

            const freshTicket = {...expiredTicket, "issued": NOW - 60, "expiry": NOW + 3600};
            const skewedRequest = new krb.ApReq("192.168.1.10", "192.168.1.50", "", "",
                krb.mockKerberosEncrypt(krb.kerberosSerialize(freshTicket), 'nginx-webserver-key'),
                krb.mockKerberosEncrypt(krb.kerberosSerialize({"version": 1, "cname": "alice@PACKETTRINO.EDU", "timestamp": NOW - 1000}), sessionKey),
                "PACKETTRINO.EDU"
            );

            const skewedValidation = krb.validateKerberosApReq('pc-webserver', skewedRequest, {origin_ip: '192.168.1.10'}, NOW);

            expect(skewedValidation.ok).toBe(false);
            expect(skewedValidation.reason).toMatch(/clock skew/);
        });

        it('should reject an authenticator whose principal does not match the ticket', async () => {
            const krb = ctxt();
            const sessionKey = krb.generateSessionKey();

            const freshTicket = {
                "version": 1, "cname": "alice@PACKETTRINO.EDU", "sname": SPN,
                "session_key": sessionKey, "issued": NOW - 60, "expiry": NOW + 3600, "caddr": "192.168.1.10"
            };

            const apRequest = new krb.ApReq("192.168.1.10", "192.168.1.50", "", "",
                krb.mockKerberosEncrypt(krb.kerberosSerialize(freshTicket), 'nginx-webserver-key'),
                krb.mockKerberosEncrypt(krb.kerberosSerialize({"version": 1, "cname": "bob@PACKETTRINO.EDU", "timestamp": NOW}), sessionKey), //<-- wrong principal
                "PACKETTRINO.EDU"
            );

            const validation = krb.validateKerberosApReq('pc-webserver', apRequest, {origin_ip: '192.168.1.10'}, NOW);

            expect(validation.ok).toBe(false);
            expect(validation.reason).toMatch(/authenticator principal/);
        });

    });

    suite('full end-to-end chain', () => {

        it('kinit -> TGS-REQ -> http() with AP-REQ -> nginx validation -> 200 OK', async () => {
            const krb = ctxt();

            //1) kinit: the client obtains a TGT over the simulated port-88 exchange
            const tgtEntry = await krb.authenticateKerberos('pc-test', 'alice', 'wonderland');
            expect(tgtEntry.spn).toMatch(/^krbtgt\//);

            //2) the HTTP client wiring acquires the service ticket automatically (TGS-REQ/TGS-REP)
            const apRequest = await krb.negotiateKerberosApReq('pc-test', 'webserver', '192.168.1.50');
            expect(apRequest).not.toBe(null);

            //3) the AP-REQ rides on the HTTP request and Nginx grants access
            const request = buildHttpRequest(krb, apRequest);
            const reply = await krb.nginx_service('pc-webserver', request);

            expect(reply.statusCode).toBe(200);
            expect(reply.body).toMatch(/Welcome to nginx/);
            expect(reply.servedTo).toBe('alice'); //<-- validated client principal surfaced for the packet analyser

            //4) a valid authenticator is bound to the ticket's minted session key
            const authenticator = krb.kerberosDeserialize(krb.mockKerberosDecrypt(apRequest.authenticatorCipher, cachedSessionKey(krb, SPN)));
            expect(authenticator.cname).toBe('alice'); //<-- the authenticator cname is local to the realm, exactly the ticket's cname
        });

        it('an expired cached service ticket triggers automatic re-authentication (fresh TGS-REQ)', async () => {
            const krb = ctxt();

            const cache = krb.getTicketCache('pc-test');
            const oldSt = cache.find(t => t.spn === SPN);

            //age the cached service ticket past its expiry
            const agedCache = cache.map(t => (t.spn === SPN) ? {...t, "end_time": NOW - 1} : t);
            krb.setTicketCache('pc-test', agedCache);

            const apRequest = await krb.negotiateKerberosApReq('pc-test', 'webserver', '192.168.1.50'); //<-- cache miss: new TGS-REQ

            expect(apRequest).not.toBe(null);
            expect(apRequest.serviceTicketCipher).not.toBe(oldSt.ticket_cipher); //<-- a fresh ticket was minted

            const request = buildHttpRequest(krb, apRequest);
            const reply = await krb.nginx_service('pc-webserver', request);

            expect(reply.statusCode).toBe(200); //<-- and the new ticket validates at the server
        });

    });

})
