import { describe, it, expect, suite, beforeAll } from 'vitest';
import { createWindowWithScripts } from './setup-globals.js';
import vm from 'vm';

describe('Kerberos client (kerberos_util.js)', () => {

    const window = createWindowWithScripts(
        './stubs-kerberos.js',
        '../src/env.js',
        '../src/lib/network_lib.js',
        '../src/lib/packets_lib.js',
        '../src/lib/kerberos_lib.js',
        '../src/services/kdc_service.js',
        '../src/utilities/kerberos_util.js',
    );

    //expose top-level lexical declarations (const/class) to the tests, same trick as kerberos.spec.js
    beforeAll(() => {
        vm.runInContext(`
            globalThis.__krb = {
                getTicketCache,
                setTicketCache,
                isKerberosTicketValid,
                purgeExpiredKerberosTickets,
                findValidKerberosTicket,
                buildKerberosSpn,
                getKerberosDefaultPrincipal,
                discoverKdcIp,
                authenticateKerberos,
                acquireKerberosServiceTicket,
                packageKerberosApReq,
                negotiateKerberosApReq,
                kerberosDeserialize,
                mockKerberosDecrypt,
                kerberosTicketRegistry,
                seedKerberosDatabase,
                KRB_AS_REP,
                KRB_TGS_REP,
                ApReq,
            };

            //a client PC (with the Phase 2 ticket-cache attribute) and a running KDC

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

            seedKerberosDatabase("PACKETTRINO.EDU");
        `, window);
    });

    const ctxt = () => window.__krb;
    const NOW = Math.floor(Date.now() / 1000);

    suite('ticket cache plumbing', () => {

        it('should read an empty cache as an empty array', () => {
            expect(ctxt().getTicketCache('pc-test')).toEqual([]);
        });

        it('should round-trip entries through the persistent attribute', () => {
            const krb = ctxt();
            krb.setTicketCache('pc-test', [{"principal": "alice@PACKETTRINO.EDU", "spn": "krbtgt/x"}]);
            expect(krb.getTicketCache('pc-test')[0].principal).toBe('alice@PACKETTRINO.EDU');
            expect(window.document.getElementById('pc-test').getAttribute('ticket-cache')).toContain('krbtgt/x');
        });

        it('should validate tickets against their start/end timestamps', () => {
            const krb = ctxt();
            const freshTicket = {"start_time": NOW - 10, "end_time": NOW + 3600, "ticket_cipher": "KRBM1:AA"};
            const futureTicket = {"start_time": NOW + 100, "end_time": NOW + 3600, "ticket_cipher": "KRBM1:AA"};
            const expiredTicket = {"start_time": NOW - 7200, "end_time": NOW - 3600, "ticket_cipher": "KRBM1:AA"};
            const malformedTicket = {"start_time": NOW - 10, "end_time": NOW + 3600}; //<-- no ticket blob

            expect(krb.isKerberosTicketValid(freshTicket, NOW)).toBe(true);
            expect(krb.isKerberosTicketValid(futureTicket, NOW)).toBe(false); //<-- start time not yet reached
            expect(krb.isKerberosTicketValid(expiredTicket, NOW)).toBe(false); //<-- end time reached: must not be reused
            expect(krb.isKerberosTicketValid(malformedTicket, NOW)).toBe(false);
        });

        it('should purge only expired entries', () => {
            const krb = ctxt();
            krb.setTicketCache('pc-test', [
                {"principal": "alive", "start_time": NOW - 10, "end_time": NOW + 3600, "ticket_cipher": "KRBM1:AA"},
                {"principal": "dead", "start_time": NOW - 7200, "end_time": NOW - 3600, "ticket_cipher": "KRBM1:AA"},
            ]);

            expect(krb.purgeExpiredKerberosTickets('pc-test', NOW)).toBe(1);
            const cache = krb.getTicketCache('pc-test');
            expect(cache).toHaveLength(1);
            expect(cache[0].principal).toBe('alive');
        });

    });

    suite('kinit (AS exchange client half)', () => {

        it('should authenticate and store a valid TGT for the correct password', async () => {
            const krb = ctxt();
            const tgtEntry = await krb.authenticateKerberos('pc-test', 'alice', 'wonderland'); //<-- alice's seeded mocked credentials

            expect(tgtEntry.principal).toBe('alice@PACKETTRINO.EDU');
            expect(tgtEntry.spn).toBe('krbtgt/PACKETTRINO.EDU@PACKETTRINO.EDU');
            expect(tgtEntry.kdc_ip).toBe('192.168.1.1');
            expect(tgtEntry.session_key).toMatch(/^[0-9A-F]{16}$/);
            expect(tgtEntry.end_time).toBeGreaterThan(tgtEntry.start_time);
            expect(tgtEntry.ticket_cipher.startsWith('KRBM1:')).toBe(true);

            const cached = krb.findValidKerberosTicket('pc-test', 'krbtgt/PACKETTRINO.EDU@PACKETTRINO.EDU');
            expect(cached.session_key).toBe(tgtEntry.session_key);

            const kdcMasterKey = ctxt().mockKerberosDecrypt(tgtEntry.ticket_cipher, 'kdc-master-key-packettrino.edu'); //<-- the blob stays opaque to the client; decrypting with the server master key proves issuance
            const tgt = krb.kerberosDeserialize(kdcMasterKey);
            expect(tgt.cname).toBe('alice');
            expect(tgt.session_key).toBe(tgtEntry.session_key); //<-- server-minted key equals the client-held key
        });

        it('should reject a wrong password', async () => {
            await expect(ctxt().authenticateKerberos('pc-test', 'alice', 'wrong-password')).rejects.toThrow(/password/i);
        });

        it('should throw with the KRB-ERROR message for unknown principals', async () => {
            await expect(ctxt().authenticateKerberos('pc-test', 'eve', 'anything')).rejects.toThrow(/eve@PACKETTRINO.EDU/);
        });

    });

    suite('automatic TGS + AP-REQ wiring (HTTP client flow)', () => {

        it('should acquire a service ticket via TGS exchange when a TGT is cached', async () => {
            const krb = ctxt();
            await krb.authenticateKerberos('pc-test', 'alice', 'wonderland'); //<-- kinit first

            const stEntry = await krb.acquireKerberosServiceTicket('pc-test', 'HTTP/webserver@PACKETTRINO.EDU');

            expect(stEntry.principal).toBe('alice@PACKETTRINO.EDU');
            expect(stEntry.spn).toBe('HTTP/webserver@PACKETTRINO.EDU');
            expect(stEntry.session_key).toMatch(/^[0-9A-F]{16}$/);

            const serviceTicket = krb.kerberosDeserialize(krb.mockKerberosDecrypt(stEntry.ticket_cipher, 'nginx-webserver-key'));
            expect(serviceTicket.session_key).toBe(stEntry.session_key); //<-- server-minted key equals client-held key
        });

        it('should reuse a cached valid service ticket instead of firing a new TGS-REQ', async () => {
            const krb = ctxt();

            const first = await krb.acquireKerberosServiceTicket('pc-test', 'HTTP/webserver@PACKETTRINO.EDU');

            //capture the client-side registry size: reuse must not create a new KDC-side ticket
            const registrySizeBefore = krb.kerberosTicketRegistry.size;

            const second = await krb.acquireKerberosServiceTicket('pc-test', 'HTTP/webserver@PACKETTRINO.EDU');

            expect(second).toStrictEqual(first); //<-- same cached entry values (re-read from the persistent cache)
            expect(krb.kerberosTicketRegistry.size).toBe(registrySizeBefore);
        });

        it('should refuse to TGS without a TGT', async () => {
            const krb = ctxt();
            krb.setTicketCache('pc-test', []); //<-- kdestroy
            await expect(krb.acquireKerberosServiceTicket('pc-test', 'HTTP/webserver@PACKETTRINO.EDU')).rejects.toThrow(/kinit/);
        });

        it('should package a cached service ticket into an AP-REQ with a session-key authenticator', async () => {
            const krb = ctxt();

            await krb.authenticateKerberos('pc-test', 'alice', 'wonderland'); //<-- ensure a TGT after the kdestroy test above
            const stEntry = await krb.acquireKerberosServiceTicket('pc-test', 'HTTP/webserver@PACKETTRINO.EDU');
            const apRequest = krb.packageKerberosApReq('pc-test', stEntry, '192.168.1.50');

            expect(apRequest).toBeInstanceOf(krb.ApReq);
            expect(apRequest.destination_ip).toBe("192.168.1.50");
            expect(apRequest.serviceTicketCipher).toBe(stEntry.ticket_cipher); //<-- the ticket left untouched by the client

            expect(apRequest.authenticatorCipher.startsWith('KRBM1:')).toBe(true);
            const authenticator = krb.kerberosDeserialize(krb.mockKerberosDecrypt(apRequest.authenticatorCipher, stEntry.session_key));
            expect(authenticator.cname).toBe('alice@PACKETTRINO.EDU');
            expect(authenticator.sname).toBe('HTTP/webserver@PACKETTRINO.EDU');
        });

        it('negotiateKerberosApReq should stay out of the way when not authenticated (plain HTTP)', async () => {
            const krb = ctxt();
            krb.setTicketCache('pc-test', []); //<-- never kinit'ed
            expect(await krb.negotiateKerberosApReq('pc-test', 'webserver', '192.168.1.50')).toBe(null);
        });

        it('negotiateKerberosApReq should produce an AP-REQ end-to-end after kinit', async () => {
            const krb = ctxt();

            await krb.authenticateKerberos('pc-test', 'alice', 'wonderland');
            const apRequest = await krb.negotiateKerberosApReq('pc-test', 'webserver', '192.168.1.50');

            expect(apRequest).toBeInstanceOf(krb.ApReq); //<-- ready to ride on the HTTP packet in Phase 3

            const cachedAgain = krb.findValidKerberosTicket('pc-test', 'HTTP/webserver@PACKETTRINO.EDU');
            expect(cachedAgain).not.toBe(null); //<-- and the service ticket is now cached for later requests
        });

    });

})
