import { describe, it, expect, suite, beforeAll } from 'vitest';
import { createWindowWithScripts } from './setup-globals.js';
import vm from 'vm';

describe('Kerberos simulation (kerberos_lib.js + kdc_service.js)', () => {

    const window = createWindowWithScripts(
        '../src/lib/packets_lib.js',
        '../src/lib/kerberos_lib.js',
        '../src/services/kdc_service.js',
    );

    //top-level `const`/`class` declarations are lexically scoped in the vm context and
    //do not become properties of the global object, so re-expose them explicitly
    beforeAll(() => {
        vm.runInContext(`
            globalThis.__krb = {
                kerberosPrincipalDatabase,
                kerberosServiceDatabase,
                seedKerberosDatabase,
                getKdcMasterKey,
                mockKerberosEncrypt,
                mockKerberosDecrypt,
                kerberosDeserialize,
                serializeKerberosPacket,
                deserializeKerberosPacket,
                AsReq,
                AsRep,
                TgsReq,
                TgsRep,
                handleKerberosAsRequest,
                handleKerberosTgsRequest,
                KRB_AS_REQ,
                KRB_TGS_REQ,
                KRB_AS_REP,
                KRB_TGS_REP,
                KDC_ERR_C_PRINCIPAL_UNKNOWN,
                KDC_ERR_S_PRINCIPAL_UNKNOWN,
                KRB_ERR_GENERIC,
            };
        `, window);
    });

    const ctxt = () => window.__krb;

    suite('message type constants', () => {

        it('should match the RFC 4120 msg-type numbering', () => {
            const krb = ctxt();
            expect(krb.KRB_AS_REQ).toBe(10);
            expect(krb.KRB_AS_REP).toBe(11);
            expect(krb.KRB_TGS_REQ).toBe(12);
            expect(krb.KRB_TGS_REP).toBe(13);
        });

    });

    suite('seedKerberosDatabase()', () => {

        it('should register the krbtgt master key and demo principals', () => {
            const krb = ctxt();
            krb.seedKerberosDatabase('PACKETTRINO.EDU');
            expect(krb.kerberosServiceDatabase.has('krbtgt/PACKETTRINO.EDU@PACKETTRINO.EDU')).toBe(true);
            expect(krb.kerberosServiceDatabase.has('HTTP/webserver@PACKETTRINO.EDU')).toBe(true);
            expect(krb.kerberosPrincipalDatabase.has('alice@PACKETTRINO.EDU')).toBe(true);
        });

        it('should not duplicate registry entries when called twice', () => {
            const krb = ctxt();
            krb.seedKerberosDatabase('PACKETTRINO.EDU');
            expect(krb.kerberosServiceDatabase.get('HTTP/webserver@PACKETTRINO.EDU').password).toBe('nginx-webserver-key');
        });

    });

    suite('mock cipher', () => {

        it('should round-trip a plaintext through mockKerberosEncrypt/Decrypt', () => {
            const krb = ctxt();
            const cipher = krb.mockKerberosEncrypt('alice@PACKETTRINO.EDU', 'keymaterial');
            expect(cipher.startsWith('KRBM1:')).toBe(true);
            expect(krb.mockKerberosDecrypt(cipher, 'keymaterial')).toBe('alice@PACKETTRINO.EDU');
        });

        it('should throw when the blob is malformed or the key differs', () => {
            const krb = ctxt();
            expect(() => krb.mockKerberosDecrypt('DEADBEEF', 'keymaterial')).toThrow();
            expect(() => krb.mockKerberosDecrypt('KRBM1:ZZ', 'keymaterial')).toThrow();
        });

    });

    suite('packet serialization', () => {

        it('should serialize a KRB_AS_REQ into JSON and restore it as a typed packet', () => {
            const krb = ctxt();
            const request = new krb.AsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "alice", "PACKETTRINO.EDU");
            const json = krb.serializeKerberosPacket(request);
            expect(typeof json).toBe('string');
            const restored = krb.deserializeKerberosPacket(json);
            expect(restored.cname).toBe('alice');
            expect(restored.realm).toBe('PACKETTRINO.EDU');
            expect(restored.dport).toBe('88');
        });

        it('should throw when a required schema field is missing', () => {
            const krb = ctxt();
            const broken = new krb.TgsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "", "", "PACKETTRINO.EDU");
            broken.tgtCipher = "some-blob";
            broken.sname = ""; //<-- SPN is a required field of KRB_TGS_REQ
            expect(() => krb.serializeKerberosPacket(broken)).toThrow(/sname/);
        });

    });

    suite('AS exchange (handleKerberosAsRequest)', () => {

        it('should return an AS-REP with a decryptable TGT and session key for a known principal', async () => {
            const krb = ctxt();
            const request = new krb.AsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "alice", "PACKETTRINO.EDU");
            const reply = await krb.handleKerberosAsRequest('kdc-0', request, "192.168.1.1", "aa:bb:cc:dd:ee:02", "PACKETTRINO.EDU");

            expect(reply).toBeInstanceOf(krb.AsRep);

            const masterKey = krb.getKdcMasterKey('PACKETTRINO.EDU');
            const tgt = krb.kerberosDeserialize(krb.mockKerberosDecrypt(reply.tgtCipher, masterKey));
            expect(tgt.cname).toBe('alice');
            expect(tgt.session_key).toMatch(/^[0-9A-F]{16}$/);

            const sessionKey = krb.mockKerberosDecrypt(reply.sessionKeyCipher, 'wonderland'); //<-- derived from alice's password
            expect(sessionKey).toBe(tgt.session_key);
        });

        it('should return a KRB-ERROR with code 6 for an unknown principal', async () => {
            const krb = ctxt();
            const request = new krb.AsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "eve", "PACKETTRINO.EDU");
            const reply = await krb.handleKerberosAsRequest('kdc-0', request, "192.168.1.1", "aa:bb:cc:dd:ee:02", "PACKETTRINO.EDU");

            expect(reply.type).toBe('reply');
            expect(reply.error_code).toBe(krb.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        });

    });

    suite('TGS exchange (handleKerberosTgsRequest)', () => {

        it('should issue a service ticket encrypted with the service private key', async () => {
            const krb = ctxt();

            const asRequest = new krb.AsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "alice", "PACKETTRINO.EDU");
            const asReply = await krb.handleKerberosAsRequest('kdc-0', asRequest, "192.168.1.1", "aa:bb:cc:dd:ee:02", "PACKETTRINO.EDU");

            const masterKey = krb.getKdcMasterKey('PACKETTRINO.EDU');
            const tgt = krb.kerberosDeserialize(krb.mockKerberosDecrypt(asReply.tgtCipher, masterKey));

            const tgsRequest = new krb.TgsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", asReply.tgtCipher, "HTTP/webserver@PACKETTRINO.EDU", "PACKETTRINO.EDU");
            const tgsReply = await krb.handleKerberosTgsRequest('kdc-0', tgsRequest, "192.168.1.1", "aa:bb:cc:dd:ee:02", "PACKETTRINO.EDU");

            expect(tgsReply).toBeInstanceOf(krb.TgsRep);

            const serviceTicket = krb.kerberosDeserialize(krb.mockKerberosDecrypt(tgsReply.serviceTicketCipher, 'nginx-webserver-key')); //<-- the SPN private key
            expect(serviceTicket.cname).toBe('alice');
            expect(serviceTicket.sname).toBe('HTTP/webserver@PACKETTRINO.EDU');

            const sessionKey = krb.mockKerberosDecrypt(tgsReply.sessionKeyCipher, tgt.session_key); //<-- wrapped with the TGT session key
            expect(sessionKey).toBe(serviceTicket.session_key);
        });

        it('should return a KRB-ERROR with code 7 for an unknown SPN', async () => {
            const krb = ctxt();

            const asRequest = new krb.AsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "alice", "PACKETTRINO.EDU");
            const asReply = await krb.handleKerberosAsRequest('kdc-0', asRequest, "192.168.1.1", "aa:bb:cc:dd:ee:02", "PACKETTRINO.EDU");

            const tgsRequest = new krb.TgsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", asReply.tgtCipher, "HTTP/ghost@PACKETTRINO.EDU", "PACKETTRINO.EDU");
            const tgsReply = await krb.handleKerberosTgsRequest('kdc-0', tgsRequest, "192.168.1.1", "aa:bb:cc:dd:ee:02", "PACKETTRINO.EDU");

            expect(tgsReply.type).toBe('reply');
            expect(tgsReply.error_code).toBe(krb.KDC_ERR_S_PRINCIPAL_UNKNOWN);
        });

        it('should return a generic KRB-ERROR for an undecryptable TGT', async () => {
            const krb = ctxt();

            const tgsRequest = new krb.TgsReq("192.168.1.10", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "KRBM1:DEAD", "HTTP/webserver@PACKETTRINO.EDU", "PACKETTRINO.EDU");
            const tgsReply = await krb.handleKerberosTgsRequest('kdc-0', tgsRequest, "192.168.1.1", "aa:bb:cc:dd:ee:02", "PACKETTRINO.EDU");

            expect(tgsReply.error_code).toBe(krb.KRB_ERR_GENERIC);
        });

    });

})
