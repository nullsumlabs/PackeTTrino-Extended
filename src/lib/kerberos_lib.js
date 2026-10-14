/**
 * @fileoverview Kerberos v5 simulation library. Defines the wire schema and the
 * serialization/deserialization methods for the simulated AS Exchange (KRB_AS_REQ /
 * KRB_AS_REP), TGS Exchange (KRB_TGS_REQ / KRB_TGS_REP), and AP Exchange (KRB_AP_REQ)
 * messages per RFC 4120, a mocked in-memory principal database, and a mock symmetric
 * cipher used in place of real crypto (this is an educational simulation, not a
 * security library). Packet classes extend the base `packet` class from
 * `packets_lib.js`, so they flow through the standard `routing` /
 * `switchProcessor` / `packetProcessor_Host` machinery, and are dispatched on
 * **UDP port 88**.
 *
 * @see https://www.rfc-editor.org/rfc/rfc4120.html — The Kerberos Network
 *   Authentication Service (V5), Message Types (Section 7.5.1): KRB_AS_REQ = 10,
 *   KRB_AS_REP = 11, KRB_TGS_REQ = 12, KRB_TGS_REP = 13, KRB_AP_REQ = 14.
 */

/** @type {number} RFC 4120 msg-type code: request for initial authentication. */
const KRB_AS_REQ = 10;

/** @type {number} RFC 4120 msg-type code: response to KRB_AS_REQ. */
const KRB_AS_REP = 11;

/** @type {number} RFC 4120 msg-type code: request for a service ticket based on a TGT. */
const KRB_TGS_REQ = 12;

/** @type {number} RFC 4120 msg-type code: response to KRB_TGS_REQ. */
const KRB_TGS_REP = 13;

/** @type {number} RFC 4120 msg-type code: authentication request at the application server. */
const KRB_AP_REQ = 14;

/** @type {number} RFC 4120 msg-type code: generic error reply. */
const KRB_ERROR = 30;

/** @type {number} Default UDP port the KDC listens on, mirroring real Kerberos. */
const KDC_LISTEN_PORT = "88";

/** @type {number} Mock encryption type advertised in REP messages (AES256-CTS-HMAC-SHA1-96 in RFC 4120). */
const KRB5_ETYPE_AES256 = 18;

/** @type {number} RFC 4120 error code: client principal not found in the KDC database. */
const KDC_ERR_C_PRINCIPAL_UNKNOWN = 6;

/** @type {number} RFC 4120 error code: server (SPN) principal not found in the KDC database. */
const KDC_ERR_S_PRINCIPAL_UNKNOWN = 7;

/** @type {number} RFC 4120 error code: generic Kerberos failure (also used for undecryptable blobs in this simulation). */
const KRB_ERR_GENERIC = 30;

/** @type {string} Default realm used when a KDC is installed without an explicit realm. */
const $KRB5DEFAULTREALM = "PACKETTRINO.EDU";

/**
 * @description In-memory principal database mocked as a JavaScript Map, modelling the
 * MIT Kerberos database. Keys are full user principals (e.g. "alice@PACKETTRINO.EDU"),
 * each mapped to a plain-text password from which the client key is derived. Seeded
 * (see seedKerberosDatabase) with one user and the realm's `krbtgt` service, which
 * acts as the KDC master key material.
 * @type {Map<string, {password: string, realm: string}>}
 */
const kerberosPrincipalDatabase = new Map();

/**
 * @description In-memory service principal database mocked as a JavaScript Map.
 * Keys are full service principal names (e.g. "HTTP/webserver.packttrino.net@PACKETTRINO.EDU"),
 * each mapped to the service's private key password used to encrypt its service tickets.
 * @type {Map<string, {password: string, serviceClass: string, instance: string, realm: string}>}
 */
const kerberosServiceDatabase = new Map();

/**
 * @description Optional short-term cache of issued ticket-granting tickets keyed by a
 * synthetic TGT id. Mirrors the fact that real KDCs are stateless — this library
 * decrypts TGTs from their blob instead — but keeps a reference registry for the
 * packet-tracer view and future Phase-2 tooling. Keys are `${networkObjectId}-${xid}`.
 * @type {Map<string, Object>}
 */
const kerberosTicketRegistry = new Map();

/**
 * @description Global clock skew in seconds tolerated when validating authenticator and
 * ticket timestamps (RFC 4120 recommends five minutes).
 * @type {number}
 */
const $KRB5CLOCKSKEW = 300;

/**
 * Registers a user principal in the mock database.
 *
 * @param {string} username - Local user name (without realm), e.g. "alice".
 * @param {string} password - Mocked plain-text password; the client key is derived from it.
 * @param {string} [realm=$KRB5DEFAULTREALM] - Kerberos realm for the principal.
 * @returns {string} The full principal name that was registered (e.g. "alice@PACKETTRINO.EDU").
 */
function registerKerberosUser(username, password, realm = $KRB5DEFAULTREALM) {
    const principal = `${username}@${realm}`;
    kerberosPrincipalDatabase.set(principal, {
        password: password,
        realm: realm
    });
    return principal;
}

/**
 * Registers a service principal (SPN) in the mock database.
 *
 * @param {string} serviceClass - Service class, e.g. "HTTP".
 * @param {string} instance - Hostname of the service instance, e.g. "webserver".
 * @param {string} password - Service private key password, used to encrypt service tickets.
 * @param {string} [realm=$KRB5DEFAULTREALM] - Kerberos realm of the service.
 * @returns {string} The full service principal name that was registered (e.g. "HTTP/webserver@PACKETTRINO.EDU").
 */
function registerKerberosService(serviceClass, instance, password, realm = $KRB5DEFAULTREALM) {
    const spn = `${serviceClass}/${instance}@${realm}`;
    kerberosServiceDatabase.set(spn, {
        password: password,
        serviceClass: serviceClass,
        instance: instance,
        realm: realm
    });
    return spn;
}

/**
 * Looks up a user principal in the mock database.
 *
 * @param {string} principal - Full principal name, e.g. "alice@PACKETTRINO.EDU".
 * @returns {Object|undefined} The database record, or `undefined` if unknown.
 */
function getKerberosUser(principal) {
    return kerberosPrincipalDatabase.get(principal);
}

/**
 * Looks up a service principal (SPN) in the mock database.
 *
 * @param {string} spn - Full service principal name, e.g. "HTTP/webserver@PACKETTRINO.EDU".
 * @returns {Object|undefined} The database record, or `undefined` if unknown.
 */
function getKerberosService(spn) {
    return kerberosServiceDatabase.get(spn);
}

/**
 * Seeds the mock databases with the default realm content if it has not been seeded yet.
 *
 * Registers the `krbtgt` service (its password doubles as the KDC master key material),
 * two demo users, and the demo web-server SPN the webserver node will use in later
 * phases. Safe to call more than once; seeding is skipped when the `krbtgt` entry exists.
 *
 * @param {string} [realm=$KRB5DEFAULTREALM] - Realm to seed.
 * @returns {void}
 */
function seedKerberosDatabase(realm = $KRB5DEFAULTREALM) {

    if (kerberosServiceDatabase.has(`krbtgt/${realm}@${realm}`)) return; //<-- already seeded

    registerKerberosService("krbtgt", realm, "kdc-master-key-" + realm.toLowerCase(), realm);

    registerKerberosUser("alice", "wonderland", realm);
    registerKerberosUser("bob", "buildercar", realm);

    registerKerberosService("HTTP", "webserver", "nginx-webserver-key", realm);

}

/**
 * Returns the KDC master key material for a realm, derived from the `krbtgt` principal.
 *
 * @param {string} realm - Kerberos realm, e.g. "PACKETTRINO.EDU".
 * @returns {string} The master key password string.
 * @throws {Error} If the `krbtgt` principal has not been seeded into the database.
 */
function getKdcMasterKey(realm) {

    const krbtgt = kerberosServiceDatabase.get(`krbtgt/${realm}@${realm}`);

    if (!krbtgt) throw new Error(`Error: no krbtgt principal for realm ${realm}; seed the Kerberos database first.`);

    return krbtgt.password;

}

/**
 * Builds a full service principal name string.
 *
 * @param {string} serviceClass - Service class, e.g. "HTTP".
 * @param {string} instance - Service instance hostname, e.g. "webserver.packttrino.net".
 * @param {string} [realm=$KRB5DEFAULTREALM] - Kerberos realm.
 * @returns {string} The SPN string "serviceClass/instance@realm".
 */
function buildSpn(serviceClass, instance, realm = $KRB5DEFAULTREALM) {
    return `${serviceClass}/${instance}@${realm}`;
}

/**
 * Generates a random session key of the given length (hex characters).
 *
 * @param {number} [length=16] - Desired key length in hexadecimal characters.
 * @returns {string} A random hex string.
 */
function generateSessionKey(length = 16) {

    const hexCharacters = "0123456789ABCDEF";
    let key = "";

    for (let i = 0; i < length; i++) key += hexCharacters[Math.floor(Math.random() * hexCharacters.length)];

    return key;

}

/**
 * Mock-symmetrical "encryption": XORs the plaintext bytes against a repeating password
 * key and hex-encodes the result, prefixing the tag `KRBM1:` so a blob's provenance and
 * integrity of the encoding can be checked on decrypt. Cryptographically worthless by
 * design — it exists to model ticket blobs flowing around the simulation, not to be secure.
 *
 * @param {string} plaintext - The cleartext to protect (usually a serialized JSON payload).
 * @param {string} key - The locking key material (a principal's password or master key).
 * @returns {string} The "encrypted" blob in the form "KRBM1:<uppercase hex>".
 */
function mockKerberosEncrypt(plaintext, key) {

    let cipher = "";

    for (let i = 0; i < plaintext.length; i++) {
        const cipherByte = plaintext.charCodeAt(i) ^ key.charCodeAt(i % key.length);
        cipher += cipherByte.toString(16).padStart(2, "0"); //<-- hex-encode the transformed byte
    }

    return "KRBM1:" + cipher.toUpperCase();

}

/**
 * Reverses `mockKerberosEncrypt`, restoring the original plaintext.
 *
 * @param {string} blob - The output of `mockKerberosEncrypt`.
 * @param {string} key - The same key string the blob was locked with.
 * @returns {string} The decrypted plaintext.
 * @throws {Error} If the blob is malformed (missing KRBM1 tag or non-hex content) or the
 *   hex payload has an odd length.
 */
function mockKerberosDecrypt(blob, key) {

    if (typeof blob !== "string" || !blob.startsWith("KRBM1:")) throw new Error("Error: malformed Kerberos blob: missing KRBM1 tag.");

    const cipher = blob.slice("KRBM1:".length);

    if (cipher.length % 2 !== 0) throw new Error("Error: malformed Kerberos blob: odd hex length.");

    let plaintext = "";

    for (let i = 0; i < cipher.length; i += 2) {
        const cipherByte = parseInt(cipher.substring(i, i + 2), 16);
        if (Number.isNaN(cipherByte)) throw new Error("Error: malformed Kerberos blob: non-hex content.");
        plaintext += String.fromCharCode(cipherByte ^ key.charCodeAt((i / 2) % key.length));
    }

    return plaintext;

}

/**
 * Selectively serializes a packet-like object into JSON, omitting functions but keeping
 * all data fields. Used to move Kerberos message payloads as flat strings inside ticket
 * blobs and to build wire-format exchange payloads.
 *
 * @param {Object} value - Any JSON-safe value (primitives are rejected downstream by `kerberosDeserialize`).
 * @returns {string} The serialized JSON string.
 * @throws {Error} If the value cannot be JSON-serialized.
 */
function kerberosSerialize(value) {
    return JSON.stringify(value);
}

/**
 * Deserializes a JSON string produced by `kerberosSerialize` (or `JSON.stringify`),
 * validating that it parses into a plain object/array and defined message types.
 *
 * @param {string} json - The serialized payload string.
 * @returns {Object|Array} The parsed value.
 * @throws {Error} If the payload is not valid JSON or not an object/array.
 */
function kerberosDeserialize(json) {

    let value;

    try {
        value = JSON.parse(json);
    } catch (error) {
        throw new Error("Error: cannot deserialize Kerberos payload: invalid JSON.", {cause: error});
    }

    if (typeof value !== "object" || value === null) throw new Error("Error: cannot deserialize Kerberos payload: unexpected type.");

    return value;

}

/**
 * Validates that an object carries every required field.
 *
 * @param {Object} message - The candidate message object.
 * @param {Array<string>} requiredFields - Field names that must be present (non-empty).
 * @returns {void}
 * @throws {Error} If any required field is missing (mentioning the field name).
 */
function validateKerberosMessage(message, requiredFields) {

    const missing = requiredFields.filter(field => message[field] === undefined || message[field] === null || message[field] === "");

    if (missing.length > 0) throw new Error(`Error: invalid Kerberos message: missing field(s) ${missing.join(", ")}.`);

}

/**
 * @description Represents a Kerberos packet extending the base `packet` class with
 * transport-level addressing for the simulated UDP port 88 exchange. Actual message
 * semantics are on subclasses (`AsReq`, `AsRep`, `TgsReq`, `TgsRep`, `ApReq`,
 * `KerberosErrorPacket`).
 */
class kerberosPacket extends packet {
    /**
     * @param {string} origin_ip - Source IP address.
     * @param {string} destination_ip - Destination IP address.
     * @param {string} origin_mac - Source MAC address.
     * @param {string} destination_mac - Destination MAC address.
     * @param {number} msgType - RFC 4120 msg-type constant this packet models.
     */
    constructor(origin_ip, destination_ip, origin_mac, destination_mac, msgType) {
        super(origin_ip, destination_ip, origin_mac, destination_mac);
        this.transport_protocol = "udp";
        this.protocol = "kerberos";
        this.ttl = 64;
        this.dport = KDC_LISTEN_PORT;
        this.krb_msg_type = msgType;
        this.realm = "";
        this.cname = "";
        this.sname = "";
        this.etype = KRB5_ETYPE_AES256;
    }
}

/**
 * @description Represents a KRB_AS_REQ message: a client principal asking the KDC for an
 * initial TGT. Carried on an ephemeral UDP source port toward port 88.
 */
class AsReq extends kerberosPacket {
    /**
     * @param {string} origin_ip - Source IP address of the client.
     * @param {string} destination_ip - Destination KDC IP address.
     * @param {string} origin_mac - Source MAC address of the client.
     * @param {string} destination_mac - Destination MAC (can be "" and resolved en-route).
     * @param {string} cname - Client principal name without realm, e.g. "alice".
     * @param {string} realm - Target realm, e.g. "PACKETTRINO.EDU".
     */
    constructor(origin_ip, destination_ip, origin_mac, destination_mac, cname, realm) {
        super(origin_ip, destination_ip, origin_mac, destination_mac, KRB_AS_REQ);
        this.type = "request";
        this.sport = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152; //<-- ephemeral source port like dnsRequest
        this.cname = cname;
        this.realm = realm;
    }
}

/**
 * @description Represents a KRB_AS_REP message: the KDC's answer containing the mocked TGT
 * (encrypted with the KDC master key) and the client session key (encrypted with the
 * principal client key), plus the TGT lease.
 */
class AsRep extends kerberosPacket {
    /**
     * @param {string} origin_ip - Source IP address of the KDC.
     * @param {string} destination_ip - Destination client IP address.
     * @param {string} origin_mac - Source MAC address of the KDC.
     * @param {string} destination_mac - Destination MAC address of the client.
     * @param {string} cname - Client principal name without realm.
     * @param {string} realm - Target realm.
     */
    constructor(origin_ip, destination_ip, origin_mac, destination_mac, cname, realm) {
        super(origin_ip, destination_ip, origin_mac, destination_mac, KRB_AS_REP);
        this.type = "reply";
        this.sport = KDC_LISTEN_PORT;
        this.cname = cname;
        this.realm = realm;
        this.tgtCipher = ""; //<-- TGT blob serialized+encrypted with the KDC master key
        this.sessionKeyCipher = ""; //<-- client session key encrypted with the client key
        this.lease = 3600; //<-- TGT lease seconds
    }
}

/**
 * @description Represents a KRB_TGS_REQ message: the client presenting its TGT and the
 * requested SPN to the KDC asking for a service ticket.
 */
class TgsReq extends kerberosPacket {
    /**
     * @param {string} origin_ip - Source IP address of the client.
     * @param {string} destination_ip - Destination KDC IP address.
     * @param {string} origin_mac - Source MAC of the client.
     * @param {string} destination_mac - Destination MAC (can be "" and resolved en-route).
     * @param {string} tgtCipher - TGT blob obtained in the AS exchange.
     * @param {string} sname - Full SPN being requested, e.g. "HTTP/webserver@PACKETTRINO.EDU".
     * @param {string} realm - Target realm.
     */
    constructor(origin_ip, destination_ip, origin_mac, destination_mac, tgtCipher, sname, realm) {
        super(origin_ip, destination_ip, origin_mac, destination_mac, KRB_TGS_REQ);
        this.type = "request";
        this.sport = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152; //<-- ephemeral source port
        this.tgtCipher = tgtCipher;
        this.sname = sname;
        this.realm = realm;
    }
}

/**
 * @description Represents a KRB_TGS_REP message: the KDC's answer containing the service
 * ticket (encrypted with the target service's private key) and the client-service session
 * key (encrypted with the AS-exchange session key).
 */
class TgsRep extends kerberosPacket {
    /**
     * @param {string} origin_ip - Source IP address of the KDC.
     * @param {string} destination_ip - Destination client IP address.
     * @param {string} origin_mac - Source MAC address of the KDC.
     * @param {string} destination_mac - Destination MAC address of the client.
     * @param {string} sname - SPN of the issued service ticket.
     * @param {string} realm - Target realm.
     */
    constructor(origin_ip, destination_ip, origin_mac, destination_mac, sname, realm) {
        super(origin_ip, destination_ip, origin_mac, destination_mac, KRB_TGS_REP);
        this.type = "reply";
        this.sport = KDC_LISTEN_PORT;
        this.sname = sname;
        this.realm = realm;
        this.serviceTicketCipher = ""; //<-- service ticket blob encrypted with the service key
        this.sessionKeyCipher = ""; //<-- client-service session key, encrypted with the AS session key
        this.lease = 3600; //<-- service ticket lease seconds
    }
}

/**
 * @description Represents a KRB_AP_REQ message: the client presenting a service ticket and
 * an authenticator to an application server (e.g. the Nginx-backed web server — schema
 * defined now, handled in Phase 2/3).
 */
class ApReq extends kerberosPacket {
    /**
     * @param {string} origin_ip - Source IP address of the client.
     * @param {string} destination_ip - Destination application server IP address.
     * @param {string} origin_mac - Source MAC of the client.
     * @param {string} destination_mac - Destination MAC (can be "" and resolved en-route).
     * @param {string} serviceTicketCipher - Service ticket blob obtained in the TGS exchange.
     * @param {string} authenticatorCipher - Authenticator blob encrypted with the session key.
     * @param {string} realm - Target realm.
     */
    constructor(origin_ip, destination_ip, origin_mac, destination_mac, serviceTicketCipher, authenticatorCipher, realm) {
        super(origin_ip, destination_ip, origin_mac, destination_mac, KRB_AP_REQ);
        this.type = "request";
        this.sport = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152; //<-- ephemeral source port
        this.dport = ""; //<-- AP exchange targets the high TCP/UDP port of the application server
        this.serviceTicketCipher = serviceTicketCipher;
        this.authenticatorCipher = authenticatorCipher;
        this.apOptions = []; //<-- e.g. ["mutual-required"] once AP exchanges are simulated
        this.realm = realm;
    }
}

/**
 * @description Represents a KRB-ERROR message echoing a failure code back to a requester.
 */
class KerberosErrorPacket extends kerberosPacket {
    /**
     * @param {string} origin_ip - Source IP address of the KDC.
     * @param {string} destination_ip - Destination requester IP address.
     * @param {string} origin_mac - Source MAC address of the KDC.
     * @param {string} destination_mac - Destination MAC address of the requester.
     * @param {number} errorCode - RFC 4120 error code (e.g. 6, 7, 30).
     * @param {string} e_text - Human readable error description.
     */
    constructor(origin_ip, destination_ip, origin_mac, destination_mac, errorCode, e_text) {
        super(origin_ip, destination_ip, origin_mac, destination_mac, KRB_ERROR);
        this.type = "reply";
        this.sport = KDC_LISTEN_PORT;
        this.error_code = errorCode;
        this.e_text = e_text;
    }
}

/**
 * Wire schemas describing every required field per simulated message type. The same map
 * drives on-wire validation in `serializeKerberosPacket` and `deserializeKerberosPacket`.
 */
const KERBEROS_MESSAGE_SCHEMAS = {
    [KRB_AS_REQ]: {name: "KRB_AS_REQ", fields: ["cname", "realm"]},
    [KRB_AS_REP]: {name: "KRB_AS_REP", fields: ["cname", "realm", "tgtCipher", "sessionKeyCipher"]},
    [KRB_TGS_REQ]: {name: "KRB_TGS_REQ", fields: ["tgtCipher", "sname", "realm"]},
    [KRB_TGS_REP]: {name: "KRB_TGS_REP", fields: ["sname", "realm", "serviceTicketCipher", "sessionKeyCipher"]},
    [KRB_AP_REQ]: {name: "KRB_AP_REQ", fields: ["serviceTicketCipher", "authenticatorCipher", "realm"]},
    [KRB_ERROR]: {name: "KRB_ERROR", fields: ["error_code", "e_text"]},
}

/**
 * Serializes any Kerberos packet into a wire-format JSON string, checking the message's
 * schema first so a message can never be emitted half-formed.
 *
 * @param {Object} kerberosPacketObject - One of the `kerberosPacket` subclasses.
 * @returns {string} JSON wire format of the packet (including L3/L2 addressing + msg payload).
 * @throws {Error} If the packet `krb_msg_type` has no schema or a required field is missing.
 */
function serializeKerberosPacket(kerberosPacketObject) {

    const schema = KERBEROS_MESSAGE_SCHEMAS[kerberosPacketObject.krb_msg_type];

    if (!schema) throw new Error(`Error: unknown Kerberos msg-type ${kerberosPacketObject.krb_msg_type}.`);

    validateKerberosMessage(kerberosPacketObject, schema.fields);

    return kerberosSerialize(kerberosPacketObject);

}

/**
 * Deserializes a wire-format JSON string produced by `serializeKerberosPacket` back into
 * a typed packet instance, restoring every schema field.
 *
 * @param {string} json - Serialized packet string.
 * @returns {Object} Reconstructed packet instance of the matching Kerberos class.
 * @throws {Error} If the payload lacks class mapping or fails its schema check.
 */
function deserializeKerberosPacket(json) {

    const raw = kerberosDeserialize(json);

    if (!raw.krb_msg_type) throw new Error("Error: cannot deserialize Kerberos packet: no msg-type present.");

    const constructorMap = {
        [KRB_AS_REQ]: AsReq,
        [KRB_AS_REP]: AsRep,
        [KRB_TGS_REQ]: TgsReq,
        [KRB_TGS_REP]: TgsRep,
        [KRB_AP_REQ]: ApReq,
        [KRB_ERROR]: KerberosErrorPacket,
    }

    const KerberosClass = constructorMap[raw.krb_msg_type];

    if (!KerberosClass) throw new Error(`Error: cannot deserialize Kerberos packet: unknown msg-type ${raw.krb_msg_type}.`);

    const packetObject = new KerberosClass(raw.origin_ip, raw.destination_ip, raw.origin_mac, raw.destination_mac);

    for (const key of Object.keys(raw)) { //<-- restore every serialized field
        if (key !== "xid") packetObject[key] = raw[key]; //<-- a fresh xid is generated by the base class
    }

    validateKerberosMessage(packetObject, KERBEROS_MESSAGE_SCHEMAS[raw.krb_msg_type].fields);

    return packetObject;

}

/**
 * Builds and routes an outgoing Kerberos request packet from a device toward a
 * destination KDC or application server, filling its source MAC/IP and relying on the
 * standard routing engine to resolve the first-hop MAC.
 *
 * @param {string} networkObjectId - The network object (client) id sending the request.
 * @param {string} destinationIp - The IP address of the target KDC or application server.
 * @param {Object} message - A populated instance of `AsReq`, `TgsReq`, or `ApReq` whose
 *   origin_ip/origin_mac were left blank by the caller.
 * @returns {Promise<void>}
 */
async function sendKerberosRequest(networkObjectId, destinationIp, message) {

    const $networkObject = document.getElementById(networkObjectId);
    const networkObjectInterface = getInterfaces(networkObjectId)[0];
    const networkObjectMac = $networkObject.getAttribute(`mac-${networkObjectInterface}`);
    const networkObjectIp = $networkObject.getAttribute(`ip-${networkObjectInterface}`);

    message.origin_ip = networkObjectIp;
    message.origin_mac = networkObjectMac;
    message.destination_ip = destinationIp;
    message.destination_mac = "";

    serializeKerberosPacket(message); //<-- schema-check before sending anything on the wire

    await routing(networkObjectId, message, true);

}

/**
 * Builds and routes a Kerberos reply packet from a device (KDC or application server)
 * back toward the requester, mirroring `dnsRequestPacketGenerator`'s conventions.
 *
 * The `packet` argument must be a `kerberosPacket` subclass already addressed in the
 * correct direction; this helper only routes it.
 *
 * @param {string} networkObjectId - The network object (KDC / server) id sending the reply.
 * @param {Object} packet - The reply packet to send.
 * @returns {Promise<void>}
 */
async function sendKerberosReply(networkObjectId, packet) {
    await routing(networkObjectId, packet, true);
}
