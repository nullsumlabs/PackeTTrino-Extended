/**
 * Simulates the MIT Kerberos KDC daemon (krb5kdc) running on a server network object.
 *
 * Listens for simulated `kerberos` protocol packets addressed to UDP port 88 and
 * dispatches them onto the corresponding RFC 4120 exchange handler:
 *
 * - **AS Handler** (`handleKerberosAsRequest`) — receives KRB_AS_REQ, validates the
 *   requested principal against the mock principal database, and answers KRB_AS_REP
 *   containing a mocked TGT (encrypted with the realm's KDC master key) plus the AS
 *   session key (encrypted with the principal's client key).
 * - **TGS Handler** (`handleKerberosTgsRequest`) — receives KRB_TGS_REQ, decrypts and
 *   validates the presented TGT with the KDC master key, checks the requested SPN
 *   against the mock service database, and answers KRB_TGS_REP containing the service
 *   ticket (encrypted with the target service's private key) plus the client-service
 *   session key (encrypted with the AS session key).
 *
 * Any failure is answered with a `KerberosErrorPacket` (type 30) instead of silence, so
 * future client phases (kinit/klist) can surface proper Kerberos error codes.
 *
 * @param {string} networkObjectId - The DOM element ID of the server running the KDC.
 * @param {Object} packet - The incoming Kerberos request packet (one of the `kerberosPacket` subclasses).
 * @returns {Promise<Object|undefined>} The reply packet, or `undefined` when the packet
 *   is not for this device, the service is off, or the request is not a request msg-type.
 */
async function kdc_service(networkObjectId, packet) {

    const $networkObject = document.getElementById(networkObjectId);

    if ($networkObject.getAttribute("kdc") !== "true") return; //<-- the KDC daemon is stopped

    const networkObjectInterface = getInterfaces(networkObjectId)[0];
    const networkObjectIp = $networkObject.getAttribute(`ip-${networkObjectInterface}`);
    const networkObjectMac = $networkObject.getAttribute(`mac-${networkObjectInterface}`);

    if (!getAvailableIps(networkObjectId).includes(packet.destination_ip)) return; //<-- not addressed to this KDC

    const realm = $networkObject.getAttribute("krb5-realm") || $KRB5DEFAULTREALM;

    seedKerberosDatabase(realm); //<-- ensure the mock database has the realm content

    if (packet instanceof AsReq) return await handleKerberosAsRequest(networkObjectId, packet, networkObjectIp, networkObjectMac, realm);

    if (packet instanceof TgsReq) return await handleKerberosTgsRequest(networkObjectId, packet, networkObjectIp, networkObjectMac, realm);

    return buildKerberosError(networkObjectId, packet, networkObjectIp, networkObjectMac, KRB_ERR_GENERIC, "The request message type is not supported by this KDC.");

}

/**
 * Builds a KRB-ERROR packet aimed back at the requester of an unsupported/failed message,
 * using the requester's own source-address triplet.
 *
 * @param {string} networkObjectId - The DOM element ID of the responding device.
 * @param {Object} packet - The incoming packet whose sender will receive the error.
 * @param {string} networkObjectIp - The responder IP address.
 * @param {string} networkObjectMac - The responder MAC address.
 * @param {number} errorCode - RFC 4120 error code (e.g. 6, 7, 30).
 * @param {string} e_text - Human readable description of the failure.
 * @returns {Object} The addressed `KerberosErrorPacket`.
 */
function buildKerberosError(networkObjectId, packet, networkObjectIp, networkObjectMac, errorCode, e_text) {

    const errorPacket = new KerberosErrorPacket(
        networkObjectIp, //source IP
        packet.origin_ip, //destination IP
        networkObjectMac, //source MAC
        packet.origin_mac, //destination MAC
        errorCode,
        e_text
    );

    errorPacket.dport = packet.sport; //<-- answer to the requester's ephemeral port

    kerberosTicketRegistry.set(`${networkObjectId}-${errorPacket.xid}`, {error_code: errorCode, e_text: e_text});

    return errorPacket;

}

/**
 * Handles a KRB_AS_REQ on behalf of the KDC (the AS Handler).
 *
 * Validates the client principal `cname@realm` against the mock database, mints a random
 * AS session key, wraps a TGT payload (client name, realm, session key, issue/expiry
 * times) with the KDC master key, and wraps the session key with the principal's client
 * key so only the real owner of the password can unwrap it (RFC 4120 initial exchange).
 *
 * @param {string} networkObjectId - The DOM element ID of the KDC device.
 * @param {AsReq} packet - The incoming KRB_AS_REQ packet.
 * @param {string} networkObjectIp - The KDC IP address.
 * @param {string} networkObjectMac - The KDC MAC address.
 * @param {string} realm - The realm served by this KDC.
 * @returns {Promise<Object>} The KRB_AS_REP or a KRB-ERROR reply packet.
 */
async function handleKerberosAsRequest(networkObjectId, packet, networkObjectIp, networkObjectMac, realm) {

    const clientPrincipal = `${packet.cname}@${realm}`;
    const clientPrincipalRecord = getKerberosUser(clientPrincipal);

    if (!clientPrincipalRecord) return buildKerberosError(networkObjectId, packet, networkObjectIp, networkObjectMac, KDC_ERR_C_PRINCIPAL_UNKNOWN, `KDC has no support for principal ${clientPrincipal}.`);

    const sessionKey = generateSessionKey(); //<-- the AS session key shared by client and TGS
    const masterKey = getKdcMasterKey(realm); //<-- the krbtgt (KDC master) key material

    const tgtPayload = {
        "version": 1,
        "cname": packet.cname,
        "realm": realm,
        "session_key": sessionKey,
        "issued": Math.floor(Date.now() / 1000),
        "expiry": Math.floor(Date.now() / 1000) + 3600
    }

    const replyPacket = new AsRep(
        networkObjectIp, //source IP
        packet.origin_ip, //destination IP
        networkObjectMac, //source MAC
        packet.origin_mac, //destination MAC
        packet.cname,
        realm
    );

    replyPacket.dport = packet.sport; //<-- answer to the requester's ephemeral port
    replyPacket.tgtCipher = mockKerberosEncrypt(kerberosSerialize(tgtPayload), masterKey);
    replyPacket.sessionKeyCipher = mockKerberosEncrypt(sessionKey, clientPrincipalRecord.password);
    replyPacket.lease = tgtPayload.expiry - tgtPayload.issued;

    kerberosTicketRegistry.set(`${networkObjectId}-${replyPacket.xid}`, {
        "cname": packet.cname,
        "sname": `krbtgt/${realm}`,
        "tgt": tgtPayload
    });

    return replyPacket;

}

/**
 * Handles a KRB_TGS_REQ on behalf of the KDC (the TGS Handler).
 *
 * Decrypts and validates the presented TGT with the realm's KDC master key (rejecting
 * malformed, expired, or cross-realm tickets), checks the requested SPN against the mock
 * service database, mints a client-service session key, wraps the service ticket payload
 * in the target service's private key, and wraps the new session key in the TGT session
 * key (RFC 4120 ticket-granting exchange).
 *
 * @param {string} networkObjectId - The DOM element ID of the KDC device.
 * @param {TgsReq} packet - The incoming KRB_TGS_REQ packet.
 * @param {string} networkObjectIp - The KDC IP address.
 * @param {string} networkObjectMac - The KDC MAC address.
 * @param {string} realm - The realm served by this KDC.
 * @returns {Promise<Object>} The KRB_TGS_REP or a KRB-ERROR reply packet.
 */
async function handleKerberosTgsRequest(networkObjectId, packet, networkObjectIp, networkObjectMac, realm) {

    const masterKey = getKdcMasterKey(realm);

    let tgtPayload;

    try {
        tgtPayload = kerberosDeserialize(mockKerberosDecrypt(packet.tgtCipher, masterKey));
    } catch (error) {
        return buildKerberosError(networkObjectId, packet, networkObjectIp, networkObjectMac, KRB_ERR_GENERIC, "The TGT cannot be decrypted with this KDC master key.");
    }

    validateKerberosMessage(tgtPayload, ["cname", "realm", "session_key", "issued", "expiry"]); //<-- throw surface: bad TGT internals are answered as generic errors

    if (tgtPayload.realm !== realm || tgtPayload.expiry < Math.floor(Date.now() / 1000)) {
        return buildKerberosError(networkObjectId, packet, networkObjectIp, networkObjectMac, KRB_ERR_GENERIC, `The TGT for ${tgtPayload.cname}@${tgtPayload.realm} is not valid on this KDC.`);
    }

    const servicePrincipalRecord = getKerberosService(packet.sname); //<-- authorization: the SPN must exist in the realm database

    if (!servicePrincipalRecord) return buildKerberosError(networkObjectId, packet, networkObjectIp, networkObjectMac, KDC_ERR_S_PRINCIPAL_UNKNOWN, `KDC has no support for service ${packet.sname}.`);

    const sessionKey = generateSessionKey(); //<-- the client-service session key

    const serviceTicketPayload = {
        "version": 1,
        "cname": tgtPayload.cname,
        "sname": packet.sname,
        "session_key": sessionKey,
        "issued": Math.floor(Date.now() / 1000),
        "expiry": Math.floor(Date.now() / 1000) + 3600,
        "caddr": packet.origin_ip //<-- the requesting client's network address, validated by the service server (AP exchange)
    }

    const replyPacket = new TgsRep(
        networkObjectIp, //source IP
        packet.origin_ip, //destination IP
        networkObjectMac, //source MAC
        packet.origin_mac, //destination MAC
        packet.sname,
        realm
    );

    replyPacket.dport = packet.sport; //<-- answer to the requester's ephemeral port
    replyPacket.serviceTicketCipher = mockKerberosEncrypt(kerberosSerialize(serviceTicketPayload), servicePrincipalRecord.password);
    replyPacket.sessionKeyCipher = mockKerberosEncrypt(sessionKey, tgtPayload.session_key);
    replyPacket.lease = serviceTicketPayload.expiry - serviceTicketPayload.issued;

    kerberosTicketRegistry.set(`${networkObjectId}-${replyPacket.xid}`, {
        "cname": tgtPayload.cname,
        "sname": packet.sname,
        "ticket": serviceTicketPayload
    });

    return replyPacket;

}
