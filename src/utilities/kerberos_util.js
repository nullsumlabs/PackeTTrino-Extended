/**
 * @fileoverview Client-side Kerberos v5 library for PackeTTrino. Implements the client
 * half of the AS Exchange (kinit), the ticket cache (the simulated `krb5cc_0` ticket
 * file, persisted on the client device as the `ticket-cache` HTML attribute so it lives
 * in the node's own memory like every other device state), the validity/expiry checks,
 * and the automatic TGS acquisition + AP-REQ packaging used by the HTTP client before
 * fetching a page. Exchanges reuse the RFC 4120 message classes and the routing engine
 * from `kerberos_lib.js`, so the client talks to the KDC over simulated UDP port 88.
 *
 * Ticket cache entry schema (`ticket-cache` attribute, JSON array):
 *
 *     {
 *       "principal": "alice@PACKETTRINO.EDU",          // owner of the ticket
 *       "spn": "krbtgt/PACKETTRINO.EDU@PACKETTRINO.EDU",// ticket service principal
 *       "realm": "PACKETTRINO.EDU",                    // target realm
 *       "kdc_ip": "192.168.1.1",                       // KDC that issued the ticket
 *       "start_time": 1690000000,                      // validity start (epoch seconds)
 *       "end_time": 1690003600,                        // validity end (epoch seconds)
 *       "session_key": "0123456789ABCDEF",             // TGS/AS session key (cleartext copy held by client)
 *       "ticket_cipher": "KRBM1:...",                  // encrypted blob (TGT for TGS-REQ, ST for AP-REQ)
 *       "etype": 18                                    // advertised encryption type
 *     }
 *
 * The KDC handles the server half of every exchange; this file never decrypts a TGT or
 * a service ticket — only keys issued *for the client* (session keys) are unwrapped
 * here, exactly like in the real protocol.
 */

/** @type {string} HTML attribute on client network devices holding the `ticketCache[]` JSON array. */
const KRB5_CACHE_ATTRIBUTE = "ticket-cache";

/** @type {number} Default ticket-assumption window in seconds: tickets with `end_time` beyond this horizon are trusted per their own expiry. */
const KRB5_CACHE_MAXLEASE = 86400;

/**
 * Reads the device's `ticketCache[]` array.
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @returns {Array<Object>} The cached ticket entries (empty array when unset or corrupt).
 */
function getTicketCache(networkObjectId) {

    const $networkObject = document.getElementById(networkObjectId);
    const rawCache = $networkObject.getAttribute(KRB5_CACHE_ATTRIBUTE);

    if (!rawCache) return [];

    let ticketCache;

    try {
        ticketCache = JSON.parse(rawCache);
    } catch (error) {
        ticketCache = []; //<-- a corrupt cache is treated like an empty one
    }

    if (!Array.isArray(ticketCache)) return []; //<-- non-array payloads are also treated like an empty one

    return ticketCache;

}

/**
 * Rewrites the device's `ticketCache[]` array (the node's persistent memory instance).
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @param {Array<Object>} ticketCache - The new array of ticket entries.
 * @returns {void}
 */
function setTicketCache(networkObjectId, ticketCache) {
    const $networkObject = document.getElementById(networkObjectId);
    $networkObject.setAttribute(KRB5_CACHE_ATTRIBUTE, kerberosSerialize(ticketCache));
}

/**
 * Checks a ticket's basic validity timestamps: its validity window must contain
 * `nowEpoch` (start has elapsed and the end time has not).
 *
 * @param {Object} ticketEntry - A `ticketCache[]` entry.
 * @param {number} [nowEpoch=Math.floor(Date.now()/1000)] - Reference epoch seconds (overridable for tests).
 * @returns {boolean} True when the ticket is within its validity window.
 */
function isKerberosTicketValid(ticketEntry, nowEpoch = Math.floor(Date.now() / 1000)) {

    if (!ticketEntry || typeof ticketEntry !== "object") return false;
    if (typeof ticketEntry.start_time !== "number" || typeof ticketEntry.end_time !== "number") return false;
    if (typeof ticketEntry.ticket_cipher !== "string" || ticketEntry.ticket_cipher === "") return false;

    return ticketEntry.start_time <= nowEpoch && nowEpoch < ticketEntry.end_time;

}

/**
 * Removes expired entries from the device's `ticketCache[]` (like real ccache garbage
 * collection, they are never reused once past `end_time`).
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @param {number} [nowEpoch=Math.floor(Date.now()/1000)] - Reference epoch seconds (overridable for tests).
 * @returns {number} The number of purged entries.
 */
function purgeExpiredKerberosTickets(networkObjectId, nowEpoch = Math.floor(Date.now() / 1000)) {

    const ticketCache = getTicketCache(networkObjectId);
    const remainingCache = ticketCache.filter(entry => isKerberosTicketValid(entry, nowEpoch));

    if (remainingCache.length !== ticketCache.length) setTicketCache(networkObjectId, remainingCache);

    return ticketCache.length - remainingCache.length;

}

/**
 * Finds a valid cached ticket for the given service principal, purging expired entries first.
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @param {string} spn - Full service principal name, e.g. "HTTP/webserver@PACKETTRINO.EDU".
 * @param {number} [nowEpoch=Math.floor(Date.now()/1000)] - Reference epoch seconds (overridable for tests).
 * @returns {Object|null} The valid `ticketCache[]` entry, or null when none is cached.
 */
function findValidKerberosTicket(networkObjectId, spn, nowEpoch = Math.floor(Date.now() / 1000)) {

    purgeExpiredKerberosTickets(networkObjectId, nowEpoch);

    const entry = getTicketCache(networkObjectId).find(entry => entry.spn === spn);

    return entry || null;

}

/**
 * Builds the `HTTP/...` SPN used for HTTP service tickets.
 *
 * @param {string} host - Hostname or IP used in the web request (e.g. "webserver").
 * @param {string} realm - Kerberos realm of the service.
 * @returns {string} The SPN, e.g. "HTTP/webserver@PACKETTRINO.EDU".
 */
function buildKerberosSpn(host, realm) {
    return buildSpn("HTTP", host, realm);
}

/**
 * Returns the cached client principal of the device (its default principal), taken
 * from the TGT entry.
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @returns {string|null} The principal string, or null when the device has no TGT.
 */
function getKerberosDefaultPrincipal(networkObjectId) {

    const tgtEntry = getTicketCache(networkObjectId).find(entry => (entry.spn || "").startsWith("krbtgt/"));

    return tgtEntry ? tgtEntry.principal : null;

}

/**
 * Discovers a running KDC for a realm on the board.
 *
 * Left-clicking simulates the classic discovery order cheaply: first any device with
 * the `kdc` service running whose realm matches, else any KDC. Returns the first
 * configured IP of the winner.
 *
 * @param {string} [realm=""] - Realm to restrict to (both orders fallback when none); empty disables the realm filter.
 * @returns {string|null} The KDC IP address, or null when no KDC is running on the board.
 */
function discoverKdcIp(realm = "") {

    const matchingKdcs = [];
    const anyKdc = [];

    document.querySelectorAll(".item-dropped").forEach($device => {

        if ($device.getAttribute("kdc") !== "true") return; //<-- kdc service off

        const deviceRealm = $device.getAttribute("krb5-realm");
        const deviceIp = $device.getAttribute("ip-enp0s3");

        if (!deviceIp) return;

        (($device.getAttribute("kdc") === "true" && deviceRealm === realm) ? matchingKdcs : anyKdc).push(deviceIp);

    });

    const chosenIp = matchingKdcs[0] || anyKdc[0];

    return chosenIp || null;

}

/**
 * Performs the client half of the AS Exchange (what `kinit` does).
 *
 * Sends a KRB_AS_REQ to the running KDC over port 88, decrypts the AS session key with
 * the provided password (the mocked credential check — only the real owner of the
 * principal's password can unwrap it), and stores the fresh TGT in the device's
 * `ticketCache[]`. The TGT itself stays opaque; it is never decrypted client side.
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @param {string} username - Local user name (without realm), e.g. "alice".
 * @param {string} password - The mocked credentials typed by the user.
 * @param {string} [requestedRealm=""] - Realm to authenticate against (discovered when empty).
 * @returns {Promise<Object>} The stored TGT `ticketCache[]` entry.
 * @throws {Error} When no KDC is reachable (`Communication error`), the principal is
 *   unknown (KRB-ERROR 6), the password is wrong, or the reply is malformed.
 */
async function authenticateKerberos(networkObjectId, username, password, requestedRealm = "") {

    const kdcIp = discoverKdcIp(requestedRealm);

    if (!kdcIp) throw new Error("Error locating KDC: no KDC daemon is running on the board.");

    kerberosFlag[networkObjectId] = false; //<-- clear the in-flight flag (same pattern as DNS/ICMP)
    delete kerberosBuffer[networkObjectId];

    const asRequest = new AsReq("", kdcIp, "", "", username, requestedRealm || $KRB5DEFAULTREALM);

    await sendKerberosRequest(networkObjectId, kdcIp, asRequest); //<-- callback array: route the request through the sim

    const asReply = kerberosBuffer[networkObjectId];

    if (!asReply) throw new Error(`Communication error with ${kdcIp}: no KRB_AS_REP received.`);

    if (asReply.krb_msg_type === KRB_ERROR) throw new Error(`kinit: ${asReply.e_text}`);

    let sessionKey;

    try {
        sessionKey = mockKerberosDecrypt(asReply.sessionKeyCipher, password); //<-- unwrap the session key with the typed password
    } catch (error) {
        throw new Error("kinit: The password is incorrect.", {cause: error});
    }

    if (!/^[0-9A-F]{16}$/.test(sessionKey)) throw new Error("kinit: The password is incorrect."); //<-- only valid keys decrypt to a 16-char hex key

    const issuedEpoch = Math.floor(Date.now() / 1000);
    const lease = Number(asReply.lease) || KRB5_CACHE_MAXLEASE;

    const tgtEntry = {
        "principal": `${username}@${asReply.realm || $KRB5DEFAULTREALM}`,
        "spn": `krbtgt/${asReply.realm}@${asReply.realm}`,
        "realm": asReply.realm,
        "kdc_ip": kdcIp,
        "start_time": issuedEpoch,
        "end_time": issuedEpoch + lease,
        "session_key": sessionKey,
        "ticket_cipher": asReply.tgtCipher,
        "etype": asReply.etype || KRB5_ETYPE_AES256,
    }

    //replace any stale TGT entries for the same principal/SPN with the fresh one

    const remainingCache = getTicketCache(networkObjectId).filter(entry => entry.spn !== tgtEntry.spn);
    remainingCache.push(tgtEntry);

    setTicketCache(networkObjectId, remainingCache);

    return tgtEntry;

}

/**
 * Performs the client half of the TGS Exchange: uses the cached TGT to request a
 * service ticket for `spn`, unwraps the client-service session key with the TGT's
 * session key, and caches the service ticket. Reuses a still-valid cached ticket when
 * one already exists.
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @param {string} spn - Full service principal name, e.g. "HTTP/webserver@PACKETTRINO.EDU".
 * @param {number} [nowEpoch=Math.floor(Date.now()/1000)] - Reference epoch seconds (overridable for tests).
 * @returns {Promise<Object>} The (possibly cached) service-ticket `ticketCache[]` entry.
 * @throws {Error} When the device has no valid TGT (`kinit` first), the SPN is unknown
 *   (KRB-ERROR 7), or no KRB_TGS_REP arrives before the reply deadline.
 */
async function acquireKerberosServiceTicket(networkObjectId, spn, nowEpoch = Math.floor(Date.now() / 1000)) {

    const cachedTicket = findValidKerberosTicket(networkObjectId, spn, nowEpoch);

    if (cachedTicket) return cachedTicket; //<-- still-valid cached service ticket

    const tgtEntry = findValidKerberosTicket(networkObjectId, `krbtgt/${(spn.split("@")[1] || $KRB5DEFAULTREALM)}@${(spn.split("@")[1] || $KRB5DEFAULTREALM)}`, nowEpoch);

    if (!tgtEntry) throw new Error("kinit: no TGT in ticket cache. Run `kinit <principal>` first.");

    kerberosFlag[networkObjectId] = false; //<-- clear the in-flight flag (same pattern as DNS/ICMP)
    delete kerberosBuffer[networkObjectId];

    const tgsRequest = new TgsReq("", tgtEntry.kdc_ip, "", "", tgtEntry.ticket_cipher, spn, tgtEntry.realm);

    await sendKerberosRequest(networkObjectId, tgtEntry.kdc_ip, tgsRequest);

    const tgsReply = kerberosBuffer[networkObjectId];

    if (!tgsReply) throw new Error(`Communication error with ${tgtEntry.kdc_ip}: no KRB_TGS_REP received.`);

    if (tgsReply.krb_msg_type === KRB_ERROR) throw new Error(`krb5: ${tgsReply.e_text}`);

    let sessionKey;

    try {
        sessionKey = mockKerberosDecrypt(tgsReply.sessionKeyCipher, tgtEntry.session_key); //<-- wrapped with the AS session key
    } catch (error) {
        throw new Error("krb5: Could not decrypt the service session key.", {cause: error});
    }

    if (!/^[0-9A-F]{16}$/.test(sessionKey)) throw new Error("krb5: Could not decrypt the service session key.");

    const issuedEpoch = Math.floor(Date.now() / 1000);
    const lease = Number(tgsReply.lease) || KRB5_CACHE_MAXLEASE;

    const serviceTicketEntry = {
        "principal": tgtEntry.principal,
        "spn": tgsReply.sname,
        "realm": tgtEntry.realm,
        "kdc_ip": tgtEntry.kdc_ip,
        "start_time": issuedEpoch,
        "end_time": issuedEpoch + lease,
        "session_key": sessionKey,
        "ticket_cipher": tgsReply.serviceTicketCipher,
        "etype": tgsReply.etype || KRB5_ETYPE_AES256,
    }

    const remainingCache = getTicketCache(networkObjectId).filter(entry => entry.spn !== serviceTicketEntry.spn);
    remainingCache.push(serviceTicketEntry);

    setTicketCache(networkObjectId, remainingCache);

    return serviceTicketEntry;

}

/**
 * Packages a cached service ticket + a fresh authenticator into a KRB_AP_REQ packet
 * destined to the application server (e.g. the Nginx-backed web server in Phase 3).
 *
 * The authenticator mirrors the real RFC 4120 structure loosely (client principal +
 * timestamp, encrypted with the client-service session key) so the server can verify
 * freshness and bind the ticket to this exact client.
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @param {Object} serviceTicketEntry - A service-ticket `ticketCache[]` entry.
 * @param {string} webServerIp - IP address of the application server.
 * @param {number} [nowEpoch=Math.floor(Date.now()/1000)] - Reference epoch seconds (overridable for tests).
 * @returns {ApReq} The addressed AP-REQ packet ready to ride on an HTTP request.
 * @throws {Error} If the entry is not a valid service-ticket cache entry.
 */
function packageKerberosApReq(networkObjectId, serviceTicketEntry, webServerIp, nowEpoch = Math.floor(Date.now() / 1000)) {

    if (!serviceTicketEntry || !serviceTicketEntry.ticket_cipher || !serviceTicketEntry.session_key) throw new Error("krb5: Cannot package AP-REQ: no service ticket available.");

    const $networkObject = document.getElementById(networkObjectId);
    const networkObjectInterface = getInterfaces(networkObjectId)[0];
    const networkObjectIp = $networkObject.getAttribute(`ip-${networkObjectInterface}`);
    const networkObjectMac = $networkObject.getAttribute(`mac-${networkObjectInterface}`);

    const authenticatorPayload = {
        "version": 1,
        "cname": (serviceTicketEntry.principal || "").split("@")[0], //<-- RFC 4120: the cname is local to the realm, matching the KDC-minted ticket
        "sname": serviceTicketEntry.spn,
        "timestamp": nowEpoch
    }

    const apRequest = new ApReq(
        networkObjectIp, //source IP
        webServerIp, //destination IP
        networkObjectMac, //source MAC (en-route filled by routing)
        "", //destination MAC
        serviceTicketEntry.ticket_cipher, //service ticket blob (opaque to the client)
        mockKerberosEncrypt(kerberosSerialize(authenticatorPayload), serviceTicketEntry.session_key),
        serviceTicketEntry.realm
    );

    return apRequest;

}

/**
 * Full negotiation flow used by the HTTP client before fetching a page:
 * 1. If the device has never `kinit`'d (no valid TGT), return `null` so the request
 *    proceeds unauthenticated, staying out of the way of plain traffic.
 * 2. Otherwise extract the web SPN for the requested host, acquire (or reuse) a service
 *    ticket for it via the TGS exchange, and package it into an AP-REQ.
 *
 * @param {string} networkObjectId - The DOM element ID of the client device.
 * @param {string} host - Hostname/IP used in the web request (drives the SPN).
 * @param {string} webServerIp - IP address of the web server.
 * @returns {Promise<ApReq|null>} The AP-REQ packet to attach to the request, or null when
 *   the device is not authenticated (no TGT).
 */
async function negotiateKerberosApReq(networkObjectId, host, webServerIp) {

    const defaultTicket = getTicketCache(networkObjectId).find(entry => (entry.spn || "").startsWith("krbtgt/"));
    const hasLiveTgt = defaultTicket && isKerberosTicketValid(defaultTicket);

    if (!hasLiveTgt) return null; //<-- not authenticated: plain HTTP

    const spn = (defaultTicket.spn.split("@").length > 1) ? buildKerberosSpn(host, defaultTicket.realm) : buildKerberosSpn(host, $KRB5DEFAULTREALM);

    let serviceTicketEntry;

    try {
        serviceTicketEntry = await acquireKerberosServiceTicket(networkObjectId, spn);
    } catch (error) {
        terminalMessage(`kerberos: ${error.message} Proceeding unauthenticated.`, networkObjectId); //<-- graceful downgrade to plain HTTP
        return null;
    }

    return packageKerberosApReq(networkObjectId, serviceTicketEntry, webServerIp);

}
