/**
 * Simulates the Nginx HTTP server running on a network object.
 *
 * When the service is on (`nginx` attribute), serves pages through the same
 * virtual-host content machinery the Apache2 simulation uses. When the
 * "Kerberos Authentication Required" toggle (`krb5-required` attribute) is enabled,
 * incoming HTTP requests must carry a Kerberos KRB_AP_REQ (attached by the client's
 * HTTP wiring as `packet.kerberosApReq`):
 *
 * - **Unauthenticated interception** — a request without an AP-REQ is answered with
 *   a simulated `401 Unauthorized` challenge instructing the client to authenticate
 *   (`kinit` first; the client then presents the AP-REQ automatically).
 * - **Ticket decryption & verification** — the AP-REQ's service ticket is decrypted
 *   with the server's locally-held private service key (`krb5-key`), and every ticket
 *   field is validated: the client principal name, the claimed network address
 *   (the KDC records the client's IP as the ticket's `caddr`), the SPN bound to this
 *   server, and the ticket/authenticator timestamp validity windows.
 * - **Access grant** — a fully valid AP-REQ lets the request through and the resource
 *   is served with `200 OK`.
 *
 * @param {string} networkObjectId - The DOM element ID of the server running Nginx.
 * @param {Object} packet - The incoming HTTP request packet.
 * @returns {Promise<Object|undefined>} The HTTP reply packet, or `undefined` when nginx is off.
 */
async function nginx_service(networkObjectId, packet) {

    const $networkObject = document.getElementById(networkObjectId);

    if ($networkObject.getAttribute("nginx") !== "true") return; //<-- nginx service is stopped

    if ($networkObject.getAttribute("krb5-required") !== "true") {
        return await serveNginxContent(networkObjectId, packet); //<-- anonymous access allowed
    }

    if (!packet.kerberosApReq) return buildKerberosChallenge(networkObjectId, packet, "401 Unauthorized: Kerberos authentication is required on this server.");

    let apRequest;

    try {
        apRequest = deserializeKerberosPacket(packet.kerberosApReq);
    } catch (error) {
        return buildKerberosChallenge(networkObjectId, packet, "401 Unauthorized: the AP-REQ payload cannot be parsed.", error);
    }

    if (apRequest.krb_msg_type !== KRB_AP_REQ) return buildKerberosChallenge(networkObjectId, packet, "401 Unauthorized: the packet is not a KRB_AP_REQ message.");

    const validation = validateKerberosApReq(networkObjectId, apRequest, packet); //<-- decrypt + validate ticket and authenticator

    if (!validation.ok) return buildKerberosChallenge(networkObjectId, packet, validation.reason);

    return await serveNginxContent(networkObjectId, packet); //<-- access granted: client principal shown by packetInfo tools

}

/**
 * Builds a `401 Unauthorized` HTTP reply carrying a Kerberos challenge, instructing the
 * client to authenticate with `kinit` and retry (the client HTTP wiring then presents
 * the AP-REQ automatically).
 *
 * @param {string} networkObjectId - The DOM element ID of the Nginx server.
 * @param {Object} packet - The intercepted HTTP request packet.
 * @param {string} challengeBody - The challenge/instruction body text.
 * @param {Error} [cause] - Optional underlying parsing/validation error, attached for diagnostics.
 * @returns {Object} The addressed `httpReply` packet with status code 401.
 */
function buildKerberosChallenge(networkObjectId, packet, challengeBody, cause) {

    const $networkObject = document.getElementById(networkObjectId);
    const networkObjectInterface = getInterfaces(networkObjectId)[0];
    const networkObjectIp = $networkObject.getAttribute(`ip-${networkObjectInterface}`);
    const networkObjectMac = $networkObject.getAttribute(`mac-${networkObjectInterface}`);

    const replyPacket = new httpReply(
        networkObjectIp, //source IP
        packet.origin_ip, //destination IP
        networkObjectMac, //source MAC
        packet.origin_mac, //destination MAC
        packet.dport, //source port
        packet.sport, //destination port
        packet.method, //method
        packet.host //host
    );

    replyPacket.statusCode = 401;
    replyPacket.contentType = "text/html";
    replyPacket.challenge = "WWW-Authenticate: Kerberos"; //<-- mirrors the real response header
    replyPacket.body = `${challengeBody}<br>WWW-Authenticate: Kerberos<br>Get a ticket first with <b>kinit &lt;principal&gt;</b>, then retry your request.`;

    if (cause instanceof Error) replyPacket.cause = cause.message; //<-- diagnostics for the packet analyser

    return replyPacket;

}

/**
 * Decrypts and validates every field of the presented AP-REQ against this server:
 *
 * 1. The service ticket blob is decrypted with the locally-held private service key
 *    (`krb5-key`; decryption failure means forgery or key mismatch).
 * 2. The ticket's SPN (`sname`) must be the SPN bound to this server (`krb5-spn`).
 * 3. The ticket's client principal (`cname`) must exist and the ticket must still be
 *    inside its validity window (`issued` <= now < `expiry`).
 * 4. The ticket's claimed network address (`caddr`, recorded by the KDC at issuance)
 *    must match the requesting client's IP.
 * 5. The authenticator, decrypted with the ticket's session key, must belong to the
 *    same client principal and its timestamp must be within `$KRB5CLOCKSKEW` seconds
 *    of this server's clock.
 *
 * @param {string} networkObjectId - The DOM element ID of the Nginx server.
 * @param {Object} apRequest - The deserialized KRB_AP_REQ packet.
 * @param {Object} packet - The HTTP request carrying it (its `origin_ip` is the requester's address).
 * @param {number} [nowEpoch=Math.floor(Date.now()/1000)] - Reference epoch seconds (overridable for tests).
 * @returns {{ok: boolean, reason?: string, clientPrincipal?: string, serviceTicket?: Object}}
 *   Validation result; on success the client principal and ticket payload are returned
 *   for use by the access-granted path and the packet-tracer view.
 */
function validateKerberosApReq(networkObjectId, apRequest, packet, nowEpoch = Math.floor(Date.now() / 1000)) {

    const $networkObject = document.getElementById(networkObjectId);
    const serverSpn = $networkObject.getAttribute("krb5-spn");
    const serverKey = $networkObject.getAttribute("krb5-key");

    if (!serverSpn || !serverKey) return {ok: false, reason: "401 Unauthorized: this nginx instance has no Kerberos SPN/key configured."};

    let serviceTicket;

    try {
        serviceTicket = kerberosDeserialize(mockKerberosDecrypt(apRequest.serviceTicketCipher, serverKey)); //<-- decrypt with the PRIVATE service key
    } catch (error) {
        return {ok: false, reason: "401 Unauthorized: the service ticket cannot be decrypted with this server's key."};
    }

    validateKerberosMessage(serviceTicket, ["cname", "sname", "session_key", "issued", "expiry", "caddr"]); //<-- malformed ticket internals

    if (serviceTicket.sname !== serverSpn) {
        return {ok: false, reason: `401 Unauthorized: the ticket was issued for ${serviceTicket.sname}, not this server (${serverSpn}).`};
    }

    if (typeof serviceTicket.cname !== "string" || serviceTicket.cname === "") {
        return {ok: false, reason: "401 Unauthorized: the ticket carries no client principal."};
    }

    //timestamp validity window of the ticket itself

    if (typeof serviceTicket.issued !== "number" || typeof serviceTicket.expiry !== "number" || serviceTicket.issued > nowEpoch + $KRB5CLOCKSKEW || nowEpoch >= serviceTicket.expiry) {
        return {ok: false, reason: "401 Unauthorized: the ticket is outside its validity window; run kinit again."};
    }

    //network address check: only the client the KDC issued the ticket for may use it

    if (serviceTicket.caddr !== packet.origin_ip) {
        return {ok: false, reason: "401 Unauthorized: the ticket's network address does not match the requesting client."};
    }

    let authenticator;

    try {
        authenticator = kerberosDeserialize(mockKerberosDecrypt(apRequest.authenticatorCipher, serviceTicket.session_key));
    } catch (error) {
        return {ok: false, reason: "401 Unauthorized: the authenticator cannot be decrypted with the ticket session key."};
    }

    validateKerberosMessage(authenticator, ["cname", "timestamp"]); //<-- malformed authenticator internals

    if (authenticator.cname !== serviceTicket.cname) {
        return {ok: false, reason: "401 Unauthorized: the authenticator principal does not match the ticket."};
    }

    if (typeof authenticator.timestamp !== "number" || Math.abs(nowEpoch - authenticator.timestamp) > $KRB5CLOCKSKEW) {
        return {ok: false, reason: "401 Unauthorized: clock skew between the client and this server is too large."};
    }

    return {ok: true, clientPrincipal: serviceTicket.cname, serviceTicket: serviceTicket};

}

/**
 * Serves the requested resource using the shared virtual-host content machinery
 * (the same site parser and resolution logic used by the Apache2 simulation; nginx
 * keeps its own `default.conf` in `/etc/nginx/sites/`).
 *
 * @param {string} networkObjectId - The DOM element ID of the Nginx server.
 * @param {Object} packet - The HTTP request packet to serve.
 * @returns {Promise<Object>} The addressed `httpReply` (200/403/404/500 per the same rules as Apache2).
 */
async function serveNginxContent(networkObjectId, packet) {

    const $networkObject = document.getElementById(networkObjectId);
    const networkObjectInterface = getInterfaces(networkObjectId)[0];
    const networkObjectIp = $networkObject.getAttribute(`ip-${networkObjectInterface}`);
    const networkObjectMac = $networkObject.getAttribute(`mac-${networkObjectInterface}`);

    const replyPacket = new httpReply(
        networkObjectIp, //source IP
        packet.origin_ip, //destination IP
        networkObjectMac, //source MAC
        packet.origin_mac, //destination MAC
        packet.dport, //source port
        packet.sport, //destination port
        packet.method, //method
        packet.host //host
    );

    const requestObject = {
        requestedPort: packet.dport,
        requestedIp: packet.destination_ip,
        requestedResource: packet.resource,
        requestedMethod: packet.method,
        requestedHost: packet.host
    }

    const nginxResult = obtainNginxContent(networkObjectId, requestObject);

    replyPacket.body = nginxResult[0];
    replyPacket.statusCode = nginxResult[1];

    if (packet.kerberosApReq) {
        try {
            replyPacket.servedTo = validateKerberosApReq(networkObjectId, deserializeKerberosPacket(packet.kerberosApReq), packet).clientPrincipal; //<-- shown by the packet analyser
        } catch (error) {
            replyPacket.servedTo = ""; //<-- a malformed blob on a Kerberos-optional server still gets served
        }
    }

    return replyPacket;

}

/**
 * Resolves the content and HTTP status code for a request against the virtual-host
 * configuration of a Nginx site. Reads `/etc/nginx/sites/` files through the same
 * XML dialect and fallback rules as the Apache2 content resolver.
 *
 * @param {string} networkObjectId - The DOM element ID of the Nginx server.
 * @param {Object} requestObject - Describes the incoming HTTP request (port/ip/resource/method/host).
 * @returns {[string, number]} A tuple of [responseBody, httpStatusCode].
 */
function obtainNginxContent(networkObjectId, requestObject) {

    const $networkObject = document.getElementById(networkObjectId);
    const networkObjectFileSystem = new FileSystem($networkObject);

    const requestedResource = (requestObject.requestedResource).endsWith("/")
        ? (requestObject.requestedResource).slice(0, -1)
        : requestObject.requestedResource;

    const vhost = parseNginxConf(networkObjectId); //<-- DocumentRoot/DirectoryIndex from /etc/nginx/sites

    const directoryValue = vhost.documentRoot;
    const directoryIndexValue = vhost.directoryIndex;

    try {

        if (requestedResource === "") {
            return [networkObjectFileSystem.read(directoryIndexValue, directoryValue.split("/").slice(1)), 200]; //<-- serve the index
        }

        const resourceFile = lastResourceSegment(requestedResource);
        return [networkObjectFileSystem.read(resourceFile, directoryValue.split("/").slice(1)), 200]; //<-- serve the requested file at the document root

    } catch (error) {
        return [$404ERRORCONTENT, 404]; //TODO: create a log in the filesystem for errors
    }

}

/**
 * Parses the first virtual host of the active nginx configuration and extracts the
 * serving parameters. Reads `/etc/nginx/sites/` files in the same commented XML
 * dialect used for Apache2 vhosts.
 *
 * @param {string} networkObjectId - The DOM element ID of the Nginx server.
 * @returns {{ip: string, port: string, documentRoot: string, directoryIndex: string, serverName: string|null}}
 * @throws {Error} If the config file is missing or malformed.
 */
function parseNginxConf(networkObjectId) {

    const $networkObject = document.getElementById(networkObjectId);
    const networkObjectFileSystem = new FileSystem($networkObject);

    const nginxContent = networkObjectFileSystem.read("default.conf", ["etc", "nginx", "sites"]);

    const filteredConf = nginxContent
        .split("\n")
        .map(line => line.trim())
        .filter(line => line !== "" && !line.startsWith("#"))
        .join("\n");

    const parser = new DOMParser();
    const $nginxDOM = parser.parseFromString(filteredConf, "application/xml");

    const $nginxVirtualHost = $nginxDOM.querySelector("VirtualHost");
    const $documentRoot = $nginxVirtualHost.querySelector("DocumentRoot");
    const $directoryIndex = $nginxVirtualHost.querySelector("DirectoryIndex");
    const $serverName = $nginxVirtualHost.querySelector("ServerName");

    return {
        ip: $nginxVirtualHost.getAttribute("ip"),
        port: $nginxVirtualHost.getAttribute("port"),
        documentRoot: $documentRoot.getAttribute("value"),
        directoryIndex: $directoryIndex.getAttribute("value"),
        serverName: $serverName ? $serverName.getAttribute("value") : null,
    }

}

/**
 * Extracts the file name from a requested resource path.
 *
 * @param {string} requestedResource - The raw URI path (may end with a slash, which was already stripped).
 * @returns {string} The last path segment (the file name being requested).
 */
function lastResourceSegment(requestedResource) {
    return requestedResource.split("/").filter(part => part !== "").pop();
}
