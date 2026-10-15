/**
 * Test doubles used by the Kerberos client suite (kerberos_client.spec.js). Loaded into
 * the same vm context *before* the real modules, then MISSING modules get faked and the
 * genuinely heavy simulation plumbing (packet routing + reply delivery) is replaced by
 * a synchronous-in-context equivalent: a request routed by the sim reaches its device in
 * the same await chain that `routing()` resolves, so the double reproduces exactly that
 * observable contract (either the reply lands in the destination buffers, or nothing does).
 */

/**
 * Emulates the routing engine: resolves the device by IP (only devices with the KDC
 * service running answer `kerberos` requests, like the real serviceProcessor), and
 * returns the KDC reply straight to the requester via the kernel's flag+buffer contract.
 *
 * @param {string} networkObjectId - The id of the device that sent the packet.
 * @param {Object} packet - The packet being routed.
 * @returns {Promise<void>}
 */
async function routing(networkObjectId, packet) {

    if (packet.protocol !== "kerberos" || packet.type !== "request") return; //<-- sim drops anything without a destination service, like real unicast to unknown IP

    let kdcId = "";

    document.querySelectorAll(".item-dropped").forEach($device => {
        if ($device.getAttribute("ip-enp0s3") === packet.destination_ip && $device.getAttribute("kdc") === "true") kdcId = $device.id; //<-- real kdc_service double-checks the destination anyway
    });

    if (kdcId === "") return; //<-- packet never reaches a KDC: no reply, exactly like the sim

    const replyPacket = await kdc_service(kdcId, packet);

    if (!replyPacket) return;

    //simulate the client kernel receiving the reply (kernelProc behaviour)

    kerberosFlag[networkObjectId] = true;
    kerberosBuffer[networkObjectId] = replyPacket;

}

/**
 * No-op terminal printer: `kerberos_util` may emit runtime warnings that the unit tests
 * do not need to observe.
 *
 * @param {string} message - Ignored.
 * @returns {void}
 */
function terminalMessage(message) {}
