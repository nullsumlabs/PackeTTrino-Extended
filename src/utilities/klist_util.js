/**
 * Formats an epoch-seconds timestamp the way real `klist` does: MM/DD/YY HH:MM:SS.
 *
 * @param {number} epoch - Unix timestamp in seconds.
 * @returns {string} The formatted timestamp string.
 */
function formatKerberosTimestamp(epoch) {

    const date = new Date(epoch * 1000);
    const pad = value => String(value).padStart(2, "0");
    const year = String(date.getFullYear()).padStart(4, "0").slice(-2);

    return `${pad(date.getMonth() + 1)}/${pad(date.getDate())}/${year} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;

}

/**
 * Handles the `klist` terminal command: purges expired entries (real `klist` reports
 * them as purged), then prints the cached tickets with their principals, SPNs, and
 * validity windows, mirroring the default principal banner of the MIT tool.
 *
 * @param {string} networkObjectId - The DOM element ID of the client running the command.
 * @returns {void}
 */
function command_klist(networkObjectId) {

    const purgedCount = purgeExpiredKerberosTickets(networkObjectId);

    const ticketCache = getTicketCache(networkObjectId);

    terminalMessage("Ticket cache: FILE:ticket-cache (client node memory)", networkObjectId, false);

    const defaultPrincipal = getKerberosDefaultPrincipal(networkObjectId);

    if (defaultPrincipal) terminalMessage(`Default principal: ${defaultPrincipal}`, networkObjectId, false);

    if (purgedCount > 0) terminalMessage(`${purgedCount} expired entries purged.`, networkObjectId, false);

    if (ticketCache.length === 0 && purgedCount === 0) {
        terminalMessage("klist: Credential cache is empty.", networkObjectId, false);
        return;
    }

    terminalMessage("", networkObjectId, false);

    terminalMessage("Valid starting            Expires                   Service principal", networkObjectId, false);

    for (const ticket of ticketCache) {
        terminalMessage(
            `${formatKerberosTimestamp(ticket.start_time).padEnd(26, " ")}` +
            `${formatKerberosTimestamp(ticket.end_time).padEnd(26, " ")}` +
            `${ticket.spn}`,
            networkObjectId,
            false
        );
    }

}
