/**
 * Handles the `kdestroy` terminal command: destroys the current credentials by wiping
 * all entries from the device's `ticketCache[]` (the simulated logout / session
 * expiration). The message mirrors the output of the MIT destroy utility.
 *
 * @param {string} networkObjectId - The DOM element ID of the client running the command.
 * @returns {void}
 */
function command_kdestroy(networkObjectId) {

    const destroyedCount = getTicketCache(networkObjectId).length;

    setTicketCache(networkObjectId, []);

    terminalMessage(
        (destroyedCount === 0)
            ? "kdestroy: Credential cache is already empty."
            : `kdestroy: Destroyed ${destroyedCount} ticket(s): credentials cache cleared.`,
        networkObjectId,
        false
    );

}
