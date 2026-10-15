/**
 * Handles the `kinit` terminal command: performs the client half of the Kerberos AS
 * Exchange to obtain an initial TGT.
 *
 * Asks the user for the (mocked) principal password (`prompt` dialog — the simulator's
 * input affordance; future phases can wire a real input into the terminal), delegates
 * the exchange to `authenticateKerberos`, and prints the resulting ticket entry to the
 * terminal on success.
 *
 * Modular by design: the terminal command is a thin wrapper — all state lives in the
 * device's `ticketCache[]` and all logic lives in `kerberos_util.js`, so later phases
 * (password prompts in the terminal, `kinit -R` renewals, preauth options) can be added
 * without touching this file.
 *
 * @param {string} networkObjectId - The DOM element ID of the client running the command.
 * @param {string} [username=""] - Local user name (without realm), e.g. "alice".
 * @returns {Promise<void>}
 */
async function command_kinit(networkObjectId, username = "") {

    const $networkObject = document.getElementById(networkObjectId);

    if (getAvailableIps(networkObjectId).every(ip => ip === "")) {
        terminalMessage("kinit: The device has no IP address configured.", networkObjectId);
        return;
    }

    if (!username) {
        terminalMessage("Usage: kinit &lt;principal&gt;   e.g. kinit alice", networkObjectId, false);
        return;
    }

    let password = "";

    if (typeof prompt === "function") { //<-- the simulator's mocked credential prompt
        password = prompt(`[kerberos] password for ${username}: `);
    }

    if (password === null || password === undefined) {
        terminalMessage("kinit: Operation cancelled by the user.", networkObjectId, false);
        return;
    }

    if (visualToggle) await minimizeTerminal();

        try {

            const tgtEntry = await authenticateKerberos(networkObjectId, username, password);

            terminalMessage(
                `kinit: Ticket for <span style='color:#4ade80;'>${tgtEntry.principal}</span> stored in the client ticket cache. ` +
                `Service: ${tgtEntry.spn}<br>` +
                `Valid starting ${formatKerberosTimestamp(tgtEntry.start_time)} — expires ${formatKerberosTimestamp(tgtEntry.end_time)} (lease ${tgtEntry.end_time - tgtEntry.start_time}s)`,
                networkObjectId
            );

        } catch (error) {

            terminalMessage(error.message, networkObjectId, false);

        }

    if (visualToggle) await maximizeTerminal();

}
