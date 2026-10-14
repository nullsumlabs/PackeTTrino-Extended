/**
 * @fileoverview Terminal `help` command. Maintains a `commandManual` registry (command
 * name -> one-line description) that ANY command utility file can extend at load time
 * (`commandManual["mycommand"] = "..."`), keeping the help output modular: new commands
 * shipped in later phases show up in `help` by just registering themselves.
 */

/**
 * @description Registry of known terminal commands and their one-line descriptions.
 * Command utilities are free to append their own entries when their file loads.
 * @type {Object<string, string>}
 */
const commandManual = {
    "apt": "install/remove packages (apt install <package>)",
    "arp": "show/manage the ARP table",
    "cat": "print the content of a file (cat <file>)",
    "cd": "change the current directory (cd <path>)",
    "cp": "copy files (cp <source> <destination>)",
    "curl": "send an HTTP request to a URL (SSO renders an automatic Kerberos AP-REQ when authenticated)",
    "dig": "query a DNS server directly (dig @<server> <domain>)",
    "dns": "show/manages DNS cache servers (dns)",
    "exit": "close the terminal",
    "help": "list the available commands (this output)",
    "ifdown": "disable a network interface (ifdown <interface>)",
    "iface": "show network interface details (iface)",
    "ifup": "enable a network interface (ifup <interface>)",
    "ip": "show/manages IP addresses and routes (ip addr / ip route add <dst>/<mask> via <nexthop>)",
    "ipv4-forwarding": "show or toggle IPv4 packet forwarding",
    "iptables": "show/manages firewall rules (iptables [-F|-S|-L|-A|-N|-D])",
    "kdestroy": "destroy all cached Kerberos tickets (simulated logout)",
    "kinit": "request a TGT from the KDC (kinit <principal>)",
    "klist": "list cached Kerberos tickets and their validity windows",
    "ls": "list a directory's contents (ls [path])",
    "man": "show the manual page of a command (man <command>)",
    "mkdir": "create a directory (mkdir <name>)",
    "mv": "move/rename a file (mv <source> <destination>)",
    "nano": "edit a file (nano <file>)",
    "ping": "test connectivity to a host (ping <host>)",
    "realnode": "inspect internal device attributes (realnode <property>)",
    "rm": "delete a file (rm <file>)",
    "systemctl": "control system services (systemctl start|stop|restart|status <service>)",
    "touch": "create an empty file (touch <file>)",
    "traceroute": "trace the route to a host (traceroute <host>)",
    "visual": "toggle the packet visualization mode (visual [on|off])",
}

/**
 * Handles the `help` terminal command: prints every command in the registry, sorted
 * alphabetically, with a pointer to the Kerberos tools.
 *
 * @param {string} networkObjectId - The DOM element ID of the client/device running the command.
 * @returns {void}
 */
function command_help(networkObjectId) {

    terminalMessage("Type one of these commands in the terminal:", networkObjectId, false);

    for (const command of Object.keys(commandManual).sort()) {
        terminalMessage(`  ${command.padEnd(17, " ")} ${commandManual[command]}`, networkObjectId, false);
    }

    terminalMessage("", networkObjectId, false);
    terminalMessage("Kerberos SSO tips: run <b>kinit &lt;user&gt;</b> first — pages fetched with curl/browser then present an automatic AP-REQ. <b>klist</b> shows tickets, <b>kdestroy</b> logs out.", networkObjectId);

}
