/**
 * @fileoverview Network configuration ("autogen") library. Provides the shared registry
 * where every scenario file saved in the `/config` folder registers itself, a schema
 * validator for the configuration format, and the board builder that renders a whole
 * network from a single declarative configuration object.
 *
 * ## Configuration format
 *
 * Every network object is declared with an explicit DOM id (so cables and IP plans are
 * deterministic), a board position, a set of interfaces (each optionally bound to a
 * switch with a cable), optional installed packages, filesystem file contents, extra
 * HTML attributes, a default gateway, and router static routes:
 *
 *     {
 *       "devices": [
 *           {
 *               "type": "pc",                       // "pc" | "router" | "switch" | "dns-server"
 *               "id": "pc-1",                       // "<type>-<index>", unique
 *               "x": 120, "y": 140,                 // board position in pixels
 *               "interfaces": {                     // optional; keyed by interface name
 *                   "enp0s3": {
 *                       "ip": "192.168.10.10",      // static address (required)
 *                       "netmask": "255.255.255.0",
 *                       "switch": "switch-1"        // switch DOM id to cable into (optional)
 *                   }
 *               },
 *               "packages": ["apache2"],            // optional; installed after creation
 *               "attrs": { "kdc": "true" },         // optional; raw attribute overrides (applied last)
 *               "files": [                          // optional; /etc file contents to seed
 *                   {"path": "/etc/resolv.conf", "content": "nameserver 10.1.30.10\n"}
 *               ],
 *               "gateway": "192.168.10.1",          // optional; default route via that IP
 *               "routes": [                         // optional; static routes (routers mainly)
 *                   {"destination": "10.1.20.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.1"}
 *               ]
 *           }
 *       ]
 *     }
 *
 * All addresses are configured statically: the autogen flow does not run DHCP discovery
 * (add the `isc-dhcp-client` package and hand-author `dnsmasq`/`isc-dhcp` config manually
 * if a scenario needs a lease negotiation demo).
 */

/** @type {string} Panel icon used by the autogen button in the bottom bar. */
const $AUTOGENTEMPLATEICON = "./assets/panel/template.svg";

/**
 * Device-type builders. Keys are the `type` field values accepted in configs; values are
 * the same element builders the icon drop flow uses (board.js `boardItemRender`).
 * @type {Record<string, Function>}
 */
const $AUTOGENDEVICEBUILDERS = {
    "pc": PcObject,
    "router": RouterObject,
    "switch": SwitchObject,
    "dns-server": DnsServerObject,
};

/**
 * Extra packages that can be installed on autogen devices beyond each builder's defaults.
 * Keys are package names; values are the installer functions from `packages/*_pkg.js`.
 * @type {Record<string, Function>}
 */
const $AUTOGENPACKAGEINSTALLERS = {
    "apache2": installApache2,
    "nginx": installNginx,
    "krb5-kdc": installKrb5Kdc,
    "bind9": installBind9,
    "iptables": installIptables,
    "resolved": installResolved,
};

/** @type {Map<string, {label: string, description: string, config: Object}>} Scenario registry keyed by scenario id. */
const autogenScenarioRegistry = new Map();

/**
 * Registers an autogen scenario. Called at load time by every file in `/config`.
 *
 * @param {string} id - Stable scenario identifier (used by the menu wiring).
 * @param {string} label - Human-readable menu text (e.g. "Autogen homelab").
 * @param {string} description - One-line description shown in the confirmation popup.
 * @param {Object} config - The configuration object (see the file overview for the schema).
 * @returns {void}
 */
function registerAutogenScenario(id, label, description, config) {
    autogenScenarioRegistry.set(id, {"label": label, "description": description, "config": config});
}

/**
 * Returns the registered scenarios in registration order.
 *
 * @returns {Array<{id: string, label: string, description: string, config: Object}>}
 */
function getAutogenScenarios() {
    return Array.from(autogenScenarioRegistry.entries(), ([id, scenario]) => ({"id": id, ...scenario}));
}

/**
 * Validates a configuration object against the autogen schema. Throws on the first
 * structural or semantic violation, quoting the offending device or cable.
 *
 * @param {Object} config - The configuration object to validate.
 * @returns {void}
 * @throws {Error} No devices, unknown device type, malformed id, duplicate id, invalid
 *   position, invalid IP/netmask/gateway/route fields, unknown switch reference, or an
 *   interface name outside the simulated `enp0s{3,8,9}` set.
 */
function validateAutogenConfig(config) {

    if (!config || !Array.isArray(config.devices) || config.devices.length === 0) {
        throw new Error("autogen: the configuration must declare a non-empty 'devices' array.");
    }

    const declaredSwitches = new Set(config.devices.filter(device => device.type === "switch").map(device => device.id));
    const seenIds = new Set();

    for (const device of config.devices) {

        if (!$AUTOGENDEVICEBUILDERS[device.type]) throw new Error(`autogen: unknown device type "${device.type}" (${device.id})`);
        if (!device.id || !device.id.startsWith(`${device.type}-`)) throw new Error(`autogen: device id "${device.id}" must start with "${device.type}-"`);
        if (seenIds.has(device.id)) throw new Error(`autogen: duplicate device id "${device.id}"`);
        if (!Number.isFinite(device.x) || !Number.isFinite(device.y)) throw new Error(`autogen: device "${device.id}" needs numeric x/y coordinates`);

        seenIds.add(device.id);

        for (const [iface, ifaceConfig] of Object.entries(device.interfaces || {})) {

            if (!/^enp0s(3|8|9)$/.test(iface)) throw new Error(`autogen: device "${device.id}" declares the unsupported interface "${iface}"`);

            if (!isValidIp(ifaceConfig.ip)) throw new Error(`autogen: device "${device.id}" interface "${iface}" has an invalid IP "${ifaceConfig.ip}"`);
            if (!isValidIp(ifaceConfig.netmask)) throw new Error(`autogen: device "${device.id}" interface "${iface}" has an invalid netmask "${ifaceConfig.netmask}"`);

            if (ifaceConfig.switch) {
                if (!declaredSwitches.has(ifaceConfig.switch)) throw new Error(`autogen: device "${device.id}" interface "${iface}" references the unknown switch "${ifaceConfig.switch}"`);
            }
        }

        if (device.routes) {
            for (const rule of device.routes) {
                if (!isValidIp(rule.destination)) throw new Error(`autogen: device "${device.id}" route destination "${rule.destination}" is not a valid IP`);
                if (!isValidIp(rule.netmask)) throw new Error(`autogen: device "${device.id}" route netmask "${rule.netmask}" is not valid`);
                if (!isValidIp(rule.nexthop)) throw new Error(`autogen: device "${device.id}" route nexthop "${rule.nexthop}" is not a valid IP`);
                if (getNetwork(rule.destination, rule.netmask) !== rule.destination) throw new Error(`autogen: device "${device.id}" route destination "${rule.destination}" is not a network address`);
            }
        }

        for (const element of device.files || []) {
            if (!element.path || !element.content || !pathBuilder(element.path).length) {
                throw new Error(`autogen: device "${device.id}" declares an invalid file write ${JSON.stringify(element)}`);
            }
        }
    }
}

/**
 * Seeds a file into a device's virtual filesystem, creating missing parent directories.
 * Paths are rooted at `/` (e.g. `/etc/hosts`).
 *
 * @param {string} networkObjectId - DOM id of the device element.
 * @param {string} filePath - Absolute file path (e.g. "/etc/resolv.conf").
 * @param {string} content - Full file content to set.
 * @returns {void}
 */
function writeAutogenFile(networkObjectId, filePath, content) {

    const $networkObject = document.getElementById(networkObjectId);
    const fileSystem = new FileSystem($networkObject);
    const segments = pathBuilder(filePath); //<-- ["etc", "hosts"] (root "/" dropped by the builder helper)
    const fileName = segments.pop();

    //create any missing parent directories (mkdir returns early when the folder exists)
    for (let depth = 0; depth < segments.length; depth++) {
        fileSystem.mkdir(segments[depth], segments.slice(0, depth));
    }

    if (fileSystem.isDirectory(fileName, segments)) throw new Error(`autogen: ${filePath} on ${networkObjectId} is a directory`);

    if (fileSystem.isFile(fileName, segments)) fileSystem.write(fileName, segments, content);
    else {
        fileSystem.touch(fileName, segments);
        fileSystem.write(fileName, segments, content);
    }

}

/**
 * Applies one device's option block to its freshly created element: attributes, package
 * installs, static interface configuration, seeded files.
 *
 * Attributes are applied *after* packages so scenario values override installer defaults.
 *
 * @param {Object} device - The configuration device block.
 * @param {HTMLElement} $device - The element created for it (its `data-*` base attributes are in place).
 * @returns {void}
 */
function applyAutogenDeviceOptions(device, $device) {

    for (const installer of device.packages || []) {

        const install = $AUTOGENPACKAGEINSTALLERS[installer];

        if (!install) throw new Error(`autogen: device "${device.id}" requests the unknown package "${installer}"`);

        install($device);
    }

    for (const [attribute, value] of Object.entries(device.attrs || {})) $device.setAttribute(attribute, value);

    for (const [iface, ifaceConfig] of Object.entries(device.interfaces || {})) {
        configureInterface(device.id, ifaceConfig.ip, ifaceConfig.netmask, iface);
    }

    for (const fileWrite of device.files || []) writeAutogenFile(device.id, fileWrite.path, fileWrite.content);

}

/**
 * Builds the whole board from an already validated configuration object.
 *
 * The current workspace is torn down (timers cleared, board emptied, the SVG cable layer
 * rebuilt exactly like `itemBoard()` does), each device is created with the same element
 * builders the manual icon drop flow uses, cables are drawn and bound (`data-switch-*`
 * attributes + switch port rows), gateways and router static routes are applied, and the
 * global `itemIndex` is rewound past the highest generated id.
 *
 * @param {Object} config - The configuration object.
 * @returns {{deviceCount: number, cableCount: number}} Board summary for the success popup.
 * @throws {Error} Schema violations (validated first) and any element-builder failure;
 *   on throw the board must be considered partially loaded (the caller shows the error).
 */
function buildNetworkFromConfig(config) {

    validateAutogenConfig(config);

    cleanUpWorkspace();

    const $board = document.querySelector(".board");

    //reset the workspace: fresh device + SVG cable layers, identical to itemBoard()'s markup
    $board.innerHTML = `
        <svg ondragover="dragOverBoard(event)" id="svg-board" rope-start="startId" rope-end="endId"
        preserveAspectRatio="none" width="100%" height="100%" style="position: absolute; top: 0; left: 0;">
        </svg>
    `;

    let cableCount = 0;

    //1. create the devices
    config.devices.forEach((device, position) => {

        itemIndex = position + 1; //<-- unique per build; only used by the builders to stamp a transient id, reasserted below

        const $device = $AUTOGENDEVICEBUILDERS[device.type](device.x, device.y);

        $device.id = device.id; //<-- reassert the exact id (independent of the itemIndex parse)
        document.querySelector(".board").appendChild($device); //<-- mount it now: every setup step looks the device up by id

        applyAutogenDeviceOptions(device, $device);

        //position: element builders clip to the board; user coordinates win after that
        $device.style.left = `${device.x}px`;
        $device.style.top = `${device.y}px`;

    });

    //2. draw the cables and bind both endpoints
    for (const device of config.devices) {
        for (const [iface, ifaceConfig] of Object.entries(device.interfaces || {})) {

            if (!ifaceConfig.switch) continue;

            const $switch = document.getElementById(ifaceConfig.switch);
            const $device = document.getElementById(device.id);

            CableObject($device.style.left, $device.style.top, $switch.style.left, $switch.style.top, device.id, ifaceConfig.switch, iface);
            addSwitchPort(ifaceConfig.switch, device.id);
            $device.setAttribute(`data-switch-${iface}`, ifaceConfig.switch);

            cableCount++;

        }
    }

    //3. close the icons of fully-cabled devices (mirrors the manual drop flow)
    for (const device of config.devices) {
        if (getAvailableInterface(device.id) === false) document.getElementById(device.id).querySelector("img").draggable = false;
    }

    //4. gateways and static routes (all interfaces exist at this point)
    for (const device of config.devices) {

        if (device.gateway) setDefaultGateway(device.id, device.gateway);

        for (const rule of device.routes || []) {
            setRemoteRoutingRule(device.id, rule.destination, rule.netmask, "0.0.0.0", rule.iface, rule.nexthop);
        }

    }

    //5. rewind the item index past the generated ids so later manual drag-and-drops stay unique:
    //   use the highest numeric id suffix declared in the config; when every id is name-based
    //   (e.g. "pc-gamma"), the device count is the next free index instead.
    const numericSuffixes = config.devices
        .map(device => Number.parseInt(device.id.split("-").pop()))
        .filter(suffix => Number.isFinite(suffix));

    itemIndex = (numericSuffixes.length > 0) ? Math.max(...numericSuffixes) + 1 : config.devices.length + 1;

    return {"deviceCount": config.devices.length, "cableCount": cableCount};

}
