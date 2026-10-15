import { describe, it, expect, beforeAll } from 'vitest';
import { createWindowWithScripts } from './setup-globals.js';
import vm from 'vm';

/**
 * End-to-end harness for the autogen (network configuration) builder. Loads the same
 * source files the real application loads (in the same relative order), then:
 *
 * 1. checks every `/config` scenario registers itself and passes schema validation;
 * 2. renders the "simple net" and "enterprise" scenarios onto a real (linkedom) board
 *    and asserts the devices, addresses, cables, ports, gateways and filesystem seeds
 *    the configs ask for (gathered inside the vm realm, asserted in the test realm);
 * 3. exercises the rejection paths (unknown device type, bad IP, unknown switch...).
 */

const window = createWindowWithScripts(
    './stubs-autogen.js',
    '../src/env.js',
    '../src/lib/dom_lib.js',
    '../src/components/assemblers/icon.js',
    '../src/components/assemblers/tooltip.js',
    '../src/components/tables/arp_tab.js',
    '../src/components/tables/routing_tab.js',
    '../src/components/tables/mac_tab.js',
    '../src/components/tables/dns_cache_tab.js',
    '../src/components/tables/dns_tab.js',
    '../src/components/menus/advOptionsMenu.js',
    '../src/components/network_elements/cable.js',
    '../src/components/network_elements/pc.js',
    '../src/components/network_elements/router.js',
    '../src/components/network_elements/switch.js',
    '../src/components/network_elements/dns-server.js',
    '../src/lib/network_lib.js',
    '../src/lib/fileSystem_lib.js',
    '../src/lib/component_lib.js',
    '../src/utilities/filesystem_utils.js',
    '../src/services/networkd_service.js',
    '../src/services/routing_service.js',
    '../src/lib/packets_lib.js',
    '../src/lib/kerberos_lib.js',
    '../src/lib/apache2_lib.js',
    '../src/packages/isc-dhcp-client_pkg.js',
    '../src/packages/iptables_pkg.js',
    '../src/packages/browser_pkg.js',
    '../src/packages/apache2_pkg.js',
    '../src/packages/bind9_pkg.js',
    '../src/packages/krb5-kdc_pkg.js',
    '../src/packages/nginx_pkg.js',
    '../src/components/network_tools/terminal.js',
    '../src/lib/network_config_lib.js',
    '../config/simple.autogen.js',
    '../config/homelab.autogen.js',
    '../config/corporate.autogen.js',
    '../config/enterprise.autogen.js',
);

beforeAll(() => {

    //<-- the tests need the terminal in the DOM because package installers print to it
    vm.runInContext(`
        document.body.appendChild(terminal());
    `, window);

});

/**
 * Runs a snippet inside the app's vm realm and returns a JSON-serialisable result, so
 * the test realm can assert on it without touching cross-realm object identities.
 *
 * @param {string} code - Snippet to run in the app realm (must produce a plain value).
 * @returns {*} The evaluated result.
 */
function inAppRealm(code) {
    return vm.runInContext(code, window);
}

describe('Autogen scenario registry (config/ scenario files)', () => {

    it('registers all four scenarios with labels and descriptions', () => {
        const scenarios = window.getAutogenScenarios();

        expect(scenarios.map(scenario => scenario.id)).toEqual([
            "simple-net", "homelab", "corp-net", "enterprise"
        ]);

        expect(scenarios.every(scenario => scenario.label && scenario.description)).toBe(true);
    });

});

describe('Autogen config validation (validateAutogenConfig)', () => {

    it('accepts every scenario file in /config as-is', () => {
        for (const scenario of window.getAutogenScenarios()) {
            expect(() => window.validateAutogenConfig(scenario.config), scenario.id).not.toThrow();
        }
    });

    it('rejects an unknown device type', () => {
        const bad = {"devices": [{"type": "printer", "id": "printer-1", "x": 0, "y": 0}]};
        expect(() => window.validateAutogenConfig(bad)).toThrow(/unknown device type/);
    });

    it('rejects a duplicate device id', () => {
        const bad = {
            "devices": [
                {"type": "switch", "id": "switch-1", "x": 0, "y": 0},
                {"type": "switch", "id": "switch-1", "x": 10, "y": 0}
            ]
        };
        expect(() => window.validateAutogenConfig(bad)).toThrow(/duplicate device id/);
    });

    it('rejects an id that does not match its type prefix', () => {
        const bad = {"devices": [{"type": "pc", "id": "router-1", "x": 0, "y": 0}]};
        expect(() => window.validateAutogenConfig(bad)).toThrow(/must start with/);
    });

    it('rejects an invalid interface IP', () => {
        const bad = {
            "devices": [
                {"type": "switch", "id": "switch-1", "x": 0, "y": 0},
                {"type": "pc", "id": "pc-1", "x": 0, "y": 0, "interfaces": {"enp0s3": {"ip": "999.0.0.1", "netmask": "255.255.255.0", "switch": "switch-1"}}}
            ]
        };
        expect(() => window.validateAutogenConfig(bad)).toThrow(/invalid IP/);
    });

    it('rejects a cable into an unknown switch', () => {
        const bad = {
            "devices": [
                {"type": "pc", "id": "pc-1", "x": 0, "y": 0, "interfaces": {"enp0s3": {"ip": "192.168.10.10", "netmask": "255.255.255.0", "switch": "switch-ghost"}}}
            ]
        };
        expect(() => window.validateAutogenConfig(bad)).toThrow(/unknown switch/);
    });

    it('rejects an unsupported interface name', () => {
        const bad = {
            "devices": [
                {"type": "switch", "id": "switch-1", "x": 0, "y": 0},
                {"type": "pc", "id": "pc-1", "x": 0, "y": 0, "interfaces": {"enp0s77": {"ip": "192.168.10.10", "netmask": "255.255.255.0", "switch": "switch-1"}}}
            ]
        };
        expect(() => window.validateAutogenConfig(bad)).toThrow(/unsupported interface/);
    });

    it('rejects a route destination that is not a network address', () => {
        const bad = {
            "devices": [
                {"type": "router", "id": "router-1", "x": 0, "y": 0, "routes": [{"destination": "10.1.10.1", "netmask": "255.255.255.0", "iface": "enp0s3", "nexthop": "10.0.0.1"}]}
            ]
        };
        expect(() => window.validateAutogenConfig(bad)).toThrow(/not a network address/);
    });

});

describe('Autogen board builder (buildNetworkFromConfig)', () => {

    const configOf = (scenarioId) => window.getAutogenScenarios().find(scenario => scenario.id === scenarioId).config;

    it('renders the simple-net scenario: devices, addresses, cables, ports and gateways', () => {

        const config = configOf("simple-net");
        const summary = window.buildNetworkFromConfig(config);

        expect(summary).toEqual({"deviceCount": 5, "cableCount": 4});

        const facts = inAppRealm(`(function inspect() {
            const config = ${JSON.stringify(config)};

            const facts = {"missingDevices": [], "cables": null, "ports": null, "defaultRoute": null, "pcIp": null, "unusedRouterIface": null, "itemIndex": itemIndex};

            //<-- devices exist with the exact declared ids
            for (const device of config.devices) {
                if (!document.getElementById(device.id)) facts.missingDevices.push(device.id);
            }

            const $pc = document.getElementById("pc-alpha");
            facts.pcIp = $pc.getAttribute("ip-enp0s3");
            facts.unusedRouterIface = document.getElementById("router-gw").getAttribute("ip-enp0s8");

            //<-- cable bindings: each cabled interface points at its switch
            facts.cableBindings = document.querySelectorAll("#svg-board > line").length;

            //<-- switch port rows: one per connected device
            facts.ports = document.getElementById("switch-main").querySelectorAll(".mac-address").length;

            //<-- default route row via the router on a PC
            const $defaultRoute = $pc.querySelector(".routing-table table").querySelector(".default-route");
            facts.defaultRoute = $defaultRoute ? $defaultRoute.querySelectorAll("td")[4].innerHTML : null;

            return facts;
        })()`);

        expect(facts.missingDevices).toEqual([]);
        expect(facts.pcIp).toBe("192.168.10.10");
        expect(facts.unusedRouterIface).toBe(""); //<-- unused interface untouched
        expect(facts.cableBindings).toBe(4); //<-- one <line> per cable
        expect(facts.ports).toBe(4); //<-- router-gw + 3 PCs
        expect(facts.defaultRoute).toBe("192.168.10.1"); //<-- Next Hop column
        expect(facts.itemIndex).toBe(6); //<-- rewound past name-based ids: device count + 1
    });

    it('renders the enterprise scenario: 4 routers, 5 switches, servers and the Kerberos showcase', () => {

        const config = configOf("enterprise");
        const summary = window.buildNetworkFromConfig(config);

        expect(summary.deviceCount).toBe(config.devices.length); //<-- 4 routers + 5 switches + 6 hosts + 4 server devices
        expect(summary.deviceCount).toBe(19);
        expect(summary.cableCount).toBe(18); //<-- every interface with a "switch" field becomes exactly one cable

        const facts = inAppRealm(`(function inspect() {
            const facts = {};

            //<-- router static routes landed (core router: three remote routes)
            facts.coreRemoteRoutes = document.getElementById("router-core").querySelectorAll(".routing-table tr.remote-route").length;

            //<-- Kerberos showcase: KDC running with its realm, nginx installed + gate on
            facts.kdc = document.getElementById("pc-kdc").getAttribute("kdc");
            facts.realm = document.getElementById("pc-kdc").getAttribute("krb5-realm");
            facts.webNginx = document.getElementById("pc-websecure").getAttribute("nginx");
            facts.webGate = document.getElementById("pc-websecure").getAttribute("krb5-required");
            facts.webSpn = document.getElementById("pc-websecure").getAttribute("krb5-spn");

            //<-- seeded /etc/hosts survived the build
            facts.hosts = new FileSystem(document.getElementById("pc-w1")).read("hosts", ["etc"]);

            return facts;
        })()`);

        expect(facts.coreRemoteRoutes).toBe(3);
        expect(facts.kdc).toBe("true");
        expect(facts.realm).toBe("PACKETTRINO.EDU");
        expect(facts.webNginx).toBe("true");
        expect(facts.webGate).toBe("true");
        expect(facts.webSpn).toBe("HTTP/webserver@PACKETTRINO.EDU");
        expect(facts.hosts).toContain("10.1.30.20 secure.corp.lan");
    });

    it('fails loudly on a config referencing a switch that is not a registered device id', () => {
        const bad = {
            "devices": [
                {"type": "switch", "id": "switch-1", "x": 0, "y": 0},
                {"type": "pc", "id": "pc-1", "x": 0, "y": 0, "interfaces": {"enp0s3": {"ip": "192.168.10.10", "netmask": "255.255.255.0", "switch": "switch-2"}}}
            ]
        };
        expect(() => window.buildNetworkFromConfig(bad)).toThrow(/unknown switch/);
    });

});
