/**
 * @description Default welcome page HTML served by the simulated Nginx server when a
 * virtual host matches. Confirms the Kerberos-protected server is running correctly.
 * @type {string}
 */
const $NGINXDEFAULTCONTENT = `
<!DOCTYPE html>
<html lang="en">
<head><title>Nginx PackeTTrino Default Page</title></head>
<body>
<h1>Welcome to nginx!</h1>
<p>This page is served by the PackeTTrino Nginx simulation.</p>
</body>
</html>`;

/**
 * @description Nginx virtual-host configuration template: one site file per server,
 * commented lines included as documentation. Mirrors the Apache vhost XML dialect that
 * the existing site parser understands, so both servers share the serving machinery.
 * @type {string}
 */
const $NGINXDEFAULTCONF = `
# NGINX VIRTUAL HOST - PackeTTrino simulation
<VirtualHost ip="0.0.0.0" port="80">
    <DocumentRoot value="/var/www/nginx" />
    <DirectoryIndex value="index.html" />
    <Options Indexes="false" FollowSymLinks="true" />
    <ServerName></ServerName>
</VirtualHost>`;

/**
 * Installs the Nginx web server package on a network object.
 *
 * Sets the `nginx` service flag (started like Bind9 on install), the Kerberos
 * integration attributes — the served SPN (`krb5-spn`, e.g. `HTTP/webserver@PACKETTRINO.EDU`),
 * the realm, the **private service key** held locally in the node's memory
 * (`krb5-key`, the node's simulated keytab entry), and the
 * `Kerberos Authentication Required` toggle (`krb5-required`, off by default) —
 * registers the SPN in the shared mock Kerberos database so the KDC can issue tickets
 * for it, and creates the default site + document root in the virtual filesystem using
 * the site-parser dialect shared with Apache2.
 *
 * @param {HTMLElement} $networkObject - The DOM element representing the network device.
 * @returns {void}
 */
function installNginx($networkObject) {

    const networkObjectId = $networkObject.id;

    terminalMessage("Installing nginx...", networkObjectId);

    const attr = (attribute, value) => $networkObject.setAttribute(attribute, value);
    const networkObjectFileSystem = new FileSystem($networkObject);

    //nginx attributes

    attr("nginx", "true"); //<-- started on install, like bind9
    attr("krb5-required", "false"); //<-- "Kerberos Authentication Required" toggle (off by default)
    attr("krb5-realm", $KRB5DEFAULTREALM);
    attr("krb5-spn", buildSpn("HTTP", "webserver", $KRB5DEFAULTREALM));

    const serviceProviderKey = "nginx-webserver-key";

    attr("krb5-key", serviceProviderKey); //<-- the private service key, held locally like /etc/krb5.keytab

    //register the SPN in the shared Kerberos mock database (the KDC issues tickets against it)

    const registeredSpn = registerKerberosService("HTTP", "webserver", serviceProviderKey, $KRB5DEFAULTREALM);
    attr("krb5-spn", registeredSpn); //<-- normalise to the exact registered SPN

    //directories and files

    networkObjectFileSystem.mkdir("www", ["var"]); //<-- ensure the parent document-root chain exists
    networkObjectFileSystem.mkdir("nginx", ["var", "www"]);
    networkObjectFileSystem.touch("index.html", ["var", "www", "nginx"]);
    networkObjectFileSystem.write("index.html", ["var", "www", "nginx"], $NGINXDEFAULTCONTENT.replace(/\s+/g, " "));
    networkObjectFileSystem.mkdir("sites", ["etc", "nginx"]);
    networkObjectFileSystem.touch("default.conf", ["etc", "nginx", "sites"]);
    networkObjectFileSystem.write("default.conf", ["etc", "nginx", "sites"], $NGINXDEFAULTCONF);

    //events are added

    if (networkObjectId.startsWith("pc-")) {
        const $iconImage = $networkObject.querySelector("img");
        if ($iconImage) $iconImage.src = "./assets/board/www-server.svg"; //<-- reflect the web-server role
    }

    terminalMessage("nginx installed successfully.", networkObjectId);

}

/**
 * Uninstalls the Nginx web server package from a network object.
 * Removes the virtual filesystem directories created by the installer, strips the
 * `nginx`, Kerberos toggle, SPN/realm, and locally-held private service key attributes,
 * and restores the default PC icon when the element is a PC.
 *
 * The SPN stays registered in the shared mock database (the KDC realm database keeps
 * service entries beyond a node's package inventory), matching real-world KDC behaviour.
 *
 * @param {string} networkObjectId - The DOM element ID of the network device.
 * @returns {void}
 */
function uninstallNginx(networkObjectId) {

    terminalMessage("Uninstalling nginx...", networkObjectId);

    const $networkObject = document.getElementById(networkObjectId);
    const rattr = (...attributes) => attributes.forEach(attribute => $networkObject.removeAttribute(attribute));
    const networkObjectFileSystem = new FileSystem($networkObject);

    networkObjectFileSystem.rmdir("nginx", ["var", "www"]);
    networkObjectFileSystem.rmdir("nginx", ["etc"]);

    rattr("nginx", "krb5-required", "krb5-realm", "krb5-spn", "krb5-key");

    if (networkObjectId.startsWith("pc-")) {
        const $iconImage = $networkObject.querySelector("img");
        if ($iconImage) $iconImage.src = "./assets/board/pc.svg"; //<-- restore the workstation icon
    }

    terminalMessage("nginx uninstalled successfully.", networkObjectId);

}

/**
 * Toggles the "Kerberos Authentication Required" setting of the Nginx server and
 * reports the new state to the terminal. Wired to the advanced-options button.
 *
 * @param {string} networkObjectId - The DOM element ID of the Nginx server device.
 * @returns {void}
 */
function toggleNginxKerberosRequired(networkObjectId) {

    const $networkObject = document.getElementById(networkObjectId);
    const isRequired = $networkObject.getAttribute("krb5-required") === "true";

    $networkObject.setAttribute("krb5-required", isRequired ? "false" : "true");

    terminalMessage(
        isRequired
            ? "nginx: Kerberos Authentication Required is now OFF — anonymous HTTP requests are served."
            : "nginx: Kerberos Authentication Required is now ON — requests must present a valid AP-REQ.",
        networkObjectId,
        false
    );

}
