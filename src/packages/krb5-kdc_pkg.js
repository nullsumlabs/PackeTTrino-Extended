/**
 * Installs the Kerberos Key Distribution Center package (krb5-kdc) on a network object.
 * Sets the `kdc` flag attribute and the default `krb5-realm`, seeds the shared mock
 * principal database for that realm, and injects the KDC option button into the
 * advanced-options modal.
 *
 * @param {HTMLElement} $networkObject - The DOM element representing the network device.
 * @returns {void}
 */
function installKrb5Kdc($networkObject) {

    const networkObjectId = $networkObject.id;

    terminalMessage("Installing krb5-kdc...", networkObjectId);

    const $advancedOptions = $networkObject.querySelector(".advanced-options-modal");
    const attr = (attribute, value) => $networkObject.setAttribute(attribute, value);

    attr("kdc", "false");
    attr("krb5-realm", $KRB5DEFAULTREALM);

    seedKerberosDatabase($KRB5DEFAULTREALM); //<-- populate the mock principal database

    if ($advancedOptions) {
        const $kdcOptionButton = document.createElement("button");
        $kdcOptionButton.id = "kdc-option";
        $kdcOptionButton.classList.add("iptab"); //<-- matches the existing advanced-options button styling
        $kdcOptionButton.innerHTML = "KDC";
        $kdcOptionButton.onclick = () => terminalMessage(`kdc service status: ${$networkObject.getAttribute("kdc") === "true" ? "running" : "stopped"} (port ${KDC_LISTEN_PORT}/udp)`, networkObjectId);
        $advancedOptions.appendChild($kdcOptionButton);
    }

    terminalMessage("krb5-kdc installed successfully.", networkObjectId);

}

/**
 * Uninstalls the Kerberos KDC package from a network object.
 * Stops and strips the `kdc` and `krb5-realm` attributes and removes the KDC
 * option button from the advanced-options modal.
 *
 * @param {string} networkObjectId - The DOM element ID of the network device.
 * @returns {void}
 */
function uninstallKrb5Kdc(networkObjectId) {

    terminalMessage("Uninstalling krb5-kdc...", networkObjectId);

    const $networkObject = document.getElementById(networkObjectId);
    const rattr = (...attributes) => attributes.forEach(attribute => $networkObject.removeAttribute(attribute));
    const $optionButton = $networkObject.querySelector("#kdc-option");

    rattr("kdc", "krb5-realm");

    if ($optionButton) $optionButton.remove(); //<-- drop the advanced-options button

    terminalMessage("krb5-kdc uninstalled successfully.", networkObjectId);

}
