/**
 * Returns the autogen button for the bottom item panel, together with its hidden
 * pop-up menu. The menu floats *upward* from the button icon and lists every scenario
 * file that registered itself into the autogen registry (the `/config` folder). It is
 * populated lazily on first open, so dropping new files into `/config` extends the
 * menu without further UI wiring.
 *
 * Clicking an option asks for confirmation (loading replaces the current workspace)
 * and then renders the whole network through `buildNetworkFromConfig`.
 *
 * @returns {HTMLElement} The button element (the menu is attached as a hidden child).
 */
function autogenButton() {

    const $autogenButton = document.createElement("div");

    $autogenButton.classList.add("item", "autogen");
    $autogenButton.draggable = false;

    $autogenButton.innerHTML = `
        <img src="${$AUTOGENTEMPLATEICON}" alt="autogen" draggable="false">
        <div class="autogen-menu hidden"></div>
    `;

    return $autogenButton;

}

/**
 * Opens (or closes) the autogen pop-up menu. First use builds one option entry per
 * registered scenario; entries re-sync on every open, so late registrations are picked
 * up too.
 *
 * @returns {void}
 */
function toggleAutogenMenu() {

    const $menu = document.querySelector(".autogen-menu");

    if ($menu.classList.contains("hidden")) {

        const scenarios = getAutogenScenarios();

        $menu.innerHTML = "";

        for (const scenario of scenarios) {
            const $option = document.createElement("button");
            $option.classList.add("autogen-option");
            $option.title = scenario.description;
            $option.textContent = scenario.label;
            $option.addEventListener("click", () => selectAutogenScenario(scenario.id));
            $menu.appendChild($option);
        }

        $menu.classList.remove("hidden");

    } else {
        $menu.classList.add("hidden");
    }

}

/**
 * Asks the user to confirm before replacing the current workspace with a scenario,
 * then loads it. Board errors popup instead of mutating state silently.
 *
 * @param {string} scenarioId - Identifier the scenario was registered with.
 * @returns {void}
 */
function selectAutogenScenario(scenarioId) {

    const scenario = autogenScenarioRegistry.get(scenarioId);

    if (!scenario) return;

    if (document.querySelectorAll(".item-dropped").length > 0) {
        bodyComponent.render(confirmPopup(
            `Load <em>${scenario.label}</em>?<br>This replaces the current workspace: ${scenario.description}`,
            () => autogenScenarioLoadHandler(scenario.label, scenario.config)
        ));
    } else {
        autogenScenarioLoadHandler(scenario.label, scenario.config); //<-- empty board: no need to confirm
    }

}

/**
 * Runs the board build for a scenario and reports the outcome in a popup.
 *
 * @param {string} label - Scenario label for the success message.
 * @param {Object} config - The scenario configuration object.
 * @returns {void}
 */
function autogenScenarioLoadHandler(label, config) {

    try {
        const summary = buildNetworkFromConfig(config);
        bodyComponent.render(popupMessage(`Scenario <em>${label}</em> loaded successfully: <em>${summary.deviceCount}</em> devices and <em>${summary.cableCount}</em> cables.`, $AUTOGENTEMPLATEICON));
    } catch (error) {
        bodyComponent.render(popupMessage(`<span>Error: </span>${error.message}`, $AUTOGENTEMPLATEICON));
    }

}
