//Stubs for running the autogen (network config) builder inside the linkedom + vm harness.

//`getComputedStyle` is used by `checkObjectClip` to clamp positions inside the board;
//a big flat window is enough for the tests.
window.matchMedia = window.matchMedia || (() => ({"matches": false, "addEventListener": () => {}, "removeEventListener": () => {}, "addListener": () => {}, "removeListener": () => {}}));
window.getComputedStyle = window.getComputedStyle || (() => ({"getPropertyValue": (property) => (property === "width" || property === "height") ? "4000" : ""}));

//the builder expects a board to render the network into
document.body.innerHTML = `<section class="board"></section>`;
