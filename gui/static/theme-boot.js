// Runs synchronously in <head> so a forced theme applies before first paint.
// (CSP forbids inline scripts, hence this tiny external file.)
"use strict";
(function () {
    try {
        var t = localStorage.getItem("lp-theme");
        if (t === "light" || t === "dark") {
            document.documentElement.setAttribute("data-theme", t);
        }
    } catch (e) { /* storage disabled — auto theme via media query */ }
})();
