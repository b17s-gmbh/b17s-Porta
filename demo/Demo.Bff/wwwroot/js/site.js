// Copy-to-clipboard for the demo credential buttons. Falls back to a temporary
// <textarea> + execCommand for non-secure contexts (navigator.clipboard is available
// on http://127.0.0.1 / localhost, which browsers treat as secure).
(function () {
    function flash(button) {
        var original = button.textContent;
        button.textContent = "Copied!";
        setTimeout(function () { button.textContent = original; }, 1200);
    }

    function fallbackCopy(text, button) {
        var area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        try { document.execCommand("copy"); } catch (e) { /* best effort */ }
        area.remove();
        flash(button);
    }

    function copy(text, button) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(
                function () { flash(button); },
                function () { fallbackCopy(text, button); });
        } else {
            fallbackCopy(text, button);
        }
    }

    document.querySelectorAll("button.copy[data-copy]").forEach(function (button) {
        button.addEventListener("click", function () {
            copy(button.getAttribute("data-copy"), button);
        });
    });

    // --- Inline API runner ------------------------------------------------
    // Invoke a BFF endpoint with fetch() and render the response in place, so the
    // demo shows each Porta flow working instead of navigating to a raw JSON page.
    //
    // The browser authenticates to the BFF with the *session cookie* only — that is the
    // core BFF pattern, so the browser never sees an access token. `credentials: "same-origin"`
    // sends that cookie; the BFF then forwards the user's token to the backend server-side
    // (WithBackendAuth(BearerToken)). No Authorization header is ever set here on purpose.
    function prettify(body) {
        try {
            return JSON.stringify(JSON.parse(body), null, 2);
        } catch (e) {
            return body;
        }
    }

    function runEndpoint(button) {
        var method = button.getAttribute("data-method");
        var url = button.getAttribute("data-url");
        var output = button.closest(".endpoint").querySelector(".endpoint-result");

        output.hidden = false;
        output.className = "endpoint-result";
        output.textContent = "Running " + method + " " + url + " …";
        button.disabled = true;

        fetch(url, {
            method: method,
            headers: { "Accept": "application/json" },
            credentials: "same-origin",
            redirect: "manual"
        }).then(function (response) {
            // An opaque redirect means the BFF bounced us to the IdP login — i.e. not signed in.
            if (response.type === "opaqueredirect" || response.status === 0) {
                output.classList.add("err");
                output.textContent = "Not signed in — log in first, then try again.";
                return;
            }
            return response.text().then(function (body) {
                output.classList.add(response.ok ? "ok" : "err");
                var status = response.status + " " + response.statusText;
                var hint = (response.status === 401 || response.status === 403)
                    ? "  (log in first)"
                    : "";
                output.textContent = status + hint + "\n\n" + (prettify(body) || "(empty response)");
            });
        }).catch(function (error) {
            output.classList.add("err");
            output.textContent = "Request failed: " + error;
        }).finally(function () {
            button.disabled = false;
        });
    }

    document.querySelectorAll("button.run[data-url]").forEach(function (button) {
        button.addEventListener("click", function () {
            runEndpoint(button);
        });
    });
})();
