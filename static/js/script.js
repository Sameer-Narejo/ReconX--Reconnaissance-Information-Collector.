// ReconX front-end script.
// JavaScript runs in the visitor's browser, not on our Flask server.

// Wait until the whole page has been read before looking for elements.
document.addEventListener("DOMContentLoaded", function () {

    // ---------- 1. Loading spinner on the scan form ----------
    const scanForm = document.getElementById("scan-form");
    const scanButton = document.getElementById("scan-button");
    const scanSpinner = document.getElementById("scan-spinner");
    const scanButtonText = document.getElementById("scan-button-text");

    // These elements only exist on the home page, so check first.
    if (scanForm && scanButton) {
        scanForm.addEventListener("submit", function () {
            scanButton.disabled = true;                  // stop double clicks
            scanSpinner.classList.remove("d-none");      // show the spinner
            scanButtonText.textContent = "Scanning...";  // change the label
        });

        // If the visitor comes back with the browser's Back button,
        // put the button back to normal.
        window.addEventListener("pageshow", function () {
            scanButton.disabled = false;
            scanSpinner.classList.add("d-none");
            scanButtonText.textContent = "Start scan";
        });
    }

    // ---------- 2. Filter box for the subdomain table ----------
    const filterBox = document.getElementById("subdomain-filter");
    const filterCount = document.getElementById("subdomain-count");

    // These elements only exist on the dashboard page.
    if (filterBox) {
        const rows = document.querySelectorAll("#subdomain-table tbody tr");

        filterBox.addEventListener("input", function () {
            const wanted = filterBox.value.trim().toLowerCase();
            let shown = 0;

            rows.forEach(function (row) {
                const matches = row.textContent.toLowerCase().includes(wanted);
                row.classList.toggle("d-none", !matches);   // hide rows that do not match
                if (matches) {
                    shown = shown + 1;
                }
            });

            filterCount.textContent = "Showing " + shown + " of " + rows.length;
        });
    }
});
