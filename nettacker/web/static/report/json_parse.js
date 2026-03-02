<script>
  (function () {
    const lengthElement = document.getElementById("json_length");
    if (!lengthElement) {
      return;
    }

    const length = parseInt(lengthElement.innerText || "0", 10) || 0;
    lengthElement.innerText = "";

    if (typeof renderjson !== "undefined") {
      renderjson.set_icons("▶", "▼");
      renderjson.set_collapse_msg(function () {
        return "...";
      });
    }

    const rawEvents = [];
    const events = [];

    for (let i = 1; i <= length; i++) {
      const container = document.getElementById("json_event_" + i);
      const button = document.getElementById("json_clipboard_" + i);
      if (!container) {
        continue;
      }
      const value = container.innerText;
      rawEvents.push(value);

      let parsed;
      try {
        parsed = JSON.parse(value);
      } catch (e) {
        parsed = { raw: value };
      }
      events.push(parsed);

      container.innerText = "";

      if (button) {
        button.addEventListener("click", function () {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(value);
          }
        });
      }

      if (typeof renderjson !== "undefined") {
        container.appendChild(renderjson(parsed));
      } else {
        container.textContent = value;
      }
    }

    // Populate basic summary cards (targets, modules, findings)
    try {
      const targets = new Set();
      const modules = new Set();

      events.forEach(function (ev) {
        if (ev.target) {
          targets.add(ev.target);
        }
        if (ev.module_name) {
          modules.add(ev.module_name);
        }
      });

      const findingsCount = events.length;
      const findingsEl = document.getElementById("findings-count");
      if (findingsEl) {
        findingsEl.textContent = String(findingsCount);
      }

      const summaryEl = document.getElementById("report-summary");
      if (summaryEl) {
        summaryEl.innerHTML =
          '<div class="nettacker-report__stat-card">' +
          '<div class="nettacker-report__stat-label">Targets</div>' +
          '<div class="nettacker-report__stat-value">' +
          targets.size +
          "</div>" +
          "</div>" +
          '<div class="nettacker-report__stat-card">' +
          '<div class="nettacker-report__stat-label">Modules</div>' +
          '<div class="nettacker-report__stat-value">' +
          modules.size +
          "</div>" +
          "</div>";
      }
    } catch (e) {
      // Non-fatal, summary is optional
    }

    function downloadBlob(content, fileName, mime) {
      try {
        const blob = new Blob([content], { type: mime });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (e) {
        console.error("Failed to trigger download", e);
      }
    }

    function toCSV(data) {
      if (!data.length) {
        return "";
      }

      const headerSet = new Set();
      data.forEach(function (row) {
        if (row && typeof row === "object") {
          Object.keys(row).forEach(function (key) {
            headerSet.add(key);
          });
        }
      });

      const headers = Array.from(headerSet);
      const escapeCell = function (cell) {
        const str =
          cell === null || cell === undefined
            ? ""
            : typeof cell === "string"
            ? cell
            : JSON.stringify(cell);
        const escaped = str.replace(/"/g, '""');
        return '"' + escaped + '"';
      };

      const rows = [];
      rows.push(headers.map(escapeCell).join(","));
      data.forEach(function (row) {
        rows.push(
          headers
            .map(function (key) {
              return escapeCell(row[key]);
            })
            .join(","),
        );
      });
      return rows.join("\n");
    }

    function toText(data) {
      if (!data.length) {
        return "";
      }
      const lines = [];
      data.forEach(function (ev, index) {
        const parts = [];
        if (ev.date) {
          parts.push("[" + ev.date + "]");
        }
        if (ev.target) {
          parts.push(ev.target);
        }
        if (ev.module_name) {
          parts.push("(" + ev.module_name + ")");
        }
        if (ev.port !== undefined) {
          parts.push("port " + ev.port);
        }
        if (ev.event) {
          parts.push("- " + ev.event);
        }

        const hadStructuredFields = parts.length > 0;
        if (ev.raw) {
          parts.push(ev.raw);
        } else if (!hadStructuredFields) {
          parts.push(String(ev));
        }

        lines.push((index + 1) + ". " + parts.join(" "));
      });
      return lines.join("\n");
    }

    const exportJsonBtn = document.getElementById("export-json");
    if (exportJsonBtn) {
      exportJsonBtn.addEventListener("click", function () {
        downloadBlob(
          JSON.stringify(events, null, 2),
          "nettacker-report.json",
          "application/json",
        );
      });
    }

    const exportCsvBtn = document.getElementById("export-csv");
    if (exportCsvBtn) {
      exportCsvBtn.addEventListener("click", function () {
        const csv = toCSV(events);
        downloadBlob(csv, "nettacker-report.csv", "text/csv");
      });
    }

    const exportTextBtn = document.getElementById("export-text");
    if (exportTextBtn) {
      exportTextBtn.addEventListener("click", function () {
        const txt = toText(events);
        downloadBlob(txt, "nettacker-report.txt", "text/plain");
      });
    }

    const exportPdfBtn = document.getElementById("export-pdf");
    if (exportPdfBtn) {
      exportPdfBtn.addEventListener("click", function () {
        // Delegate PDF generation to the browser's print-to-PDF feature
        window.print();
      });
    }
  })();
</script>