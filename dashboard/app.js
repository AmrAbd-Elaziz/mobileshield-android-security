"use strict";

const DASHBOARD_DATA_URL = "data.json";

const severityColors = {
  Critical: "#ff3b5c",
  High: "#ff923d",
  Medium: "#ffd34e",
  Low: "#48a7ff",
  Informational: "#849189",
};

const masvsNames = {
  "MASVS-STORAGE": "Secure Storage",
  "MASVS-CRYPTO": "Cryptography",
  "MASVS-AUTH": "Authentication",
  "MASVS-NETWORK": "Network Security",
  "MASVS-PLATFORM": "Platform Interaction",
  "MASVS-CODE": "Code Quality",
  "MASVS-RESILIENCE": "App Resilience",
  "MASVS-PRIVACY": "Privacy",
};

const state = {
  data: null,
  findings: [],
  search: "",
  severity: "All",
  masvs: "All",
  status: "All",
};

function getElement(id) {
  const element = document.getElementById(id);

  if (!element) {
    throw new Error(`Missing dashboard element: ${id}`);
  }

  return element;
}

function setText(id, value) {
  getElement(id).textContent = String(value);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function severityClass(severity) {
  return `badge-${severity.toLowerCase()}`;
}

function formatPercentage(value) {
  const numericValue = Number(value);

  if (Number.isInteger(numericValue)) {
    return `${numericValue}%`;
  }

  return `${numericValue.toFixed(1)}%`;
}

function renderMetrics(data) {
  const metrics = data.metrics;
  const coverage = formatPercentage(
    metrics.validation_coverage,
  );

  setText("critical-count", metrics.critical_findings);
  setText("total-count", metrics.total_findings);
  setText("passed-count", metrics.controls_passed);
  setText("masvs-count", metrics.masvs_areas_covered);
  setText("test-count", metrics.automated_tests);
  setText("coverage-count", coverage);

  setText(
    "phone-controls",
    `${metrics.controls_passed}/${metrics.remediation_controls}`,
  );

  setText("phone-coverage", coverage);
  setText("ring-value", coverage);
  setText("assurance-passed", metrics.controls_passed);

  setText(
    "assurance-failed",
    metrics.remediation_controls -
      metrics.controls_passed,
  );

  setText(
    "assurance-closed",
    metrics.closed_findings,
  );

  const ring = document.querySelector(
    ".assurance-ring",
  );

  if (ring) {
    const angle =
      (metrics.validation_coverage / 100) * 360;

    ring.style.background = `
      conic-gradient(
        var(--android) 0deg ${angle}deg,
        #1c2721 ${angle}deg 360deg
      )
    `;
  }
}

function renderSeverityBars(distribution) {
  const container = getElement("severity-bars");

  const entries = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
  ];

  const maximum = Math.max(
    ...entries.map(
      (severity) => distribution[severity] || 0,
    ),
    1,
  );

  container.innerHTML = entries
    .map((severity) => {
      const count = distribution[severity] || 0;
      const width = (count / maximum) * 100;
      const color =
        severityColors[severity] ||
        severityColors.Informational;

      return `
        <div class="bar-row">
          <p>${escapeHtml(severity)}</p>

          <div
            class="bar-track"
            role="progressbar"
            aria-label="${escapeHtml(severity)} findings"
            aria-valuemin="0"
            aria-valuemax="${maximum}"
            aria-valuenow="${count}"
          >
            <span
              class="bar-fill"
              style="
                width: ${width}%;
                --bar-color: ${color};
              "
            ></span>
          </div>

          <strong>${count}</strong>
        </div>
      `;
    })
    .join("");
}

function populateMasvsFilter(distribution) {
  const select = getElement("masvs-filter");

  Object.entries(distribution)
    .filter(([, count]) => count > 0)
    .forEach(([group]) => {
      const option = document.createElement("option");
      option.value = group;
      option.textContent = group;
      select.appendChild(option);
    });
}

function renderMasvsCoverage(distribution) {
  const container = getElement("masvs-cards");

  container.innerHTML = Object.entries(distribution)
    .map(([group, count], index) => {
      const active = count > 0;
      const name = masvsNames[group] || group;

      return `
        <article
          class="coverage-card ${active ? "active" : ""}"
        >
          <small>
            AREA ${String(index + 1).padStart(2, "0")}
          </small>

          <h3>${escapeHtml(group)}</h3>

          <strong>${count}</strong>

          <p>${escapeHtml(name)}</p>
        </article>
      `;
    })
    .join("");
}

function renderWorkflow(stages) {
  const container = getElement("workflow-steps");

  container.innerHTML = stages
    .map(
      (stage, index) => `
        <article class="workflow-card">
          <span class="workflow-number">
            STAGE ${String(index + 1).padStart(2, "0")}
          </span>

          <h3>${escapeHtml(stage.stage)}</h3>

          <p>${escapeHtml(stage.description)}</p>
        </article>
      `,
    )
    .join("");
}

function matchesSearch(finding) {
  if (!state.search) {
    return true;
  }

  const searchable = [
    finding.finding_id,
    finding.title,
    finding.category,
    finding.severity,
    finding.masvs_group,
    finding.maswe_id,
    finding.file_path,
    finding.evidence,
    finding.control,
    finding.disposition,
  ]
    .join(" ")
    .toLowerCase();

  return searchable.includes(state.search);
}

function getFilteredFindings() {
  return state.findings.filter((finding) => {
    const severityMatches =
      state.severity === "All" ||
      finding.severity === state.severity;

    const masvsMatches =
      state.masvs === "All" ||
      finding.masvs_group === state.masvs;

    const statusMatches =
      state.status === "All" ||
      finding.disposition === state.status;

    return (
      matchesSearch(finding) &&
      severityMatches &&
      masvsMatches &&
      statusMatches
    );
  });
}

function renderFindings() {
  const tbody = getElement("findings-body");
  const emptyState = getElement("empty-state");
  const filtered = getFilteredFindings();

  setText(
    "result-count",
    `${filtered.length} of ${state.findings.length} findings`,
  );

  if (filtered.length === 0) {
    tbody.innerHTML = "";
    emptyState.hidden = false;
    return;
  }

  emptyState.hidden = true;

  tbody.innerHTML = filtered
    .map(
      (finding) => `
        <tr>
          <td>
            <span class="finding-id">
              ${escapeHtml(finding.finding_id)}
            </span>
          </td>

          <td class="finding-title">
            <strong>
              ${escapeHtml(finding.title)}
            </strong>

            <small>
              ${escapeHtml(finding.category)}
            </small>
          </td>

          <td>
            <span
              class="badge ${severityClass(finding.severity)}"
            >
              ${escapeHtml(finding.severity)}
            </span>
          </td>

          <td class="mapping-cell">
            <strong>
              ${escapeHtml(finding.masvs_group)}
            </strong>

            <small>
              ${escapeHtml(finding.maswe_id)}
            </small>
          </td>

          <td>
            ${escapeHtml(finding.target_sla)}
          </td>

          <td>
            <span class="badge badge-closed">
              ${escapeHtml(finding.disposition)}
            </span>
          </td>
        </tr>
      `,
    )
    .join("");
}

function attachFilterEvents() {
  const searchInput = getElement("search-input");
  const severityFilter = getElement("severity-filter");
  const masvsFilter = getElement("masvs-filter");
  const statusFilter = getElement("status-filter");

  searchInput.addEventListener("input", (event) => {
    state.search = event.target.value
      .trim()
      .toLowerCase();

    renderFindings();
  });

  severityFilter.addEventListener(
    "change",
    (event) => {
      state.severity = event.target.value;
      renderFindings();
    },
  );

  masvsFilter.addEventListener(
    "change",
    (event) => {
      state.masvs = event.target.value;
      renderFindings();
    },
  );

  statusFilter.addEventListener(
    "change",
    (event) => {
      state.status = event.target.value;
      renderFindings();
    },
  );
}

function attachNavigationState() {
  const links = document.querySelectorAll(
    ".navigation a",
  );

  const sections = Array.from(links)
    .map((link) => {
      const target = document.querySelector(
        link.getAttribute("href"),
      );

      return {
        link,
        target,
      };
    })
    .filter((item) => item.target);

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) {
          return;
        }

        sections.forEach(({ link, target }) => {
          const isActive = target === entry.target;

          link.style.color = isActive
            ? "var(--android)"
            : "";

          link.setAttribute(
            "aria-current",
            isActive ? "page" : "false",
          );
        });
      });
    },
    {
      rootMargin: "-25% 0px -65% 0px",
      threshold: 0,
    },
  );

  sections.forEach(({ target }) => {
    observer.observe(target);
  });
}

function revealOnScroll() {
  const elements = document.querySelectorAll(
    [
      ".metric-card",
      ".state-panel",
      ".data-panel",
      ".coverage-card",
      ".workflow-card",
      ".conclusion",
    ].join(","),
  );

  elements.forEach((element) => {
    element.style.opacity = "0";
    element.style.transform = "translateY(14px)";
    element.style.transition =
      "opacity 500ms ease, transform 500ms ease";
  });

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) {
          return;
        }

        entry.target.style.opacity = "1";
        entry.target.style.transform = "translateY(0)";
        observer.unobserve(entry.target);
      });
    },
    {
      threshold: 0.08,
    },
  );

  elements.forEach((element, index) => {
    element.style.transitionDelay =
      `${Math.min(index % 6, 5) * 45}ms`;

    observer.observe(element);
  });
}

function showLoadingError(error) {
  console.error(error);

  const tbody = getElement("findings-body");

  tbody.innerHTML = `
    <tr>
      <td colspan="6">
        <div class="empty-state">
          Dashboard data could not be loaded.
          Start a local HTTP server instead of opening
          index.html directly.
        </div>
      </td>
    </tr>
  `;
}

async function initializeDashboard() {
  try {
    const response = await fetch(
      DASHBOARD_DATA_URL,
      {
        cache: "no-store",
      },
    );

    if (!response.ok) {
      throw new Error(
        `Dashboard data request failed: ${response.status}`,
      );
    }

    const data = await response.json();

    state.data = data;
    state.findings = data.findings;

    renderMetrics(data);
    renderSeverityBars(
      data.severity_distribution,
    );
    populateMasvsFilter(
      data.masvs_distribution,
    );
    renderMasvsCoverage(
      data.masvs_distribution,
    );
    renderWorkflow(data.security_flow);
    renderFindings();

    attachFilterEvents();
    attachNavigationState();
    revealOnScroll();
  } catch (error) {
    showLoadingError(error);
  }
}

document.addEventListener(
  "DOMContentLoaded",
  initializeDashboard,
);