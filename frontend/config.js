/**
 * AUTO-RECON AI — Frontend Configuration
 * ====================================================================
 * Configures the backend API Base URL for both local development
 * and production cloud deployments (e.g., Vercel, Railway, Render, AWS, GCP).
 *
 * Requirements:
 * - In local development: defaults to http://127.0.0.1:8000/api
 * - In production: configurable via:
 *     1. window.AUTORECON_API_BASE_URL (injected before this script)
 *     2. URL query parameter: ?api=https://your-backend.domain/api
 *     3. PRODUCTION_API constant defined below
 *     4. window.API_BASE (legacy override)
 * ====================================================================
 */
(function () {
  // 1. Default local backend URL (FastAPI)
  const DEFAULT_LOCAL_API = "http://127.0.0.1:8000/api";

  // 2. Production Backend URL Placeholder
  // Update this once your backend is deployed (e.g. "https://api-autorecon.yourdomain.com/api" or Railway/Render URL)
  // Leave empty ("") while backend hosting is pending to allow automatic fallback & query param overrides.
  const PRODUCTION_API = "";

  // 3. Optional URL query parameter override for easy live testing/staging:
  // e.g. https://auto-recon-ai.vercel.app/?api=https://my-backend.railway.app/api
  let urlParamApi = null;
  if (typeof window !== "undefined" && window.location && window.location.search) {
    try {
      const searchParams = new URLSearchParams(window.location.search);
      if (searchParams.has("api")) {
        urlParamApi = searchParams.get("api");
      }
    } catch (e) {
      // Ignore URL parsing errors on legacy browsers
    }
  }

  // 4. Resolve the active API base URL in order of precedence
  const isLocalhost =
    typeof window !== "undefined" &&
    (window.location.hostname === "localhost" ||
     window.location.hostname === "127.0.0.1" ||
     window.location.hostname === "");

  let resolvedApiBase;
  if (window.AUTORECON_API_BASE_URL) {
    resolvedApiBase = window.AUTORECON_API_BASE_URL;
  } else if (urlParamApi) {
    resolvedApiBase = urlParamApi;
  } else if (PRODUCTION_API && PRODUCTION_API.trim() !== "") {
    resolvedApiBase = PRODUCTION_API.trim();
  } else if (window.API_BASE) {
    resolvedApiBase = window.API_BASE;
  } else if (isLocalhost) {
    resolvedApiBase = DEFAULT_LOCAL_API;
  } else {
    // Production default when no external URL is specified yet:
    // Graceful relative path or local fallback
    resolvedApiBase = DEFAULT_LOCAL_API;
  }

  // Normalize: remove trailing slash if present
  resolvedApiBase = resolvedApiBase.replace(/\/+$/, "");

  // Expose configuration globally
  window.AUTORECON_CONFIG = {
    API_BASE_URL: resolvedApiBase,
    APP_NAME: "AUTO-RECON AI",
    VERSION: "1.0.0",
    IS_LOCAL: isLocalhost,
    ENV: isLocalhost ? "development" : "production",
    GITHUB_REPO: "https://github.com/Vatsa-47/Auto-Recon-AI"
  };

  // Ensure window.API_BASE is set for full backward compatibility with all existing code
  window.API_BASE = resolvedApiBase;

  console.info(`%c[AUTO-RECON AI] Config Loaded%c | API Base: %c${resolvedApiBase}%c | Env: ${window.AUTORECON_CONFIG.ENV}`,
    "background: #1e3a8a; color: #fff; padding: 2px 6px; border-radius: 3px; font-weight: bold;",
    "color: inherit;",
    "color: #2563eb; font-weight: bold;",
    "color: inherit;"
  );
})();
