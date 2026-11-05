/** Built-in defaults. A user config only needs to override what it changes (objects merge, arrays replace). */
export const DEFAULTS: Record<string, unknown> = {
  "sourceGroups": {
    "kev": {
      "everyMinutes": 60,
      "sources": [
        "kev"
      ]
    },
    "advisories": {
      "everyMinutes": 360,
      "sources": [
        "osv",
        "ghsa",
        "nvd",
        "epss"
      ]
    },
    "bulletins": {
      "everyMinutes": 1440,
      "sources": [
        "rss"
      ]
    },
    "inventory-scan": {
      "everyMinutes": 1440,
      "sources": [
        "inventory",
        "scan"
      ]
    },
    "digest": {
      "everyMinutes": 1440,
      "sources": [
        "digest"
      ]
    }
  },
  "localRuntimes": {
    "includeNode": true
  },
  "thresholds": {
    "page": 100,
    "alert": 60,
    "digest": 35
  },
  "scoring": {
    "severity": {
      "critical": 80,
      "high": 60,
      "medium": 35,
      "low": 10,
      "unknown": 30
    },
    "kevBoost": 50,
    "epss": [
      {
        "min": 0.5,
        "boost": 25
      },
      {
        "min": 0.1,
        "boost": 12
      },
      {
        "min": 0.01,
        "boost": 4
      }
    ],
    "runtimeBoost": 10,
    "unverifiedPenalty": 20
  },
  "autoFix": {
    "patchBumpsQueued": true,
    "requireTestsPass": true,
    "nonPatchRequiresApproval": true,
    "neverPushOrDeploy": true
  },
  "remediation": {
    "dryRun": true,
    "minTier": "alert",
    "maxPerRun": 3,
    "hook": {
      "url": "",
      "secretEnv": "OSMOSECURE_HOOK_SECRET"
    }
  },
  "notify": {
    "notifiers": [
      {
        "type": "stdout"
      }
    ],
    "maxFindingsPerMessage": 10
  },
  "scan": {
    "prefer": "auto",
    "maxDetailFetchPerRun": 400,
    "includeDevDependencies": false
  },
  "feeds": {
    "lookbackDays": 3,
    "userAgent": "osmosecure/0.1 (open-source vulnerability watcher)",
    "minIntervalMs": {
      "default": 1000,
      "nvd": 6500,
      "github": 1000
    },
    "kev": {
      "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    },
    "osv": {
      "baseUrl": "https://osv-vulnerabilities.storage.googleapis.com",
      "apiUrl": "https://api.osv.dev",
      "ecosystems": [
        "npm",
        "Packagist",
        "RubyGems",
        "PyPI"
      ],
      "maxIdsPerRun": 300
    },
    "ghsa": {
      "url": "https://api.github.com/advisories",
      "perPage": 100
    },
    "nvd": {
      "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
      "maxResults": 500,
      "maxPages": 6
    },
    "epss": {
      "url": "https://api.first.org/data/v1/epss",
      "batchSize": 50
    },
    "rss": [
      {
        "id": "oss-security",
        "name": "oss-security mailing list",
        "url": "https://seclists.org/rss/oss-sec.rss",
        "enabled": true
      },
      {
        "id": "php-news",
        "name": "php.net news",
        "url": "https://www.php.net/feed.atom",
        "enabled": true
      },
      {
        "id": "nginx-news",
        "name": "nginx news",
        "url": "https://nginx.org/index.rss",
        "enabled": true
      },
      {
        "id": "nodejs-vuln",
        "name": "Node.js vulnerability feed",
        "url": "https://nodejs.org/en/feed/vulnerability.xml",
        "enabled": true
      },
      {
        "id": "debian-dsa",
        "name": "Debian security advisories",
        "url": "https://www.debian.org/security/dsa",
        "enabled": true
      },
      {
        "id": "ubuntu-usn",
        "name": "Ubuntu security notices",
        "url": "https://ubuntu.com/security/notices/rss.xml",
        "enabled": true
      },
      {
        "id": "openssl",
        "name": "OpenSSL security advisories",
        "url": "",
        "enabled": false,
        "todo": "no stable feed URL known; set one in your config if you have it"
      },
      {
        "id": "postgresql",
        "name": "PostgreSQL security",
        "url": "",
        "enabled": false,
        "todo": "no stable feed URL known; set one in your config if you have it"
      }
    ]
  },
  "triage": {
    "backend": "claude-cli",
    "maxItemsPerRun": 25,
    "maxInputChars": 6000,
    "maxOutputTokens": 1200
  }
};

export function deepMerge(base: unknown, over: unknown): unknown {
  const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
  if (!isObj(base) || !isObj(over)) return over === undefined ? base : over;
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = k in base ? deepMerge(base[k], v) : v;
  return out;
}
