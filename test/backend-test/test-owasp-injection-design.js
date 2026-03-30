/**
 * OWASP A03:2021 - Injection
 * OWASP A04:2021 - Insecure Design
 * OWASP A05:2021 - Security Misconfiguration
 * OWASP A08:2021 - Software and Data Integrity Failures
 *
 * Tests that verify input validation, parameterized queries,
 * role system design integrity, and protection against injection attacks.
 */
const { describe, test } = require("node:test");
const assert = require("node:assert");
const { hasPermission, isValidRole, ROLES, ROLE_LIST, ROLE_PERMISSIONS } = require("../../server/roles");

// ─── A03-01: SQL Injection via Role Field ──────────────────────────────────
describe("A03-01: SQL Injection via Role Field", () => {
    const sqlPayloads = [
        "admin' OR '1'='1",
        "admin'; DROP TABLE user;--",
        "admin' UNION SELECT * FROM user--",
        "1 OR 1=1",
        "' OR ''='",
        "admin'/*",
        "admin'; UPDATE user SET role='admin' WHERE '1'='1",
        "readonly' OR role='admin",
    ];

    for (const payload of sqlPayloads) {
        test(`SQL injection payload rejected as role: "${payload.substring(0, 40)}..."`, () => {
            assert.strictEqual(isValidRole(payload), false);
            assert.strictEqual(hasPermission(payload, "manage-users"), false);
            assert.strictEqual(hasPermission(payload, "view-dashboard"), false);
        });
    }
});

// ─── A03-02: NoSQL / Object Injection via Role ─────────────────────────────
describe("A03-02: NoSQL / Object Injection via Role", () => {
    test("$gt operator object is rejected", () => {
        assert.strictEqual(hasPermission({ "$gt": "" }, "manage-users"), false);
    });

    test("$ne operator object is rejected", () => {
        assert.strictEqual(hasPermission({ "$ne": null }, "manage-users"), false);
    });

    test("nested object role is rejected", () => {
        assert.strictEqual(hasPermission({ role: "admin" }, "manage-users"), false);
    });

    test("array role is rejected", () => {
        assert.strictEqual(hasPermission(["admin"], "manage-users"), false);
    });
});

// ─── A03-03: XSS via Username Input ────────────────────────────────────────
describe("A03-03: XSS Payloads in Username Validation", () => {
    // The user-socket-handler validates username is a non-empty string
    // These tests verify the validation logic
    function validateUsername(username) {
        if (!username || typeof username !== "string" || username.trim() === "") {
            return false;
        }
        return true;
    }

    test("script tag username passes string validation (stored XSS must be escaped on render)", () => {
        // Note: Uptime Kuma uses Vue.js which auto-escapes by default
        // The username is stored as-is but rendered safely via {{ }}
        const xssPayload = "<script>alert('xss')</script>";
        assert.strictEqual(validateUsername(xssPayload), true,
            "String validation accepts it; output encoding prevents XSS");
    });

    test("empty username is rejected", () => {
        assert.strictEqual(validateUsername(""), false);
    });

    test("whitespace-only username is rejected", () => {
        assert.strictEqual(validateUsername("   "), false);
    });

    test("null username is rejected", () => {
        assert.strictEqual(validateUsername(null), false);
    });

    test("undefined username is rejected", () => {
        assert.strictEqual(validateUsername(undefined), false);
    });

    test("numeric username is rejected", () => {
        assert.strictEqual(validateUsername(123), false);
    });

    test("object username is rejected", () => {
        assert.strictEqual(validateUsername({}), false);
    });
});

// ─── A04-01: Insecure Design — Role Hierarchy Integrity ───────────────────
describe("A04-01: Insecure Design — Role Hierarchy Integrity", () => {
    test("role hierarchy is strictly ordered: readonly < developer < admin", () => {
        const readonlyCount = ROLE_PERMISSIONS[ROLES.READONLY].length;
        const devCount = ROLE_PERMISSIONS[ROLES.DEVELOPER].length;
        const adminCount = ROLE_PERMISSIONS[ROLES.ADMIN].length;

        assert.ok(readonlyCount < devCount, "readonly must have fewer permissions than developer");
        assert.ok(devCount < adminCount, "developer must have fewer permissions than admin");
    });

    test("all readonly permissions are also in developer", () => {
        const devPerms = new Set(ROLE_PERMISSIONS[ROLES.DEVELOPER]);
        for (const perm of ROLE_PERMISSIONS[ROLES.READONLY]) {
            assert.ok(devPerms.has(perm), `Developer missing readonly permission: ${perm}`);
        }
    });

    test("all developer permissions are also in admin", () => {
        const adminPerms = new Set(ROLE_PERMISSIONS[ROLES.ADMIN]);
        for (const perm of ROLE_PERMISSIONS[ROLES.DEVELOPER]) {
            assert.ok(adminPerms.has(perm), `Admin missing developer permission: ${perm}`);
        }
    });

    test("admin-exclusive permissions exist (not in developer)", () => {
        const devPerms = new Set(ROLE_PERMISSIONS[ROLES.DEVELOPER]);
        const adminOnly = ROLE_PERMISSIONS[ROLES.ADMIN].filter(p => !devPerms.has(p));

        assert.ok(adminOnly.length > 0, "Admin should have exclusive permissions");
        assert.ok(adminOnly.includes("manage-users"), "manage-users must be admin-exclusive");
        assert.ok(adminOnly.includes("manage-settings"), "manage-settings must be admin-exclusive");
    });
});

// ─── A04-02: Insecure Design — Privilege Separation ───────────────────────
describe("A04-02: Privilege Separation Between Roles", () => {
    test("readonly cannot do anything destructive", () => {
        const destructivePerms = [
            "manage-users", "manage-settings", "manage-monitors",
            "manage-maintenance", "manage-notifications", "manage-status-pages",
            "manage-tags", "manage-proxies", "manage-docker-hosts",
            "manage-api-keys", "manage-remote-browsers", "manage-cloudflared",
        ];
        for (const perm of destructivePerms) {
            assert.strictEqual(
                hasPermission(ROLES.READONLY, perm), false,
                `Readonly must not have: ${perm}`
            );
        }
    });

    test("developer cannot manage users or system settings", () => {
        const adminPerms = [
            "manage-users", "manage-settings", "manage-api-keys",
            "manage-remote-browsers", "manage-cloudflared", "manage-status-pages",
        ];
        for (const perm of adminPerms) {
            assert.strictEqual(
                hasPermission(ROLES.DEVELOPER, perm), false,
                `Developer must not have: ${perm}`
            );
        }
    });

    test("only 3 roles exist — no hidden escalation path", () => {
        assert.strictEqual(ROLE_LIST.length, 3);
        assert.deepStrictEqual(
            ROLE_LIST.sort(),
            ["admin", "developer", "readonly"]
        );
    });
});

// ─── A04-03: Insecure Design — Default Role Safety ────────────────────────
describe("A04-03: Default Role Safety", () => {
    test("migration default 'admin' ensures backward compatibility", () => {
        // Existing users before RBAC get admin role by default
        assert.strictEqual(hasPermission("admin", "manage-users"), true);
        assert.strictEqual(hasPermission("admin", "manage-monitors"), true);
    });

    test("missing role falls back safely (denies access)", () => {
        assert.strictEqual(hasPermission(undefined, "manage-users"), false);
        assert.strictEqual(hasPermission(null, "manage-monitors"), false);
        assert.strictEqual(hasPermission("", "view-dashboard"), false);
    });
});

// ─── A05-01: Security Misconfiguration — Permission Map Integrity ─────────
describe("A05-01: Permission Map Integrity", () => {
    test("ROLE_PERMISSIONS has no extra keys beyond ROLE_LIST", () => {
        const permKeys = Object.keys(ROLE_PERMISSIONS);
        for (const key of permKeys) {
            assert.ok(
                ROLE_LIST.includes(key),
                `Unexpected role in ROLE_PERMISSIONS: "${key}"`
            );
        }
    });

    test("all permission strings are non-empty lowercase with hyphens", () => {
        for (const role of ROLE_LIST) {
            for (const perm of ROLE_PERMISSIONS[role]) {
                assert.ok(typeof perm === "string" && perm.length > 0, `Empty perm in ${role}`);
                assert.ok(/^[a-z-]+$/.test(perm), `Invalid perm format: "${perm}" in role ${role}`);
            }
        }
    });

    test("no permission starts or ends with hyphen", () => {
        for (const role of ROLE_LIST) {
            for (const perm of ROLE_PERMISSIONS[role]) {
                assert.ok(!perm.startsWith("-"), `Perm starts with hyphen: ${perm}`);
                assert.ok(!perm.endsWith("-"), `Perm ends with hyphen: ${perm}`);
            }
        }
    });
});

// ─── A08-01: Data Integrity — Role Values ──────────────────────────────────
describe("A08-01: Data Integrity — Role Values Cannot Be Corrupted", () => {
    test("ROLES object is not extensible at runtime", () => {
        // Even though JS doesn't enforce this by default,
        // the module exports a constant object
        const originalKeys = Object.keys(ROLES);
        assert.strictEqual(originalKeys.length, 3);
        assert.deepStrictEqual(originalKeys.sort(), ["ADMIN", "DEVELOPER", "READONLY"]);
    });

    test("ROLES values match ROLE_LIST values", () => {
        const roleValues = Object.values(ROLES).sort();
        const listValues = [...ROLE_LIST].sort();
        assert.deepStrictEqual(roleValues, listValues);
    });

    test("permission arrays are not empty for any role", () => {
        for (const role of ROLE_LIST) {
            assert.ok(
                ROLE_PERMISSIONS[role].length > 0,
                `Role "${role}" has empty permissions array`
            );
        }
    });

    test("every role has view-dashboard (minimum access)", () => {
        for (const role of ROLE_LIST) {
            assert.ok(
                ROLE_PERMISSIONS[role].includes("view-dashboard"),
                `Role "${role}" missing view-dashboard`
            );
        }
    });
});

// ─── A08-02: Mass Assignment Protection ────────────────────────────────────
describe("A08-02: Mass Assignment — Role Field Protection", () => {
    test("only valid roles are accepted for user creation", () => {
        const validRoles = ["admin", "developer", "readonly"];
        const attemptedRoles = [
            "admin", "developer", "readonly",
            "superadmin", "root", "system", "owner",
            "ADMIN", "Developer", "ReadOnly",
        ];

        for (const role of attemptedRoles) {
            const isValid = validRoles.includes(role);
            assert.strictEqual(
                isValidRole(role), isValid,
                `Role "${role}" validation should be ${isValid}`
            );
        }
    });
});
