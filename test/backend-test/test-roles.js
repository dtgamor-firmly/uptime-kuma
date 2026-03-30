const { describe, test } = require("node:test");
const assert = require("node:assert");
const { hasPermission, isValidRole, ROLES, ROLE_LIST, ROLE_PERMISSIONS } = require("../../server/roles");

describe("Roles Module", () => {
    test("ROLES constants should be defined", () => {
        assert.strictEqual(ROLES.ADMIN, "admin");
        assert.strictEqual(ROLES.DEVELOPER, "developer");
        assert.strictEqual(ROLES.READONLY, "readonly");
    });

    test("ROLE_LIST should contain all roles", () => {
        assert.strictEqual(ROLE_LIST.length, 3);
        assert.ok(ROLE_LIST.includes("admin"));
        assert.ok(ROLE_LIST.includes("developer"));
        assert.ok(ROLE_LIST.includes("readonly"));
    });

    test("isValidRole should validate roles correctly", () => {
        assert.strictEqual(isValidRole("admin"), true);
        assert.strictEqual(isValidRole("developer"), true);
        assert.strictEqual(isValidRole("readonly"), true);
        assert.strictEqual(isValidRole("superadmin"), false);
        assert.strictEqual(isValidRole(""), false);
        assert.strictEqual(isValidRole(null), false);
        assert.strictEqual(isValidRole(undefined), false);
    });
});

describe("Admin Role Permissions", () => {
    test("admin should have all permissions", () => {
        const allPermissions = [
            "manage-users",
            "manage-settings",
            "manage-monitors",
            "manage-maintenance",
            "manage-notifications",
            "manage-status-pages",
            "manage-tags",
            "manage-proxies",
            "manage-docker-hosts",
            "manage-api-keys",
            "manage-remote-browsers",
            "manage-cloudflared",
            "view-dashboard",
        ];

        for (const perm of allPermissions) {
            assert.strictEqual(
                hasPermission("admin", perm),
                true,
                `Admin should have permission: ${perm}`
            );
        }
    });

    test("admin should have manage-users permission", () => {
        assert.strictEqual(hasPermission("admin", "manage-users"), true);
    });

    test("admin should have manage-settings permission", () => {
        assert.strictEqual(hasPermission("admin", "manage-settings"), true);
    });

    test("admin should have manage-api-keys permission", () => {
        assert.strictEqual(hasPermission("admin", "manage-api-keys"), true);
    });

    test("admin should have manage-cloudflared permission", () => {
        assert.strictEqual(hasPermission("admin", "manage-cloudflared"), true);
    });
});

describe("Developer Role Permissions", () => {
    test("developer should have monitor management permissions", () => {
        assert.strictEqual(hasPermission("developer", "manage-monitors"), true);
        assert.strictEqual(hasPermission("developer", "manage-maintenance"), true);
        assert.strictEqual(hasPermission("developer", "manage-notifications"), true);
        assert.strictEqual(hasPermission("developer", "manage-tags"), true);
        assert.strictEqual(hasPermission("developer", "manage-proxies"), true);
        assert.strictEqual(hasPermission("developer", "manage-docker-hosts"), true);
    });

    test("developer should have view-dashboard permission", () => {
        assert.strictEqual(hasPermission("developer", "view-dashboard"), true);
    });

    test("developer should NOT have admin-only permissions", () => {
        assert.strictEqual(hasPermission("developer", "manage-users"), false);
        assert.strictEqual(hasPermission("developer", "manage-settings"), false);
        assert.strictEqual(hasPermission("developer", "manage-api-keys"), false);
        assert.strictEqual(hasPermission("developer", "manage-remote-browsers"), false);
        assert.strictEqual(hasPermission("developer", "manage-cloudflared"), false);
        assert.strictEqual(hasPermission("developer", "manage-status-pages"), false);
    });
});

describe("Read-Only Role Permissions", () => {
    test("readonly should have view-dashboard permission", () => {
        assert.strictEqual(hasPermission("readonly", "view-dashboard"), true);
    });

    test("readonly should NOT have any management permissions", () => {
        const managementPerms = [
            "manage-users",
            "manage-settings",
            "manage-monitors",
            "manage-maintenance",
            "manage-notifications",
            "manage-status-pages",
            "manage-tags",
            "manage-proxies",
            "manage-docker-hosts",
            "manage-api-keys",
            "manage-remote-browsers",
            "manage-cloudflared",
        ];

        for (const perm of managementPerms) {
            assert.strictEqual(
                hasPermission("readonly", perm),
                false,
                `Readonly should NOT have permission: ${perm}`
            );
        }
    });

    test("readonly should only have exactly 1 permission", () => {
        assert.strictEqual(ROLE_PERMISSIONS["readonly"].length, 1);
        assert.strictEqual(ROLE_PERMISSIONS["readonly"][0], "view-dashboard");
    });
});

describe("Invalid Role Handling", () => {
    test("unknown role should have no permissions", () => {
        assert.strictEqual(hasPermission("unknown", "manage-users"), false);
        assert.strictEqual(hasPermission("unknown", "view-dashboard"), false);
    });

    test("null role should have no permissions", () => {
        assert.strictEqual(hasPermission(null, "manage-users"), false);
        assert.strictEqual(hasPermission(undefined, "view-dashboard"), false);
    });

    test("empty string role should have no permissions", () => {
        assert.strictEqual(hasPermission("", "manage-users"), false);
    });
});
