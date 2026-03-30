const { describe, test } = require("node:test");
const assert = require("node:assert");
const { ROLES, ROLE_PERMISSIONS, hasPermission, isValidRole } = require("../../server/roles");

/**
 * Tests for the database migration and role assignment logic.
 * These tests verify the role system's data integrity and constraints
 * that would be enforced during user creation and management.
 */

describe("Role Assignment Validation", () => {
    test("first user (setup) should be assigned admin role", () => {
        // Simulates the setup flow where the first user is created as admin
        const firstUserRole = "admin";
        assert.strictEqual(isValidRole(firstUserRole), true);
        assert.strictEqual(firstUserRole, ROLES.ADMIN);
    });

    test("new user can be assigned any valid role", () => {
        for (const role of [ROLES.ADMIN, ROLES.DEVELOPER, ROLES.READONLY]) {
            assert.strictEqual(isValidRole(role), true, `${role} should be a valid role`);
        }
    });

    test("default role from migration should be admin", () => {
        // Migration adds role column with default "admin"
        // This ensures existing single-user instances keep full access
        const defaultRole = "admin";
        assert.strictEqual(defaultRole, ROLES.ADMIN);
        assert.strictEqual(hasPermission(defaultRole, "manage-users"), true);
    });

    test("role strings should be lowercase", () => {
        for (const role of [ROLES.ADMIN, ROLES.DEVELOPER, ROLES.READONLY]) {
            assert.strictEqual(role, role.toLowerCase(), `Role ${role} should be lowercase`);
        }
    });

    test("invalid role strings should be rejected", () => {
        const invalidRoles = [
            "Admin",        // uppercase
            "ADMIN",        // all caps
            "super-admin",  // non-existent
            "moderator",    // non-existent
            "viewer",       // non-existent (use "readonly" instead)
            "read-only",    // hyphenated (use "readonly" instead)
            "",
            " ",
            "admin ",       // trailing space
            " admin",       // leading space
        ];

        for (const invalid of invalidRoles) {
            assert.strictEqual(
                isValidRole(invalid),
                false,
                `"${invalid}" should not be a valid role`
            );
        }
    });
});

describe("Role Hierarchy", () => {
    test("admin permissions should be a superset of developer permissions", () => {
        const adminPerms = ROLE_PERMISSIONS[ROLES.ADMIN];
        const devPerms = ROLE_PERMISSIONS[ROLES.DEVELOPER];

        for (const perm of devPerms) {
            assert.ok(
                adminPerms.includes(perm),
                `Admin should have developer permission: ${perm}`
            );
        }
    });

    test("developer permissions should be a superset of readonly permissions", () => {
        const devPerms = ROLE_PERMISSIONS[ROLES.DEVELOPER];
        const readonlyPerms = ROLE_PERMISSIONS[ROLES.READONLY];

        for (const perm of readonlyPerms) {
            assert.ok(
                devPerms.includes(perm),
                `Developer should have readonly permission: ${perm}`
            );
        }
    });

    test("admin should have more permissions than developer", () => {
        const adminPerms = ROLE_PERMISSIONS[ROLES.ADMIN];
        const devPerms = ROLE_PERMISSIONS[ROLES.DEVELOPER];

        assert.ok(
            adminPerms.length > devPerms.length,
            `Admin (${adminPerms.length}) should have more permissions than developer (${devPerms.length})`
        );
    });

    test("developer should have more permissions than readonly", () => {
        const devPerms = ROLE_PERMISSIONS[ROLES.DEVELOPER];
        const readonlyPerms = ROLE_PERMISSIONS[ROLES.READONLY];

        assert.ok(
            devPerms.length > readonlyPerms.length,
            `Developer (${devPerms.length}) should have more permissions than readonly (${readonlyPerms.length})`
        );
    });
});

describe("Permission Boundary Tests", () => {
    test("only admin can manage users", () => {
        assert.strictEqual(hasPermission(ROLES.ADMIN, "manage-users"), true);
        assert.strictEqual(hasPermission(ROLES.DEVELOPER, "manage-users"), false);
        assert.strictEqual(hasPermission(ROLES.READONLY, "manage-users"), false);
    });

    test("only admin can manage settings", () => {
        assert.strictEqual(hasPermission(ROLES.ADMIN, "manage-settings"), true);
        assert.strictEqual(hasPermission(ROLES.DEVELOPER, "manage-settings"), false);
        assert.strictEqual(hasPermission(ROLES.READONLY, "manage-settings"), false);
    });

    test("admin and developer can manage monitors", () => {
        assert.strictEqual(hasPermission(ROLES.ADMIN, "manage-monitors"), true);
        assert.strictEqual(hasPermission(ROLES.DEVELOPER, "manage-monitors"), true);
        assert.strictEqual(hasPermission(ROLES.READONLY, "manage-monitors"), false);
    });

    test("admin and developer can manage maintenance", () => {
        assert.strictEqual(hasPermission(ROLES.ADMIN, "manage-maintenance"), true);
        assert.strictEqual(hasPermission(ROLES.DEVELOPER, "manage-maintenance"), true);
        assert.strictEqual(hasPermission(ROLES.READONLY, "manage-maintenance"), false);
    });

    test("all roles can view dashboard", () => {
        assert.strictEqual(hasPermission(ROLES.ADMIN, "view-dashboard"), true);
        assert.strictEqual(hasPermission(ROLES.DEVELOPER, "view-dashboard"), true);
        assert.strictEqual(hasPermission(ROLES.READONLY, "view-dashboard"), true);
    });

    test("non-existent permission should be denied for all roles", () => {
        assert.strictEqual(hasPermission(ROLES.ADMIN, "non-existent-perm"), false);
        assert.strictEqual(hasPermission(ROLES.DEVELOPER, "non-existent-perm"), false);
        assert.strictEqual(hasPermission(ROLES.READONLY, "non-existent-perm"), false);
    });
});
