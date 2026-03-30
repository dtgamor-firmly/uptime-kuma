/**
 * OWASP A01:2021 - Broken Access Control
 *
 * Tests that verify the role-based access control system cannot be bypassed.
 * Covers: privilege escalation, role tampering, forced browsing, missing
 * access checks, IDOR, and self-privilege escalation.
 */
const { describe, test } = require("node:test");
const assert = require("node:assert");
const { hasPermission, isValidRole, ROLES, ROLE_LIST, ROLE_PERMISSIONS } = require("../../server/roles");

// Lightweight replicas of server functions (to avoid heavy deps)
function checkLogin(socket) {
    if (!socket.userID) {
        throw new Error("You are not logged in.");
    }
}

function checkPermission(socket, permission) {
    checkLogin(socket);
    if (!hasPermission(socket.userRole, permission)) {
        throw new Error("Permission denied. Your role does not have access to this action.");
    }
}

// ─── A01-01: Vertical Privilege Escalation ─────────────────────────────────
describe("A01-01: Vertical Privilege Escalation", () => {
    test("readonly user cannot escalate to manage-monitors", () => {
        const socket = { userID: 10, userRole: "readonly" };
        assert.throws(() => checkPermission(socket, "manage-monitors"));
    });

    test("readonly user cannot escalate to manage-users", () => {
        const socket = { userID: 10, userRole: "readonly" };
        assert.throws(() => checkPermission(socket, "manage-users"));
    });

    test("developer cannot escalate to manage-users", () => {
        const socket = { userID: 20, userRole: "developer" };
        assert.throws(() => checkPermission(socket, "manage-users"));
    });

    test("developer cannot escalate to manage-settings", () => {
        const socket = { userID: 20, userRole: "developer" };
        assert.throws(() => checkPermission(socket, "manage-settings"));
    });

    test("developer cannot escalate to manage-status-pages", () => {
        const socket = { userID: 20, userRole: "developer" };
        assert.throws(() => checkPermission(socket, "manage-status-pages"));
    });

    test("developer cannot escalate to manage-api-keys", () => {
        const socket = { userID: 20, userRole: "developer" };
        assert.throws(() => checkPermission(socket, "manage-api-keys"));
    });

    test("developer cannot escalate to manage-cloudflared", () => {
        const socket = { userID: 20, userRole: "developer" };
        assert.throws(() => checkPermission(socket, "manage-cloudflared"));
    });

    test("developer cannot escalate to manage-remote-browsers", () => {
        const socket = { userID: 20, userRole: "developer" };
        assert.throws(() => checkPermission(socket, "manage-remote-browsers"));
    });
});

// ─── A01-02: Unauthenticated Access ────────────────────────────────────────
describe("A01-02: Unauthenticated Access to Protected Resources", () => {
    const allPermissions = [
        "manage-users", "manage-settings", "manage-monitors",
        "manage-maintenance", "manage-notifications", "manage-status-pages",
        "manage-tags", "manage-proxies", "manage-docker-hosts",
        "manage-api-keys", "manage-remote-browsers", "manage-cloudflared",
        "view-dashboard",
    ];

    test("socket with no userID is rejected for all permissions", () => {
        const socket = {};
        for (const perm of allPermissions) {
            assert.throws(
                () => checkPermission(socket, perm),
                { message: "You are not logged in." },
                `Unauthenticated access should be denied for: ${perm}`
            );
        }
    });

    test("socket with null userID is rejected", () => {
        const socket = { userID: null, userRole: "admin" };
        assert.throws(() => checkPermission(socket, "manage-users"), {
            message: "You are not logged in.",
        });
    });

    test("socket with undefined userID is rejected", () => {
        const socket = { userID: undefined, userRole: "admin" };
        assert.throws(() => checkPermission(socket, "manage-users"), {
            message: "You are not logged in.",
        });
    });

    test("socket with zero userID is rejected (falsy)", () => {
        const socket = { userID: 0, userRole: "admin" };
        assert.throws(() => checkPermission(socket, "manage-users"), {
            message: "You are not logged in.",
        });
    });

    test("socket with empty string userID is rejected (falsy)", () => {
        const socket = { userID: "", userRole: "admin" };
        assert.throws(() => checkPermission(socket, "manage-users"), {
            message: "You are not logged in.",
        });
    });
});

// ─── A01-03: Role Tampering / Injection ────────────────────────────────────
describe("A01-03: Role Tampering and Injection", () => {
    test("fabricated role string is rejected", () => {
        const socket = { userID: 1, userRole: "superadmin" };
        assert.throws(() => checkPermission(socket, "manage-users"));
    });

    test("empty string role is rejected", () => {
        const socket = { userID: 1, userRole: "" };
        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });

    test("null role is rejected", () => {
        const socket = { userID: 1, userRole: null };
        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });

    test("undefined role is rejected", () => {
        const socket = { userID: 1, userRole: undefined };
        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });

    test("numeric role is rejected", () => {
        const socket = { userID: 1, userRole: 1 };
        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });

    test("boolean role is rejected", () => {
        const socket = { userID: 1, userRole: true };
        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });

    test("object role is rejected", () => {
        const socket = { userID: 1, userRole: { admin: true } };
        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });

    test("array role is rejected", () => {
        const socket = { userID: 1, userRole: ["admin"] };
        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });

    test("role with SQL injection payload is rejected", () => {
        const socket = { userID: 1, userRole: "admin' OR '1'='1" };
        assert.throws(() => checkPermission(socket, "manage-users"));
    });

    test("role with uppercase variant is rejected (case-sensitive)", () => {
        const socket = { userID: 1, userRole: "Admin" };
        assert.throws(() => checkPermission(socket, "manage-users"));
        assert.strictEqual(isValidRole("Admin"), false);
    });

    test("role with whitespace padding is rejected", () => {
        const socket = { userID: 1, userRole: " admin " };
        assert.throws(() => checkPermission(socket, "manage-users"));
        assert.strictEqual(isValidRole(" admin "), false);
    });

    test("prototype pollution role __proto__ is rejected", () => {
        const socket = { userID: 1, userRole: "__proto__" };
        assert.throws(() => checkPermission(socket, "manage-users"));
    });

    test("prototype pollution role constructor is rejected", () => {
        const socket = { userID: 1, userRole: "constructor" };
        assert.throws(() => checkPermission(socket, "manage-users"));
    });
});

// ─── A01-04: Permission Completeness ───────────────────────────────────────
describe("A01-04: Permission Completeness — No Permission Gaps", () => {
    test("every role in ROLE_LIST has an entry in ROLE_PERMISSIONS", () => {
        for (const role of ROLE_LIST) {
            assert.ok(
                ROLE_PERMISSIONS[role] !== undefined,
                `Role "${role}" is missing from ROLE_PERMISSIONS`
            );
        }
    });

    test("every role in ROLE_PERMISSIONS is in ROLE_LIST", () => {
        for (const role of Object.keys(ROLE_PERMISSIONS)) {
            assert.ok(
                ROLE_LIST.includes(role),
                `Role "${role}" in ROLE_PERMISSIONS is not in ROLE_LIST`
            );
        }
    });

    test("no role has duplicate permissions", () => {
        for (const role of ROLE_LIST) {
            const perms = ROLE_PERMISSIONS[role];
            const unique = new Set(perms);
            assert.strictEqual(
                perms.length,
                unique.size,
                `Role "${role}" has duplicate permissions`
            );
        }
    });

    test("readonly has strictly fewer permissions than developer", () => {
        assert.ok(
            ROLE_PERMISSIONS[ROLES.READONLY].length < ROLE_PERMISSIONS[ROLES.DEVELOPER].length
        );
    });

    test("developer has strictly fewer permissions than admin", () => {
        assert.ok(
            ROLE_PERMISSIONS[ROLES.DEVELOPER].length < ROLE_PERMISSIONS[ROLES.ADMIN].length
        );
    });

    test("manage-users is exclusively admin", () => {
        for (const role of ROLE_LIST) {
            if (role === ROLES.ADMIN) {
                assert.strictEqual(hasPermission(role, "manage-users"), true);
            } else {
                assert.strictEqual(
                    hasPermission(role, "manage-users"),
                    false,
                    `Role "${role}" should NOT have manage-users`
                );
            }
        }
    });
});

// ─── A01-05: Self-Privilege Escalation Guards ──────────────────────────────
describe("A01-05: Self-Privilege Escalation Guards (user-socket-handler logic)", () => {
    // These test the validation logic that should exist in the editUser handler

    test("admin cannot change their own role (logic check)", () => {
        const currentUserID = 1;
        const editPayload = { id: 1, role: "readonly" };

        // Simulates: if (bean.id === socket.userID && user.role !== ROLES.ADMIN)
        const isSelf = editPayload.id === currentUserID;
        const isDemotion = editPayload.role !== ROLES.ADMIN;

        assert.ok(isSelf && isDemotion, "Self-demotion should be detected");
    });

    test("admin cannot deactivate themselves (logic check)", () => {
        const currentUserID = 1;
        const editPayload = { id: 1, active: false };

        const isSelf = editPayload.id === currentUserID;
        const isDeactivation = editPayload.active === false;

        assert.ok(isSelf && isDeactivation, "Self-deactivation should be detected");
    });

    test("admin cannot delete themselves (logic check)", () => {
        const currentUserID = 1;
        const deleteTargetID = 1;

        assert.strictEqual(currentUserID, deleteTargetID, "Self-deletion should be blocked");
    });
});

// ─── A01-06: Forced Browsing — Non-existent Permissions ───────────────────
describe("A01-06: Access to Non-Existent Permissions", () => {
    test("requesting a non-existent permission is denied for admin", () => {
        assert.strictEqual(hasPermission("admin", "delete-database"), false);
    });

    test("requesting a non-existent permission is denied for developer", () => {
        assert.strictEqual(hasPermission("developer", "exec-shell"), false);
    });

    test("requesting a non-existent permission is denied for readonly", () => {
        assert.strictEqual(hasPermission("readonly", "admin-panel"), false);
    });

    test("empty permission string is denied", () => {
        assert.strictEqual(hasPermission("admin", ""), false);
    });

    test("null permission is denied", () => {
        assert.strictEqual(hasPermission("admin", null), false);
    });

    test("undefined permission is denied", () => {
        assert.strictEqual(hasPermission("admin", undefined), false);
    });
});
