const { describe, test } = require("node:test");
const assert = require("node:assert");
const { hasPermission } = require("../../server/roles");

/**
 * Replicate the checkLogin and checkPermission logic from util-server.js
 * without importing the full module (which has heavy dependencies).
 */
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

describe("checkLogin", () => {
    test("should throw if socket has no userID", () => {
        const socket = {};
        assert.throws(() => checkLogin(socket), {
            message: "You are not logged in.",
        });
    });

    test("should throw if socket.userID is null", () => {
        const socket = { userID: null };
        assert.throws(() => checkLogin(socket), {
            message: "You are not logged in.",
        });
    });

    test("should not throw if socket.userID is set", () => {
        const socket = { userID: 1 };
        assert.doesNotThrow(() => checkLogin(socket));
    });
});

describe("checkPermission", () => {
    test("should throw if user is not logged in", () => {
        const socket = {};
        assert.throws(() => checkPermission(socket, "manage-monitors"), {
            message: "You are not logged in.",
        });
    });

    test("admin should pass all permission checks", () => {
        const socket = { userID: 1, userRole: "admin" };

        assert.doesNotThrow(() => checkPermission(socket, "manage-users"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-settings"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-monitors"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-maintenance"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-notifications"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-status-pages"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-tags"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-proxies"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-docker-hosts"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-api-keys"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-remote-browsers"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-cloudflared"));
        assert.doesNotThrow(() => checkPermission(socket, "view-dashboard"));
    });

    test("developer should pass developer-level permission checks", () => {
        const socket = { userID: 2, userRole: "developer" };

        assert.doesNotThrow(() => checkPermission(socket, "manage-monitors"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-maintenance"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-notifications"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-tags"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-proxies"));
        assert.doesNotThrow(() => checkPermission(socket, "manage-docker-hosts"));
        assert.doesNotThrow(() => checkPermission(socket, "view-dashboard"));
    });

    test("developer should fail admin-only permission checks", () => {
        const socket = { userID: 2, userRole: "developer" };

        assert.throws(() => checkPermission(socket, "manage-users"), {
            message: "Permission denied. Your role does not have access to this action.",
        });
        assert.throws(() => checkPermission(socket, "manage-settings"), {
            message: "Permission denied. Your role does not have access to this action.",
        });
        assert.throws(() => checkPermission(socket, "manage-api-keys"), {
            message: "Permission denied. Your role does not have access to this action.",
        });
        assert.throws(() => checkPermission(socket, "manage-cloudflared"), {
            message: "Permission denied. Your role does not have access to this action.",
        });
        assert.throws(() => checkPermission(socket, "manage-status-pages"), {
            message: "Permission denied. Your role does not have access to this action.",
        });
    });

    test("readonly should only pass view-dashboard", () => {
        const socket = { userID: 3, userRole: "readonly" };

        assert.doesNotThrow(() => checkPermission(socket, "view-dashboard"));
    });

    test("readonly should fail all management permissions", () => {
        const socket = { userID: 3, userRole: "readonly" };
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
            assert.throws(
                () => checkPermission(socket, perm),
                {
                    message: "Permission denied. Your role does not have access to this action.",
                },
                `Readonly should fail permission check for: ${perm}`
            );
        }
    });

    test("unknown role should fail all permissions", () => {
        const socket = { userID: 99, userRole: "hacker" };

        assert.throws(() => checkPermission(socket, "view-dashboard"));
        assert.throws(() => checkPermission(socket, "manage-monitors"));
    });

    test("missing userRole should fail all permissions", () => {
        const socket = { userID: 1, userRole: undefined };

        assert.throws(() => checkPermission(socket, "view-dashboard"));
    });
});
