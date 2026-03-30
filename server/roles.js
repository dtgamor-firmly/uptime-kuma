/**
 * Role-Based Access Control (RBAC) for Uptime Kuma
 *
 * Roles:
 *   - admin: Full access, can manage users, settings, and all resources
 *   - developer: Can add/edit/delete monitors, maintenance, notifications, tags, proxies, docker hosts
 *   - readonly: Can only view the dashboard and status pages
 */

const ROLES = {
    ADMIN: "admin",
    DEVELOPER: "developer",
    READONLY: "readonly",
};

const ROLE_LIST = [ROLES.ADMIN, ROLES.DEVELOPER, ROLES.READONLY];

/**
 * Permissions that each role has.
 * "manage-users" = add/edit/delete users
 * "manage-settings" = change application settings
 * "manage-monitors" = add/edit/delete/pause/resume monitors
 * "manage-maintenance" = add/edit/delete maintenance windows
 * "manage-notifications" = add/edit/delete notification providers
 * "manage-status-pages" = add/edit/delete status pages
 * "manage-tags" = add/edit/delete tags
 * "manage-proxies" = add/edit/delete proxies
 * "manage-docker-hosts" = add/edit/delete docker hosts
 * "manage-api-keys" = add/edit/delete API keys
 * "manage-remote-browsers" = add/edit/delete remote browsers
 * "manage-cloudflared" = manage cloudflared tunnel
 * "view-dashboard" = view monitors, heartbeats, stats
 */
const ROLE_PERMISSIONS = {
    [ROLES.ADMIN]: [
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
    ],
    [ROLES.DEVELOPER]: [
        "manage-monitors",
        "manage-maintenance",
        "manage-notifications",
        "manage-tags",
        "manage-proxies",
        "manage-docker-hosts",
        "view-dashboard",
    ],
    [ROLES.READONLY]: [
        "view-dashboard",
    ],
};

/**
 * Check if a role has a specific permission
 * @param {string} role The user's role
 * @param {string} permission The permission to check
 * @returns {boolean} Whether the role has the permission
 */
function hasPermission(role, permission) {
    if (typeof role !== "string" || typeof permission !== "string") {
        return false;
    }
    const perms = ROLE_PERMISSIONS[role];
    if (!perms) {
        return false;
    }
    return perms.includes(permission);
}

/**
 * Check if a role is valid
 * @param {string} role Role to validate
 * @returns {boolean} Whether the role is valid
 */
function isValidRole(role) {
    return ROLE_LIST.includes(role);
}

module.exports = {
    ROLES,
    ROLE_LIST,
    ROLE_PERMISSIONS,
    hasPermission,
    isValidRole,
};
