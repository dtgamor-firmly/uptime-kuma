const { checkPermission } = require("../util-server");
const { log } = require("../../src/util");
const { R } = require("redbean-node");
const passwordHash = require("../password-hash");
const { isValidRole, ROLES } = require("../roles");
const { passwordStrength } = require("check-password-strength");
const TranslatableError = require("../translatable-error");

/**
 * Send the user list to the socket (admin only)
 * @param {Socket} socket Socket.io instance
 * @returns {Promise<void>}
 */
async function sendUserList(socket) {
    let list = await R.getAll("SELECT id, username, role, active FROM user ORDER BY id ASC");
    socket.emit("userList", list);
}

/**
 * Handlers for user management (admin only)
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 */
module.exports.userSocketHandler = (socket) => {

    // Get user list
    socket.on("getUserList", async (callback) => {
        try {
            checkPermission(socket, "manage-users");
            await sendUserList(socket);
            callback({
                ok: true,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    // Add a new user
    socket.on("addUser", async (user, callback) => {
        try {
            checkPermission(socket, "manage-users");

            if (!user.username || typeof user.username !== "string" || user.username.trim() === "") {
                throw new Error("Username is required.");
            }

            if (!user.password || typeof user.password !== "string") {
                throw new Error("Password is required.");
            }

            if (passwordStrength(user.password).value === "Too weak") {
                throw new TranslatableError("passwordTooWeak");
            }

            if (!isValidRole(user.role)) {
                throw new Error("Invalid role.");
            }

            // Check for duplicate username
            let existing = await R.findOne("user", " username = ? ", [user.username.trim()]);
            if (existing) {
                throw new Error("Username already exists.");
            }

            let bean = R.dispense("user");
            bean.username = user.username.trim();
            bean.password = await passwordHash.generate(user.password);
            bean.role = user.role;
            bean.active = 1;
            await R.store(bean);

            log.info("user", `Added user: ${bean.username} with role: ${bean.role} by user ID: ${socket.userID}`);

            await sendUserList(socket);

            callback({
                ok: true,
                msg: "successAdded",
                msgi18n: true,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
                msgi18n: !!e.msgi18n,
            });
        }
    });

    // Edit a user (change role / active status)
    socket.on("editUser", async (user, callback) => {
        try {
            checkPermission(socket, "manage-users");

            let bean = await R.findOne("user", " id = ? ", [user.id]);
            if (!bean) {
                throw new Error("User not found.");
            }

            // Prevent admin from demoting themselves
            if (bean.id === socket.userID && user.role !== ROLES.ADMIN) {
                throw new Error("You cannot change your own role.");
            }

            // Prevent admin from deactivating themselves
            if (bean.id === socket.userID && user.active === false) {
                throw new Error("You cannot deactivate your own account.");
            }

            if (user.role && isValidRole(user.role)) {
                bean.role = user.role;
            }

            if (user.active !== undefined) {
                bean.active = user.active ? 1 : 0;
            }

            // Optionally update password
            if (user.password && typeof user.password === "string" && user.password.length > 0) {
                if (passwordStrength(user.password).value === "Too weak") {
                    throw new TranslatableError("passwordTooWeak");
                }
                bean.password = await passwordHash.generate(user.password);
            }

            await R.store(bean);

            log.info("user", `Edited user: ${bean.username} (ID: ${bean.id}) by user ID: ${socket.userID}`);

            await sendUserList(socket);

            callback({
                ok: true,
                msg: "Saved.",
                msgi18n: true,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
                msgi18n: !!e.msgi18n,
            });
        }
    });

    // Delete a user
    socket.on("deleteUser", async (userID, callback) => {
        try {
            checkPermission(socket, "manage-users");

            if (userID === socket.userID) {
                throw new Error("You cannot delete your own account.");
            }

            let bean = await R.findOne("user", " id = ? ", [userID]);
            if (!bean) {
                throw new Error("User not found.");
            }

            await R.trash(bean);

            log.info("user", `Deleted user: ${bean.username} (ID: ${bean.id}) by user ID: ${socket.userID}`);

            await sendUserList(socket);

            callback({
                ok: true,
                msg: "successDeleted",
                msgi18n: true,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });
};
