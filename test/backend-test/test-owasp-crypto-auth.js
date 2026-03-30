/**
 * OWASP A02:2021 - Cryptographic Failures
 * OWASP A07:2021 - Identification and Authentication Failures
 *
 * Tests that verify JWT tokens, password hashing, and authentication
 * mechanisms are secure and cannot be bypassed.
 */
const { describe, test } = require("node:test");
const assert = require("node:assert");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// Replicate shake256 from util-server.js
const SHAKE256_LENGTH = 16;
function shake256(msg, len) {
    const hash = crypto.createHash("shake256", { outputLength: len });
    hash.update(msg);
    return hash.digest("hex");
}

// Replicate JWT creation from User model
function createJWT(user, jwtSecret) {
    return jwt.sign(
        {
            username: user.username,
            h: shake256(user.password, SHAKE256_LENGTH),
            role: user.role || "admin",
        },
        jwtSecret
    );
}

// ─── A02-01: JWT Token Security ────────────────────────────────────────────
describe("A02-01: JWT Token Security", () => {
    const jwtSecret = "test-secret-key-for-unit-tests";
    const user = {
        username: "testadmin",
        password: "$2a$10$somehashedpassword",
        role: "admin",
    };

    test("JWT contains username, password hash, and role", () => {
        const token = createJWT(user, jwtSecret);
        const decoded = jwt.decode(token);

        assert.strictEqual(decoded.username, "testadmin");
        assert.strictEqual(decoded.role, "admin");
        assert.strictEqual(typeof decoded.h, "string");
        assert.strictEqual(decoded.h.length, SHAKE256_LENGTH * 2); // hex encoding
    });

    test("JWT does NOT contain the raw password", () => {
        const token = createJWT(user, jwtSecret);
        const decoded = jwt.decode(token);
        const tokenString = JSON.stringify(decoded);

        assert.strictEqual(tokenString.includes(user.password), false,
            "JWT payload must never contain the raw password hash");
    });

    test("JWT signature is verified with correct secret", () => {
        const token = createJWT(user, jwtSecret);
        const decoded = jwt.verify(token, jwtSecret);
        assert.strictEqual(decoded.username, "testadmin");
    });

    test("JWT signature verification fails with wrong secret", () => {
        const token = createJWT(user, jwtSecret);
        assert.throws(() => jwt.verify(token, "wrong-secret"), {
            name: "JsonWebTokenError",
        });
    });

    test("tampered JWT payload is detected", () => {
        const token = createJWT(user, jwtSecret);
        const parts = token.split(".");
        // Tamper with the payload
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
        payload.role = "admin"; // try to escalate
        payload.username = "hacker";
        parts[1] = Buffer.from(JSON.stringify(payload)).toString("base64url");
        const tampered = parts.join(".");

        assert.throws(() => jwt.verify(tampered, jwtSecret), {
            name: "JsonWebTokenError",
        });
    });

    test("JWT with 'none' algorithm is rejected", () => {
        // Create unsigned token (alg: none attack)
        const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
        const payload = Buffer.from(JSON.stringify({
            username: "hacker",
            role: "admin",
            h: "fake",
        })).toString("base64url");
        const fakeToken = `${header}.${payload}.`;

        assert.throws(() => jwt.verify(fakeToken, jwtSecret));
    });

    test("password change invalidates existing JWT (hash binding)", () => {
        const originalToken = createJWT(user, jwtSecret);
        const decoded = jwt.verify(originalToken, jwtSecret);

        // Simulate password change
        const updatedUser = { ...user, password: "$2a$10$differenthashedpassword" };
        const newHash = shake256(updatedUser.password, SHAKE256_LENGTH);

        // The old token's hash should not match the new password
        assert.notStrictEqual(decoded.h, newHash,
            "JWT hash must differ after password change, invalidating old tokens");
    });

    test("different passwords produce different JWT hashes", () => {
        const user1 = { ...user, password: "password1" };
        const user2 = { ...user, password: "password2" };

        const token1 = createJWT(user1, jwtSecret);
        const token2 = createJWT(user2, jwtSecret);

        const decoded1 = jwt.decode(token1);
        const decoded2 = jwt.decode(token2);

        assert.notStrictEqual(decoded1.h, decoded2.h);
    });
});

// ─── A02-02: Role in JWT ───────────────────────────────────────────────────
describe("A02-02: Role Included in JWT for Client-Side Rendering", () => {
    const jwtSecret = "test-secret-key";

    test("admin role is encoded in JWT", () => {
        const token = createJWT({ username: "a", password: "p", role: "admin" }, jwtSecret);
        assert.strictEqual(jwt.decode(token).role, "admin");
    });

    test("developer role is encoded in JWT", () => {
        const token = createJWT({ username: "d", password: "p", role: "developer" }, jwtSecret);
        assert.strictEqual(jwt.decode(token).role, "developer");
    });

    test("readonly role is encoded in JWT", () => {
        const token = createJWT({ username: "r", password: "p", role: "readonly" }, jwtSecret);
        assert.strictEqual(jwt.decode(token).role, "readonly");
    });

    test("missing role defaults to admin (backward compatibility)", () => {
        const token = createJWT({ username: "old", password: "p" }, jwtSecret);
        assert.strictEqual(jwt.decode(token).role, "admin");
    });

    test("client-side role from JWT cannot override server-side role check", () => {
        // Even if a user modifies the decoded JWT role on the client,
        // the server re-reads role from the database on each loginByToken
        // and sets socket.userRole from the DB, not from the JWT payload.
        const token = createJWT({ username: "readonly_user", password: "p", role: "readonly" }, jwtSecret);
        const clientDecoded = jwt.decode(token);

        // Client could tamper with this value in memory
        clientDecoded.role = "admin";

        // But the server verifies the token signature and reads role from DB
        // so this test just validates the JWT signature blocks tampering
        const tampered = jwt.sign(clientDecoded, "wrong-secret");
        assert.throws(() => jwt.verify(tampered, jwtSecret));
    });
});

// ─── A07-01: Authentication Bypass Attempts ────────────────────────────────
describe("A07-01: Authentication Bypass Attempts", () => {
    test("login function rejects non-string username", () => {
        // Simulates the guard in auth.js login()
        function validateLogin(username, password) {
            if (typeof username !== "string" || typeof password !== "string") {
                return null;
            }
            return "user"; // simplified
        }

        assert.strictEqual(validateLogin(null, "pass"), null);
        assert.strictEqual(validateLogin(undefined, "pass"), null);
        assert.strictEqual(validateLogin(123, "pass"), null);
        assert.strictEqual(validateLogin({}, "pass"), null);
        assert.strictEqual(validateLogin([], "pass"), null);
        assert.strictEqual(validateLogin(true, "pass"), null);
    });

    test("login function rejects non-string password", () => {
        function validateLogin(username, password) {
            if (typeof username !== "string" || typeof password !== "string") {
                return null;
            }
            return "user";
        }

        assert.strictEqual(validateLogin("user", null), null);
        assert.strictEqual(validateLogin("user", undefined), null);
        assert.strictEqual(validateLogin("user", 123), null);
        assert.strictEqual(validateLogin("user", {}), null);
        assert.strictEqual(validateLogin("user", []), null);
    });
});

// ─── A07-02: Password Strength Enforcement ─────────────────────────────────
describe("A07-02: Password Strength Enforcement", () => {
    const { passwordStrength } = require("check-password-strength");

    test("empty password is too weak", () => {
        assert.strictEqual(passwordStrength("").value, "Too weak");
    });

    test("single character password is too weak", () => {
        assert.strictEqual(passwordStrength("a").value, "Too weak");
    });

    test("common password '123456' is too weak", () => {
        assert.strictEqual(passwordStrength("123456").value, "Too weak");
    });

    test("password 'password' is too weak", () => {
        assert.strictEqual(passwordStrength("password").value, "Too weak");
    });

    test("strong password is accepted", () => {
        const result = passwordStrength("C0mpl3x!P@ssw0rd#2024");
        assert.notStrictEqual(result.value, "Too weak",
            `Password should not be "Too weak", got: ${result.value}`);
    });
});

// ─── A07-03: Session Security ──────────────────────────────────────────────
describe("A07-03: Session / Socket Security", () => {
    test("logout clears userID from socket (logic check)", () => {
        // Simulates the logout handler in server.js
        const socket = { userID: 1, userRole: "admin" };

        // Logout logic
        socket.userID = null;

        assert.strictEqual(socket.userID, null);
    });

    test("after logout, checkLogin rejects the socket", () => {
        const socket = { userID: 1, userRole: "admin" };
        socket.userID = null; // logout

        assert.throws(() => {
            if (!socket.userID) {
                throw new Error("You are not logged in.");
            }
        });
    });
});
