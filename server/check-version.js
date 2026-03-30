const { setSetting, setting } = require("./util-server");
const axios = require("axios");
const compareVersions = require("compare-versions");
const { log } = require("../src/util");

exports.version = require("../package.json").version;
exports.latestVersion = null;

// How much time in ms to wait between update checks
const UPDATE_CHECKER_INTERVAL_MS = 1000 * 60 * 60 * 48;
const UPDATE_CHECKER_LATEST_VERSION_URL = "https://uptime.kuma.pet/version";

let interval;

exports.startInterval = () => {
    // Update checking disabled — this is a custom fork.
};

/**
 * Enable the check update feature
 * @param {boolean} value Should the check update feature be enabled?
 * @returns {Promise<void>}
 */
exports.enableCheckUpdate = async (value) => {
    await setSetting("checkUpdate", value);

    clearInterval(interval);

    if (value) {
        exports.startInterval();
    }
};

exports.socket = null;
