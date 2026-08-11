declare const __dirname: string;
declare const require: (name: string) => any;

const fs = require("node:fs") as { readFileSync: (file: string, encoding: string) => string };
const path = require("node:path") as { join: (...parts: string[]) => string };

const assetsDirectory = path.join(__dirname, "assets");

export const injectedHead =
  "<style id=\"komari-passkey-styles\">" +
  fs.readFileSync(path.join(assetsDirectory, "passkey-ui.css"), "utf8") +
  "</style>";

export const injectedBody =
  "<script id=\"komari-passkey-ui\">" +
  fs.readFileSync(path.join(assetsDirectory, "passkey-ui.js"), "utf8") +
  "</script>";
