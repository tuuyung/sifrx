const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Reject HTML parsing and inline handlers: vault values must remain literal text.
class Element {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.listeners = {};
    this.textContent = "";
  }
  append(...nodes) { this.children.push(...nodes); }
  addEventListener(name, action) { this.listeners[name] = action; }
  set innerHTML(value) { throw new Error("Unsafe HTML rendering"); }
  set onclick(value) { throw new Error("Unsafe inline handler"); }
}
const stored = new Map([["sifrx_mp", "old-persisted-password"]]);
const copied = [];
const sandbox = {
  window: { fetch: async () => ({}), addEventListener() {} },
  document: { addEventListener() {}, createElement: tag => new Element(tag) },
  sessionStorage: {
    getItem: key => stored.get(key) || null,
    removeItem: key => stored.delete(key),
    setItem: (key, value) => { stored.set(key, value); }
  },
  navigator: { clipboard: { writeText: async value => copied.push(value) } },
};
vm.createContext(sandbox);
const source = fs.readFileSync(path.join(__dirname, "../app.js"), "utf8");
vm.runInContext(source, sandbox);
assert.equal(stored.has("sifrx_mp"), false);
assert.equal(vm.runInContext("appState.masterPassword", sandbox), null);
const malicious = "&#39;);alert(1);//\\'\"<img src=x onerror=alert(1)>\n";
sandbox.malicious = malicious;
const card = vm.runInContext(`
  appState.decryptedItems.example = {username: malicious, password: malicious, website: malicious};
  renderVaultItem({id: "example", type: "login", title: malicious});
`, sandbox);
const nodes = [];
function walk(node) { nodes.push(node); node.children.forEach(walk); }
walk(card);
assert.equal(nodes.filter(node => node.textContent === malicious).length, 4);
const copyButtons = nodes.filter(node => node.tagName === "button" && node.textContent === "Kopyala");
assert.equal(copyButtons.length, 3);
copyButtons.forEach(button => button.listeners.click());
assert.deepEqual(copied, [malicious, malicious, malicious]);
assert.equal(nodes.some(node => node.tagName === "img"), false);
console.log("Frontend security regression checks passed.");
