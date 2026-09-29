/*
 * MMMCMXCIX vault.
 * The private pages live in /vault.json as AES-256-GCM ciphertext.
 * The key is derived from the password with PBKDF2-SHA256; nothing
 * readable is ever stored in the repo or sent anywhere.
 */
(function () {
  "use strict";

  var form = document.getElementById("gate");
  var input = document.getElementById("key");
  var status = document.getElementById("status");
  var main = document.getElementById("main");
  if (!form || !input || !status || !main) return;

  if (!window.crypto || !window.crypto.subtle) {
    status.textContent = "this browser cannot open the vault.";
    form.querySelector("button").disabled = true;
    return;
  }

  function fromB64(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function deriveKey(password, salt, iterations) {
    var enc = new TextEncoder();
    return crypto.subtle
      .importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iterations },
          base,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
      });
  }

  function open(html) {
    var doc = new DOMParser().parseFromString(html, "text/html");
    var nodes = Array.prototype.slice.call(doc.body.childNodes);
    main.textContent = "";
    nodes.forEach(function (n) {
      main.appendChild(document.importNode(n, true));
    });
    var t = doc.querySelector("title");
    if (t) document.title = t.textContent;
    var h = main.querySelector("h1, h2");
    if (h) {
      h.setAttribute("tabindex", "-1");
      h.focus();
    }
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var password = input.value;
    if (!password) {
      status.textContent = "no key.";
      input.focus();
      return;
    }
    var button = form.querySelector("button");
    button.disabled = true;
    status.textContent = "...";

    fetch("/vault.json", { cache: "no-store" })
      .then(function (r) {
        if (r.status === 404) throw new Error("empty");
        if (!r.ok) throw new Error("network");
        return r.json();
      })
      .then(function (v) {
        if (v.v !== 1) throw new Error("format");
        return deriveKey(password, fromB64(v.salt), v.iter).then(function (key) {
          return crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(v.iv) }, key, fromB64(v.ct));
        });
      })
      .then(function (plain) {
        input.value = "";
        open(new TextDecoder().decode(plain));
      })
      .catch(function (err) {
        button.disabled = false;
        input.value = "";
        input.focus();
        if (err && err.message === "empty") status.textContent = "nothing sealed yet.";
        else if (err && (err.message === "network" || err.message === "format")) status.textContent = "the vault could not be read.";
        else status.textContent = "incorrect.";
      });
  });
})();
