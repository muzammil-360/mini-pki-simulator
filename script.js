/* Mini PKI Simulator - all logic runs in the browser (Web Crypto API) */

/* ===== 1. Helpers ===== */
const $ = (id) => document.getElementById(id);
const A = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const enc = (t) => new TextEncoder().encode(t);
const S = crypto.subtle;

// generate an RSA key pair
const gen = () => S.generateKey(A, true, ["sign", "verify"]);
// sign text with a private key (returns base64)
const sign = async (k, t) => b64(await S.sign(A.name, k, enc(t)));
// verify a signature using a base64 public key
const vrf = async (pubB64, sig, t) =>
  S.verify(A.name, await S.importKey("spki", unb(pubB64), { name: A.name, hash: "SHA-256" }, false, ["verify"]), unb(sig), enc(t));
// short SHA-256 fingerprint of a certificate
const fp = async (t) =>
  [...new Uint8Array(await S.digest("SHA-256", enc(t)))]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
const day = (ms) => new Date(ms).toISOString().slice(0, 10);

/* ===== 2. State ===== */
let sn = 1000,
  root,
  inter,
  rogue,
  trustFp,
  crl;
let users = [];
let revoked = [];

/* ===== Saved history (localStorage) ===== */
const KEY = "miniPkiState";
let logs = [];
let cleared = false;
let saveChain = Promise.resolve();

// show one row in the event log table (newest on top)
function addLogRow(time, m) {
  const tr = document.createElement("tr");
  tr.innerHTML = "<td></td><td></td>";
  tr.children[0].textContent = time;
  tr.children[1].textContent = m;
  $("logBody").prepend(tr);
}

// add an event to the log and save everything
function log(m) {
  const time = new Date().toLocaleTimeString();
  logs.push([time, m]);
  addLogRow(time, m);
  save();
}

// turn a certificate (with its keys) into plain text data, and back again
const expCert = async (c) => ({
  tbs: c.tbs,
  text: c.text,
  sig: c.sig,
  fp: c.fp,
  priv: b64(await S.exportKey("pkcs8", c.keys.privateKey)),
  pub: b64(await S.exportKey("spki", c.keys.publicKey)),
});
const impCert = async (o) => ({
  tbs: o.tbs,
  text: o.text,
  sig: o.sig,
  fp: o.fp,
  keys: {
    privateKey: await S.importKey("pkcs8", unb(o.priv), { name: A.name, hash: "SHA-256" }, true, ["sign"]),
    publicKey: await S.importKey("spki", unb(o.pub), { name: A.name, hash: "SHA-256" }, true, ["verify"]),
  },
});

// save all data in the browser (one save at a time)
function save() {
  saveChain = saveChain.then(async () => {
    if (cleared || !root) return;
    try {
      const data = {
        sn,
        trustFp,
        revoked,
        crl,
        logs,
        root: await expCert(root),
        inter: await expCert(inter),
        rogue: await expCert(rogue),
        users: await Promise.all(users.map(expCert)),
      };
      localStorage.setItem(KEY, JSON.stringify(data));
    } catch (e) {
      console.warn("Could not save history", e);
    }
  });
}

// load saved data; returns true if something was restored
async function load() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return false;
    const o = JSON.parse(raw);
    root = await impCert(o.root);
    inter = await impCert(o.inter);
    rogue = await impCert(o.rogue);
    users = await Promise.all(o.users.map(impCert));
    sn = o.sn;
    trustFp = o.trustFp;
    revoked = o.revoked;
    crl = o.crl;
    logs = o.logs;
    return true;
  } catch (e) {
    localStorage.removeItem(KEY);
    return false;
  }
}

// Clear history button
$("clearBtn").onclick = () => {
  if (confirm("Delete all saved certificates and history?")) {
    cleared = true;
    localStorage.removeItem(KEY);
    location.reload();
  }
};

/* ===== 3. Certificates and CA setup ===== */
// build a certificate and sign it with the issuer's private key
async function mk(o) {
  const now = Date.now(),
    exp = o.days < 0;
  const tbs = {
    serial: ++sn,
    subject: o.subject,
    issuer: o.issuer,
    email: o.email || "-",
    organisation: o.org || "-",
    notBefore: day(exp ? now - 60 * 864e5 : now),
    notAfter: day(exp ? now - 864e5 : now + o.days * 864e5),
    isCA: !!o.isCA,
    keyUsage: o.isCA ? "certSign, crlSign" : "digitalSignature",
    publicKey: b64(await S.exportKey("spki", o.keys.publicKey)),
  };
  const text = JSON.stringify(tbs);
  return { tbs, text, sig: await sign(o.signer, text), keys: o.keys, fp: await fp(text) };
}

// the Intermediate CA signs the list of revoked serial numbers
async function publishCRL() {
  const text = JSON.stringify({ issuer: inter.tbs.subject, revoked });
  crl = { text, sig: await sign(inter.keys.privateKey, text) };
}

// restore saved history, or create Root CA (self-signed), Intermediate CA and a Rogue CA for the attack demo
async function init() {
  const restored = await load();
  if (!restored) {
    const rk = await gen(),
      ik = await gen(),
      gk = await gen();
    root = await mk({ subject: "Mini Root CA", issuer: "Mini Root CA", days: 3650, isCA: true, keys: rk, signer: rk.privateKey });
    inter = await mk({ subject: "Mini Intermediate CA", issuer: "Mini Root CA", days: 1825, isCA: true, keys: ik, signer: rk.privateKey });
    rogue = await mk({ subject: "Rogue CA", issuer: "Rogue CA", days: 365, isCA: true, keys: gk, signer: gk.privateKey });
    trustFp = root.fp;
    await publishCRL();
  }
  $("caStatus").textContent = (restored ? "Saved history loaded. " : "") + "Root CA and Intermediate CA are ready (RSA 2048, SHA-256).";
  $("caInfo").textContent =
    "Trust store: Mini Root CA\nRoot fingerprint: " +
    root.fp +
    "\nRoot is self-signed.\n\nIntermediate: " +
    inter.tbs.subject +
    "\nFingerprint: " +
    inter.fp +
    "\nSigned by: " +
    inter.tbs.issuer;
  $("issueBtn").disabled = false;
  if (restored) {
    logs.forEach(([t, m]) => addLogRow(t, m));
    if (users.length) {
      renderTable();
      renderSelect();
    }
  } else {
    log("Root CA created and self-signed");
    log("Intermediate CA created and signed by Root");
    log("Empty CRL published by Intermediate");
  }
}

/* ===== 4. Registration form (validation and issuing) ===== */
function validate() {
  let ok = true;
  const n = $("name").value.trim(),
    e = $("email").value.trim(),
    o = $("org").value.trim();
  const set = (id, good, msg) => {
    $(id).textContent = good ? "" : msg;
    if (!good) ok = false;
  };
  set("e-name", /^[A-Za-z ]{3,}$/.test(n), "Use at least 3 letters (letters and spaces only).");
  set("e-email", /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e), "Enter a valid email like name@example.com.");
  set("e-org", o.length >= 2, "Organisation is required.");
  return ok;
}

$("regForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!validate()) return;
  const b = $("issueBtn");
  b.disabled = true;
  b.textContent = "Generating RSA keys...";
  const keys = await gen();
  const c = await mk({
    subject: $("name").value.trim(),
    issuer: inter.tbs.subject,
    email: $("email").value.trim(),
    org: $("org").value.trim(),
    days: +$("days").value,
    keys,
    signer: inter.keys.privateKey,
  });
  users.push(c);
  renderTable();
  renderSelect();
  log("Keys generated for " + c.tbs.subject + ". Certificate #" + c.tbs.serial + " signed by Intermediate CA");
  ev.target.reset();
  b.disabled = false;
  b.textContent = "Generate keys and issue certificate";
});

/* ===== 5. Tables and dropdown ===== */
function status(c) {
  if (revoked.includes(c.tbs.serial)) return ["Revoked", "t-bad"];
  if (c.tbs.notAfter < day(Date.now())) return ["Expired", "t-warn"];
  return ["Valid", "t-ok"];
}

function renderTable() {
  const tb = $("certTable").tBodies[0];
  tb.innerHTML = "";
  users.forEach((c) => {
    const tr = document.createElement("tr"),
      t = c.tbs,
      [s, cl] = status(c);
    [t.serial, t.subject, t.email, t.organisation, c.fp, t.notAfter].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const st = document.createElement("td"),
      tag = document.createElement("span");
    tag.className = "tag " + cl;
    tag.textContent = s;
    st.appendChild(tag);
    tr.appendChild(st);
    const ac = document.createElement("td");
    if (s !== "Revoked") {
      const b = document.createElement("button");
      b.className = "red";
      b.textContent = "Revoke";
      b.onclick = async () => {
        revoked.push(t.serial);
        await publishCRL();
        log("Certificate #" + t.serial + " revoked. New CRL signed by Intermediate CA");
        renderTable();
      };
      ac.appendChild(b);
    }
    tr.appendChild(ac);
    tb.appendChild(tr);
  });
}

function renderSelect() {
  const s = $("certSelect");
  s.innerHTML = "";
  users.forEach((c, i) => {
    const o = document.createElement("option");
    o.value = i;
    o.textContent = "#" + c.tbs.serial + " " + c.tbs.subject;
    s.appendChild(o);
  });
  s.value = users.length - 1;
  showCert();
}

function showCert() {
  const c = users[$("certSelect").value];
  $("certView").textContent = c
    ? JSON.stringify(c.tbs, null, 1).replace(/"publicKey": "(.{30}).*"/, '"publicKey": "$1..."') +
      "\n\nSignature: " +
      c.sig.slice(0, 60) +
      "..."
    : "Nothing selected.";
}
$("certSelect").addEventListener("change", showCert);

/* ===== 6. Chain verification and attacks ===== */
async function verifyChain(c, text, sig) {
  const steps = [],
    st = { root: "ok", inter: "ok", leaf: "ok" };
  const add = (ok, msg, n) => {
    steps.push([ok, msg]);
    if (!ok) st[n] = "bad";
  };
  const t = JSON.parse(text),
    today = day(Date.now());
  // user certificate checks
  add(t.issuer === inter.tbs.subject, 'Issuer name "' + t.issuer + '" matches the Intermediate CA', "leaf");
  add(await vrf(inter.tbs.publicKey, sig, text), "Signature checked with the Intermediate CA public key", "leaf");
  add(today >= t.notBefore && today <= t.notAfter, "Dates: valid " + t.notBefore + " to " + t.notAfter, "leaf");
  const crlOk = await vrf(inter.tbs.publicKey, crl.sig, crl.text);
  add(crlOk && !JSON.parse(crl.text).revoked.includes(t.serial), "Serial #" + t.serial + " is not on the signed CRL", "leaf");
  // intermediate CA checks
  add(inter.tbs.isCA, "Intermediate is allowed to sign certificates (isCA)", "inter");
  add(await vrf(root.tbs.publicKey, inter.sig, inter.text), "Intermediate signature checked with the Root public key", "inter");
  // root CA checks
  add(await vrf(root.tbs.publicKey, root.sig, root.text), "Root certificate is correctly self-signed", "root");
  add(root.fp === trustFp, "Root fingerprint is in the trust store", "root");
  return { steps, st, ok: steps.every((s) => s[0]) };
}

// mode: undefined = normal check, 'tamper' = edit the name, 'forge' = sign with the rogue CA
async function run(mode) {
  const c = users[$("certSelect").value];
  if (!c) {
    $("verdict").className = "verdict bad";
    $("verdict").textContent = "Issue a certificate first.";
    return;
  }
  let text = c.text,
    sig = c.sig,
    label = "Verification";
  if (mode === "tamper") {
    text = JSON.stringify({ ...c.tbs, subject: c.tbs.subject + " (forged)" });
    label = "Name-change attack";
  }
  if (mode === "forge") {
    const f = await mk({
      subject: c.tbs.subject,
      issuer: inter.tbs.subject,
      email: c.tbs.email,
      org: c.tbs.organisation,
      days: 365,
      keys: c.keys,
      signer: rogue.keys.privateKey,
    });
    text = f.text;
    sig = f.sig;
    label = "Rogue-CA forgery";
  }
  const r = await verifyChain(c, text, sig);
  ["root", "inter", "leaf"].forEach((k) => ($("n-" + k).className = "node " + r.st[k]));
  $("steps").innerHTML = "";
  r.steps.forEach(([ok, m]) => {
    const li = document.createElement("li");
    li.className = ok ? "y" : "n";
    li.textContent = m;
    $("steps").appendChild(li);
  });
  $("verdict").className = "verdict " + (r.ok ? "ok" : "bad");
  $("verdict").textContent = r.ok
    ? "TRUSTED: the whole chain checks out."
    : "REJECTED: do not trust this certificate. Look at the failed checks above.";
  log(label + " on #" + c.tbs.serial + ": " + (r.ok ? "trusted" : "rejected"));
}
$("vBtn").onclick = () => run();
$("tBtn").onclick = () => run("tamper");
$("fBtn").onclick = () => run("forge");

/* ===== 7. RSA maths demo (p=61, q=53, e=17, d=2753) ===== */
$("mathBtn").onclick = () => {
  const m = BigInt(Math.trunc($("msg").value)),
    n = 3233n;
  const mod = (b, e) => {
    let r = 1n;
    b %= n;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % n;
      b = (b * b) % n;
      e >>= 1n;
    }
    return r;
  };
  if (m < 0n || m >= n) {
    $("mathOut").textContent = "Enter a number from 0 to 3232.";
    return;
  }
  const s = mod(m, 2753n),
    back = mod(s, 17n);
  $("mathOut").textContent =
    "Signature = " +
    m +
    "^2753 mod 3233 = " +
    s +
    ". Check: " +
    s +
    "^17 mod 3233 = " +
    back +
    (back === m ? ". It matches, so the signature is valid." : ". No match.");
};

init(); // start the app
