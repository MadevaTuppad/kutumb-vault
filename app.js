/* ============================================================
   Family ID Vault — frontend logic
   ------------------------------------------------------------
   SET THESE THREE VALUES BEFORE DEPLOYING:
   ============================================================ */
const APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzOKYIehng7nEgUyty0BZruFnpNd6Uct1Cr1EVzoX-6vC9vdhIO1hTPjaTkIlgcuXNhLQ/exec";
// A fixed salt for this deployment. Generate your own random 16 bytes
// once (see README) and hardcode them here. This value is NOT secret,
// but must stay the same forever for this vault (changing it means
// nobody can decrypt previously-uploaded files).
const SALT_BASE64 = "UHh8Nu4Ou0vh22k22/HVUQ==";
const PBKDF2_ITERATIONS = 250000;
// Must exactly match CHECK_PLAINTEXT in generate-passphrase-check.html.
const CHECK_PLAINTEXT = "kutumb-vault-check-v1";

/* ============================================================
   State
   ------------------------------------------------------------
   idToken/currentUser/vaultKey optionally survive a page refresh via
   sessionStorage (see persistAuth / restoreSessionOnLoad below) — this
   is a deliberate convenience trade-off. sessionStorage never touches
   the network, so it doesn't affect man-in-the-middle exposure, but it IS readable by
   any JS running in this origin (e.g. an XSS bug) or by anyone with
   physical access to an unlocked device's DevTools. It's cleared the
   moment the tab is actually closed (unlike localStorage).
   ============================================================ */
let idToken = null;
let currentUser = null; // { email, name }
let vaultKey = null;    // CryptoKey, only exists after passphrase unlock

/* ------------------------------------------------------------
   Session persistence (sessionStorage — cleared when the tab closes)
   ------------------------------------------------------------ */
const SESSION_AUTH_KEY = "kutumbVaultAuth";  // { idToken, currentUser } — survives Lock vault
const SESSION_VAULTKEY_KEY = "kutumbVaultKey"; // exported raw AES key, base64 — cleared by Lock vault

function persistAuth() {
  try {
    sessionStorage.setItem(SESSION_AUTH_KEY, JSON.stringify({ idToken, currentUser }));
  } catch (err) {
    // Non-fatal — worst case, the next refresh just asks to sign in again.
  }
}
function clearPersistedAuth() {
  try { sessionStorage.removeItem(SESSION_AUTH_KEY); } catch (err) {}
}
async function persistVaultKey() {
  try {
    const rawKey = await crypto.subtle.exportKey("raw", vaultKey);
    sessionStorage.setItem(SESSION_VAULTKEY_KEY, bytesToBase64(new Uint8Array(rawKey)));
  } catch (err) {
    // Non-fatal — worst case, the next refresh just asks for the passphrase again.
  }
}
function clearPersistedVaultKey() {
  try { sessionStorage.removeItem(SESSION_VAULTKEY_KEY); } catch (err) {}
}

/* ============================================================
   Small helpers
   ============================================================ */
function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToBase64(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}
function setStatus(el, msg, kind) {
  el.textContent = msg || "";
  el.className = "status" + (kind ? " " + kind : "");
}
// Same as setStatus, but prepends a small spinner — used for transient
// "in progress" messages (checking access, unlocking, loading) so it's
// visually obvious something is happening, not just a text change that's
// easy to miss.
function setLoadingStatus(el, msg) {
  el.textContent = "";
  el.className = "status";
  const spinner = document.createElement("span");
  spinner.className = "spinner";
  el.appendChild(spinner);
  el.appendChild(document.createTextNode(msg));
}
// Swaps a button into a disabled, spinner+label loading state, and back.
// Used for View/Download/Share/Unlock, which previously gave zero
// feedback between tap and the action completing.
function setButtonLoading(btn, loadingText) {
  if (btn.dataset.originalText === undefined) btn.dataset.originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "";
  const spinner = document.createElement("span");
  spinner.className = "spinner";
  btn.appendChild(spinner);
  btn.appendChild(document.createTextNode(loadingText));
}
function clearButtonLoading(btn) {
  btn.disabled = false;
  if (btn.dataset.originalText !== undefined) {
    btn.textContent = btn.dataset.originalText;
    delete btn.dataset.originalText;
  }
}
function showScreen(id) {
  ["screenSignIn", "screenPassphrase", "screenVault", "screenUpload"].forEach(s => {
    document.getElementById(s).classList.toggle("hidden", s !== id);
  });
}

/* ------------------------------------------------------------
   iOS Safari needs different handling than Android Chrome for
   opening/downloading blob URLs — see comments at each call site.
   ------------------------------------------------------------ */
function isIOS() {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1); // iPadOS reports as Mac
}

function extFromMimetype(mimetype) {
  const mt = (mimetype || "").toLowerCase();
  if (mt.includes("pdf")) return "pdf";
  if (mt.includes("png")) return "png";
  if (mt.includes("webp")) return "webp";
  if (mt.includes("heic") || mt.includes("heif")) return "heic";
  return "jpg";
}

/* ============================================================
   Backend calls
   NOTE: Content-Type is deliberately "text/plain" (not
   "application/json") so the browser treats this as a "simple
   request" and skips a CORS preflight, which Apps Script Web
   Apps don't handle. The server still parses the body as JSON.
   ============================================================ */
// uploadFile/getFile can carry up to ~15MB of file data (~20MB once
// base64-encoded), which can genuinely take longer than a few seconds on
// a slow mobile connection. Lightweight calls (checkAccess, listFiles,
// getPassphraseCheck) have no reason to ever take that long, so they get
// a much tighter timeout to fail fast instead of leaving the UI stuck.
const LARGE_PAYLOAD_ACTIONS = new Set(["uploadFile", "getFile"]);
const DEFAULT_TIMEOUT_MS = 15000;
const LARGE_PAYLOAD_TIMEOUT_MS = 60000;

async function callBackend(action, payload) {
  const timeoutMs = LARGE_PAYLOAD_ACTIONS.has(action) ? LARGE_PAYLOAD_TIMEOUT_MS : DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  // If nothing comes back in time, something (a network issue, a blocked
  // request, an extension silently intercepting it) is preventing this
  // from ever settling on its own — fail loudly instead of leaving the
  // UI stuck on a loading message forever.
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify({ action, ...payload }),
      signal: controller.signal,
    });
  } catch (err) {
    if (err.name === "AbortError") {
      // Note: aborting here only stops the client from waiting — Apps
      // Script may still finish executing server-side (e.g. an upload
      // can still land even though this call reports failure). If a
      // person retries after an upload timeout, a duplicate entry is
      // possible; not fixable from the client side alone.
      throw new Error("Request timed out — check your connection (or try disabling browser extensions) and try again.");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
  if (!res.ok) throw new Error("Network error: " + res.status);
  return res.json();
}

/* ============================================================
   Google Sign-In
   ============================================================ */
function handleCredentialResponse(response) {
  const statusEl = document.getElementById("signInStatus");
  idToken = response.credential;
  setLoadingStatus(statusEl, "Checking access…");

  callBackend("checkAccess", { idToken })
    .then(res => {
      if (!res.ok) {
        setStatus(statusEl, "This Google account isn't on the family allow-list.", "error");
        idToken = null;
        return;
      }
      currentUser = { email: res.email, name: res.name };
      document.getElementById("userName").textContent = res.name;
      document.getElementById("userBadge").classList.remove("hidden");
      persistAuth();
      showScreen("screenPassphrase");
    })
    .catch(err => setStatus(statusEl, err.message || "Couldn't reach the vault backend. Try again.", "error"));
}

/** Clears all auth/session state. Shared by explicit sign-out and by
 *  the automatic expired-session detection below. */
function resetAuthState() {
  idToken = null;
  currentUser = null;
  vaultKey = null;
  clearPersistedAuth();
  clearPersistedVaultKey();
  document.getElementById("userBadge").classList.add("hidden");
  setStatus(document.getElementById("signInStatus"), ""); // clear any leftover "Checking access..." / error text
  // Without this, Google Identity Services silently re-selects the same
  // account on the next "Sign in with Google" attempt instead of showing
  // the account picker.
  if (window.google && google.accounts && google.accounts.id) {
    google.accounts.id.disableAutoSelect();
  }
}

document.getElementById("signOutBtn").addEventListener("click", () => {
  resetAuthState();
  showScreen("screenSignIn");
});

/* ------------------------------------------------------------
   Re-check the session whenever the app becomes visible again
   (phone unlocked, tab switched back to, app reopened from home
   screen). Google's ID token is short-lived (~1 hour); without this,
   a backgrounded tab keeps showing the old signed-in state even
   after the token has quietly expired, and nothing tells the person
   they need to sign in again until some action fails.
   ------------------------------------------------------------ */
let checkingSession = false;
async function verifySessionOnResume() {
  if (!idToken || checkingSession) return; // nothing to check, or already checking
  checkingSession = true;
  try {
    const res = await callBackend("checkAccess", { idToken });
    if (!res.ok) {
      resetAuthState();
      showScreen("screenSignIn");
      setStatus(document.getElementById("signInStatus"),
        "Your session expired — please sign in again.", "error");
    }
    // else: still valid, nothing to do — the UI wasn't actually stale.
  } catch {
    // Network hiccup — don't force a sign-out over a transient failure.
  } finally {
    checkingSession = false;
  }
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") onAppResume();
});
window.addEventListener("pageshow", onAppResume);

function onAppResume() {
  verifySessionOnResume();
  // Self-heal a stuck "couldn't load documents" error automatically on
  // the next natural resume, rather than requiring the manual Retry link
  // — only meaningful once the vault is actually unlocked.
  if (fileListLoadFailed && vaultKey) loadFileList();
}

document.getElementById("lockBtn").addEventListener("click", () => {
  vaultKey = null; // drop the key from memory; passphrase must be re-entered
  clearPersistedVaultKey(); // otherwise a refresh right after Lock would silently restore it
  showScreen("screenPassphrase");
});

/* ============================================================
   Passphrase → AES key (PBKDF2)
   ============================================================ */
async function deriveKeyFromPassphrase(passphrase) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64ToBytes(SALT_BASE64),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true, // extractable — required so the key can be persisted to sessionStorage (see persistVaultKey)
    ["encrypt", "decrypt"]
  );
}

document.getElementById("passphraseForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const statusEl = document.getElementById("passphraseStatus");
  const submitBtn = e.target.querySelector('button[type="submit"]');
  const passphrase = document.getElementById("passphraseInput").value;
  document.getElementById("passphraseInput").value = "";
  setLoadingStatus(statusEl, "Unlocking…");
  setButtonLoading(submitBtn, "Unlocking…");

  let candidateKey;
  try {
    candidateKey = await deriveKeyFromPassphrase(passphrase);
  } catch {
    setStatus(statusEl, "Couldn't derive a key from that passphrase.", "error");
    clearButtonLoading(submitBtn);
    return;
  }

  let checkRes;
  try {
    checkRes = await callBackend("getPassphraseCheck", { idToken });
  } catch (err) {
    // Surface the real reason (e.g. the timeout message) instead of a
    // generic one — this is a network/backend failure, not a bad
    // passphrase, and the two should never look the same to the user.
    setStatus(statusEl, err.message || "Couldn't verify the passphrase right now. Try again.", "error");
    clearButtonLoading(submitBtn);
    return;
  }

  if (checkRes.ok && checkRes.exists) {
    // A canary is configured — this is the real, reliable check.
    // AES-GCM's authentication tag fails deterministically on any
    // wrong key, so this never gives a false positive or negative.
    try {
      await decryptWithKey(
        candidateKey,
        base64ToBytes(checkRes.ciphertextBase64),
        base64ToBytes(checkRes.ivBase64)
      );
    } catch {
      setStatus(statusEl, "That passphrase doesn't look right — try again.", "error");
      clearButtonLoading(submitBtn);
      return;
    }
  } else if (!checkRes.ok) {
    // Couldn't reach the check at all — fail safe by refusing to
    // proceed rather than silently skipping verification.
    setStatus(statusEl, "Couldn't verify the passphrase right now. Try again.", "error");
    clearButtonLoading(submitBtn);
    return;
  }
  // else: no canary configured yet — proceed unverified (nothing to
  // check against; see generate-passphrase-check.html to set one up).

  vaultKey = candidateKey;
  await persistVaultKey();
  setStatus(statusEl, "");
  clearButtonLoading(submitBtn);
  showScreen("screenVault");
  loadFileList();
  loadDependents();
});

/* ============================================================
   Encrypt + upload
   ============================================================ */
async function encryptBytes(plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, vaultKey, plainBytes
  );
  return { ciphertext: new Uint8Array(ciphertext), iv };
}
async function decryptBytes(ciphertextBytes, ivBytes) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes }, vaultKey, ciphertextBytes
  );
  return new Uint8Array(plain);
}
// Same as decryptBytes, but takes an explicit key — used only to verify
// the passphrase canary before vaultKey itself has been set.
async function decryptWithKey(key, ciphertextBytes, ivBytes) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes }, key, ciphertextBytes
  );
  return new Uint8Array(plain);
}

const MAX_FILE_BYTES = 15 * 1024 * 1024; // 15MB — comfortably under Apps Script's request-size limits once base64-encoded

// Must stay in sync with ALLOWED_ID_TYPES in backend.gs — the backend is
// the real enforcement point, this only controls what the dropdown offers.
const ID_TYPE_CATEGORIES = {
  official: ["Aadhaar", "PAN", "Passport", "Driving Licence", "Voter ID"],
  other: ["Passport-size Photo", "Gas Passbook", "Ration Card", "Birth Certificate",
          "Bank Passbook", "Insurance Policy", "Property Documents", "Other"],
};

function populateIdTypeOptions(category) {
  const select = document.getElementById("idTypeSelect");
  select.innerHTML = '<option value="" disabled selected>Select ID type</option>';
  for (const type of ID_TYPE_CATEGORIES[category] || []) {
    const opt = document.createElement("option");
    opt.value = type;
    opt.textContent = type;
    select.appendChild(opt);
  }
}

document.querySelectorAll("#idCategoryTabs .tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#idCategoryTabs .tab-btn").forEach(b => {
      b.classList.toggle("active", b === btn);
      b.setAttribute("aria-selected", b === btn ? "true" : "false");
    });
    populateIdTypeOptions(btn.dataset.category);
  });
});
populateIdTypeOptions("official"); // initial state matches the tab marked active in the HTML

/* ------------------------------------------------------------
   Dependents — family members without their own Google account
   (e.g. a parent without a phone). A guardian (an account holder
   listed in her GuardianEmails, enforced server-side) uploads on her
   behalf. listDependents only ever returns dependents the CURRENT
   user is a guardian of — someone unrelated to her never sees her as
   an upload option, though her documents remain visible to the whole
   family via the normal Family tab regardless (viewing was never
   restricted, only who can add/manage her documents is).
   ------------------------------------------------------------ */
let dependents = []; // only MY dependents — [{ name, addedAt }]
let myDependentNames = new Set(); // same data, as a Set, for quick lookups (delete-menu gating)

async function loadDependents() {
  try {
    const res = await callBackend("listDependents", { idToken });
    if (res.ok) {
      dependents = res.dependents;
      myDependentNames = new Set(dependents.map(d => d.name));
      populateSubjectSelect();
    }
  } catch (err) {
    // Non-fatal — the dropdown just won't offer any dependents yet;
    // this is set up entirely by the admin, directly in the sheet.
  }
}

function populateSubjectSelect(selectedName) {
  const select = document.getElementById("subjectSelect");
  const previousValue = selectedName !== undefined ? selectedName : select.value;
  select.innerHTML = '';
  const myselfOpt = document.createElement("option");
  myselfOpt.value = "";
  myselfOpt.textContent = "Myself";
  select.appendChild(myselfOpt);
  for (const dep of dependents) {
    const opt = document.createElement("option");
    opt.value = dep.name;
    opt.textContent = dep.name;
    select.appendChild(opt);
  }
  if (dependents.length > 0) {
    const manageOpt = document.createElement("option");
    manageOpt.value = "__manage__";
    manageOpt.textContent = "Manage family members…";
    select.appendChild(manageOpt);
  }

  if (previousValue && [...select.options].some(o => o.value === previousValue)) {
    select.value = previousValue;
  }
}

document.getElementById("subjectSelect").addEventListener("change", async (e) => {
  const select = e.target;
  if (select.value !== "__manage__") return;

  select.value = ""; // this option only ever triggers an action, never stays selected
  // Lightweight text-based removal flow — deliberately no new screen.
  // Only ever offers MY dependents, since `dependents` already only
  // contains ones I'm a guardian of. Adding a new dependent is
  // deliberately admin-only (done directly in the sheet), so there's
  // no corresponding "add" branch here.
  const listText = dependents.map((d, i) => `${i + 1}. ${d.name}`).join("\n");
  const choice = prompt(`Remove which family member?\n${listText}\n\nType the number, or Cancel to keep everyone.`);
  if (!choice) return;
  const idx = parseInt(choice, 10) - 1;
  if (isNaN(idx) || idx < 0 || idx >= dependents.length) {
    alert("Didn't recognize that number — nothing was removed.");
    return;
  }
  const target = dependents[idx];
  if (!confirm(`Remove "${target.name}"? Her already-uploaded documents stay in the vault, just tagged as before — this only stops her being offered for new uploads.`)) {
    return;
  }
  try {
    const res = await callBackend("deleteDependent", { idToken, name: target.name });
    if (!res.ok) {
      alert("Couldn't remove her: " + (res.error || "unknown error"));
      return;
    }
    await loadDependents();
  } catch (err) {
    alert(err.message || "Couldn't remove that family member.");
  }
});

document.getElementById("openUploadBtn").addEventListener("click", () => {
  showScreen("screenUpload");
});
document.getElementById("backToVaultBtn").addEventListener("click", () => {
  showScreen("screenVault");
});

document.getElementById("fileInput").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const statusEl = document.getElementById("uploadStatus");
  const inputEl = e.target;
  const idTypeSelect = document.getElementById("idTypeSelect");
  const idType = idTypeSelect.value;
  const subjectSelect = document.getElementById("subjectSelect");
  const rawSubjectValue = subjectSelect.value;
  const subjectName = rawSubjectValue === "__manage__" ? "" : rawSubjectValue; // "" = myself

  if (!idType) {
    setStatus(statusEl, "Choose a document type before uploading.", "error");
    inputEl.value = "";
    return;
  }

  if (file.size > MAX_FILE_BYTES) {
    setStatus(statusEl, "That photo is too large (max 15MB). Try again with a smaller image.", "error");
    inputEl.value = "";
    return;
  }

  // Warn before silently creating a second copy of the same document type.
  // Matches on ID type + broad media category (image vs PDF) + who it
  // belongs to. For my own documents, only my own uploads count. For a
  // dependent's documents, ANY guardian's upload counts — co-guardians
  // share responsibility for the same person's documents.
  const newIsPdf = (file.type || "").toLowerCase().includes("pdf");
  const existing = allFiles.find(f =>
    (subjectName ? true : f.uploader === currentUser.email) &&
    f.idType === idType &&
    (f.subjectName || "") === subjectName &&
    ((f.mimetype || "").toLowerCase().includes("pdf")) === newIsPdf
  );
  if (existing) {
    const kindLabel = newIsPdf ? "PDF" : "image";
    const proceed = confirm(`${subjectName ? subjectName : "You"} already ${subjectName ? "has" : "have"} a ${idType} (${kindLabel}) in the vault. Replace it with this new one?`);
    if (!proceed) {
      inputEl.value = "";
      return;
    }
  }

  inputEl.disabled = true;
  setLoadingStatus(statusEl, "Encrypting on this device…");
  try {
    const arrayBuffer = await file.arrayBuffer();
    const { ciphertext, iv } = await encryptBytes(new Uint8Array(arrayBuffer));
    setLoadingStatus(statusEl, "Uploading encrypted file…");
    const res = await callBackend("uploadFile", {
      idToken,
      ciphertextBase64: bytesToBase64(ciphertext),
      ivBase64: bytesToBase64(iv),
      mimetype: file.type || "image/jpeg",
      idType,
      subjectName,
    });
    if (!res.ok) {
      setStatus(statusEl, "Upload failed: " + (res.error || "unknown error"), "error");
      return;
    }

    if (existing) {
      // Best-effort cleanup — the new copy is already safely uploaded
      // either way, so a failure here shouldn't be shown as an error;
      // the old copy would just remain until deleted manually.
      try {
        await callBackend("deleteFile", { idToken, driveFileId: existing.driveFileId });
      } catch (err) {
        console.warn("Couldn't remove the replaced document:", err);
      }
    }

    setStatus(statusEl, existing ? "Replaced in the vault." : "Saved to the vault.", "success");
    inputEl.value = "";
    idTypeSelect.selectedIndex = 0;
    // Subject selection (Myself / a dependent) intentionally stays as-is —
    // convenient when uploading several documents for the same person in
    // a row, same reasoning as keeping the category tab selection.
    loadFileList();
    setTimeout(() => showScreen("screenVault"), 700);
  } catch (err) {
    setStatus(statusEl, "Something went wrong encrypting that file.", "error");
  } finally {
    inputEl.disabled = false;
  }
});

/* ============================================================
   List + decrypt-on-demand
   ============================================================ */
let allFiles = [];
let fileListLoadFailed = false; // lets a resumed session auto-retry instead of leaving a stale error forever
let activeTab = "mine"; // "mine" | "family"
let memberFilter = ""; // uploader email, "" = all

// Closes any open per-card "⋯" menu — called both when a click lands
// outside every menu, and before opening a different one (so at most
// one menu is ever open at a time).
function closeAllFileMenus() {
  document.querySelectorAll(".file-menu-dropdown.open").forEach(d => d.classList.remove("open"));
}
document.addEventListener("click", closeAllFileMenus);

/* ------------------------------------------------------------
   Thumbnails auto-decrypt as their card scrolls into view (the
   vault is already unlocked at this point, so this doesn't reveal
   anything a manual "View" click wouldn't — it just avoids the
   empty placeholder box until the user taps a button). Lazy via
   IntersectionObserver so it only loads what's actually visible,
   not every document at once.
   ------------------------------------------------------------ */
const thumbLoaders = new WeakMap(); // thumb element -> load function
const cardCleanups = new WeakMap(); // card element -> cleanup function, run just before the card is discarded
const thumbObserver = ("IntersectionObserver" in window)
  ? new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        const load = thumbLoaders.get(entry.target);
        if (load) {
          thumbObserver.unobserve(entry.target);
          thumbLoaders.delete(entry.target);
          load();
        }
      }
    }, { rootMargin: "200px" })
  : null;

// A document either belongs to the account holder who uploaded it, or
// to a dependent they uploaded it on behalf of. These two helpers give
// a single consistent identity/display-name across both cases, used by
// the member filter and the file card's "who" label.
function subjectKeyOf(f) {
  return f.subjectName ? "dep:" + f.subjectName : f.uploader;
}
function subjectDisplayNameOf(f) {
  return f.subjectName || f.uploaderName || f.uploader;
}

function populateMemberFilter() {
  const select = document.getElementById("memberFilterSelect");
  const previousValue = select.value;

  // Distinct subjects (account holders + dependents), sorted by name.
  const seen = new Map(); // subjectKey -> display name
  for (const f of allFiles) {
    const key = subjectKeyOf(f);
    if (!seen.has(key)) seen.set(key, subjectDisplayNameOf(f));
  }
  const members = [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]));

  select.innerHTML = '<option value="">All family members</option>';
  for (const [key, name] of members) {
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = name;
    select.appendChild(opt);
  }
  // Keep the previous selection if that member still has files.
  if (previousValue && seen.has(previousValue)) {
    select.value = previousValue;
  } else {
    memberFilter = "";
  }
}

async function loadFileList() {
  const listStatus = document.getElementById("listStatus");
  setLoadingStatus(listStatus, "Loading…");
  try {
    const res = await callBackend("listFiles", { idToken });
    if (!res.ok) {
      showListLoadError(listStatus, "Couldn't load documents.");
      return;
    }
    fileListLoadFailed = false;
    allFiles = res.files;
    populateMemberFilter();
    renderFileList();
  } catch (err) {
    showListLoadError(listStatus, err.message || "Couldn't reach the vault backend.");
  }
}

// Shows a load failure with a "Retry" link, and remembers the failure so
// it can be retried automatically the next time the app becomes visible
// again — without this, the message just sits there forever, since
// nothing else ever touches listStatus unless another load happens to
// succeed on its own.
function showListLoadError(el, msg) {
  fileListLoadFailed = true;
  el.textContent = "";
  el.className = "status error";
  el.appendChild(document.createTextNode(msg + " "));
  const retryBtn = document.createElement("button");
  retryBtn.type = "button";
  retryBtn.className = "link-btn";
  retryBtn.textContent = "Retry";
  retryBtn.addEventListener("click", () => loadFileList());
  el.appendChild(retryBtn);
}

function renderFileList() {
  const listEl = document.getElementById("fileList");
  const listStatus = document.getElementById("listStatus");
  const filterVal = document.getElementById("filterSelect").value;

  let scoped = activeTab === "mine"
    ? allFiles.filter(f => !f.subjectName && f.uploader === currentUser.email)
    : (memberFilter ? allFiles.filter(f => subjectKeyOf(f) === memberFilter) : allFiles);

  const filtered = filterVal ? scoped.filter(f => f.idType === filterVal) : scoped;

  // Release resources held by the cards about to be discarded: revoke any
  // decrypted blob URL, and stop observing thumbnails that never scrolled
  // into view (otherwise IntersectionObserver keeps a reference to the
  // detached element forever, leaking memory across repeated re-renders).
  for (const oldCard of listEl.children) {
    const cleanup = cardCleanups.get(oldCard);
    if (cleanup) cleanup();
  }
  listEl.innerHTML = "";
  for (const meta of filtered) {
    listEl.appendChild(buildFileCard(meta));
  }
  setStatus(listStatus, filtered.length ? "" :
    (activeTab === "mine" ? "You haven't uploaded any documents yet." : "No documents match this filter."));
}

document.getElementById("filterSelect").addEventListener("change", renderFileList);

document.getElementById("memberFilterSelect").addEventListener("change", (e) => {
  memberFilter = e.target.value;
  renderFileList();
});

function setActiveTab(tab) {
  activeTab = tab;
  const mineBtn = document.getElementById("tabMine");
  const familyBtn = document.getElementById("tabFamily");
  const memberSelect = document.getElementById("memberFilterSelect");
  mineBtn.classList.toggle("active", tab === "mine");
  familyBtn.classList.toggle("active", tab === "family");
  mineBtn.setAttribute("aria-selected", tab === "mine");
  familyBtn.setAttribute("aria-selected", tab === "family");
  memberSelect.classList.toggle("hidden", tab !== "family");
  if (tab !== "family") {
    memberFilter = "";
    memberSelect.value = "";
  }
  renderFileList();
}
document.getElementById("tabMine").addEventListener("click", () => setActiveTab("mine"));
document.getElementById("tabFamily").addEventListener("click", () => setActiveTab("family"));

function buildFileCard(meta) {
  const card = document.createElement("div");
  card.className = "file-card";

  const thumb = document.createElement("div");
  thumb.className = "file-thumb";
  const isPdf = (meta.mimetype || "").toLowerCase().includes("pdf");
  if (isPdf) {
    thumb.classList.add("file-thumb-pdf");
    thumb.textContent = "PDF";
  } else {
    thumb.classList.add("file-thumb-loading");
  }
  card.appendChild(thumb);

  const metaEl = document.createElement("div");
  metaEl.className = "file-meta";

  const whoEl = document.createElement("div");
  whoEl.className = "who";
  // Built with textContent, not innerHTML — meta.idType is technically
  // attacker-controllable (a family member could bypass the <select> and
  // POST an arbitrary string to the backend), so it must never be treated
  // as HTML here.
  whoEl.textContent = (meta.idType ? meta.idType + " — " : "") + subjectDisplayNameOf(meta);
  metaEl.appendChild(whoEl);

  const whenEl = document.createElement("div");
  whenEl.className = "when";
  whenEl.textContent = new Date(meta.date).toLocaleString();
  metaEl.appendChild(whenEl);

  card.appendChild(metaEl);

  // Delete is shown for the document's own uploader, or — for a
  // dependent's document — any of her current guardians (co-guardians
  // can manage each other's uploads for the same dependent). This is a
  // convenience only; the backend enforces the same rule independently
  // and will refuse the request even if this check were somehow bypassed.
  const canManage = meta.uploader === currentUser.email ||
    (meta.subjectName && myDependentNames.has(meta.subjectName));
  if (canManage) {
    const menuWrap = document.createElement("div");
    menuWrap.className = "file-menu";

    const menuBtn = document.createElement("button");
    menuBtn.className = "file-menu-btn";
    menuBtn.textContent = "⋯";
    menuBtn.setAttribute("aria-label", "More options");
    menuWrap.appendChild(menuBtn);

    const dropdown = document.createElement("div");
    dropdown.className = "file-menu-dropdown";
    const deleteItem = document.createElement("button");
    deleteItem.className = "file-menu-item";
    deleteItem.textContent = "Delete";
    dropdown.appendChild(deleteItem);
    menuWrap.appendChild(dropdown);

    menuBtn.addEventListener("click", (e) => {
      e.stopPropagation(); // don't let the global listener immediately close this
      const wasOpen = dropdown.classList.contains("open");
      closeAllFileMenus();
      if (!wasOpen) dropdown.classList.add("open");
    });

    deleteItem.addEventListener("click", async (e) => {
      e.stopPropagation();
      dropdown.classList.remove("open");
      const label = meta.idType || "this document";
      if (!confirm(`Delete this ${label}? This can't be undone.`)) return;

      deleteItem.disabled = true;
      deleteItem.textContent = "Deleting…";
      try {
        const res = await callBackend("deleteFile", { idToken, driveFileId: meta.driveFileId });
        if (!res.ok) {
          alert("Couldn't delete: " + (res.error || "unknown error"));
          deleteItem.disabled = false;
          deleteItem.textContent = "Delete";
          return;
        }
        allFiles = allFiles.filter(f => f.driveFileId !== meta.driveFileId);
        populateMemberFilter();
        renderFileList(); // also runs the usual cardCleanups for every discarded card, including this one
      } catch (err) {
        alert(err.message || "Couldn't delete this document.");
        deleteItem.disabled = false;
        deleteItem.textContent = "Delete";
      }
    });

    card.appendChild(menuWrap);
  }

  const actions = document.createElement("div");
  actions.className = "file-actions";

  const viewBtn = document.createElement("button");
  viewBtn.className = "icon-btn";
  viewBtn.textContent = "View";
  actions.appendChild(viewBtn);

  const downloadBtn = document.createElement("button");
  downloadBtn.className = "icon-btn";
  downloadBtn.textContent = "Download";
  actions.appendChild(downloadBtn);

  const shareBtn = document.createElement("button");
  shareBtn.className = "icon-btn";
  shareBtn.textContent = "Share";
  actions.appendChild(shareBtn);

  card.appendChild(actions);

  let decryptedBlob = null; // cached after first decrypt, per session only
  let decryptedUrl = null;  // one object URL reused by thumbnail/View/Download, revoked on cleanup
  let decryptPromise = null; // in-flight/cached promise — prevents duplicate concurrent decrypts

  function ensureDecrypted() {
    if (decryptPromise) return decryptPromise; // covers both "already decrypted" and "decrypt in progress"
    decryptPromise = (async () => {
      const res = await callBackend("getFile", { idToken, driveFileId: meta.driveFileId });
      if (!res.ok) throw new Error(res.error || "fetch failed");
      const plainBytes = await decryptBytes(
        base64ToBytes(res.ciphertextBase64),
        base64ToBytes(meta.ivBase64)
      );
      decryptedBlob = new Blob([plainBytes], { type: meta.mimetype || "image/jpeg" });
      decryptedUrl = URL.createObjectURL(decryptedBlob);
      if (!isPdf) {
        thumb.classList.remove("file-thumb-loading");
        thumb.style.backgroundImage = `url(${decryptedUrl})`;
        thumb.style.backgroundSize = "cover";
        thumb.style.backgroundPosition = "center";
      }
      return decryptedBlob;
    })();
    // Don't permanently cache a failure — let the next call (e.g. a manual
    // "View" tap after the auto-load silently failed) retry from scratch.
    decryptPromise.catch(() => { decryptPromise = null; });
    return decryptPromise;
  }

  cardCleanups.set(card, () => {
    if (decryptedUrl) URL.revokeObjectURL(decryptedUrl);
    if (thumbObserver) {
      thumbObserver.unobserve(thumb);
      thumbLoaders.delete(thumb);
    }
  });

  // Auto-load the thumbnail once this card scrolls into view.
  if (!isPdf) {
    const autoLoad = () => {
      ensureDecrypted().catch(() => {
        // Wrong passphrase or fetch failure — don't alert for an
        // automatic background load; just stop showing the spinner
        // and fall back to a plain placeholder. The user will still
        // see a clear error if they tap View/Download/Share.
        thumb.classList.remove("file-thumb-loading");
        thumb.classList.add("file-thumb-error");
      });
    };
    if (thumbObserver) {
      thumbLoaders.set(thumb, autoLoad);
      thumbObserver.observe(thumb);
    } else {
      autoLoad(); // no IntersectionObserver support — just load immediately
    }
  }

  viewBtn.addEventListener("click", async () => {
    // iOS Safari's popup blocker only allows window.open() when called
    // synchronously from the click — not after an awaited decrypt. So we
    // open a blank tab right away and fill in its location once ready.
    const tab = isIOS() ? window.open("", "_blank") : null;
    setButtonLoading(viewBtn, "Opening…");
    try {
      await ensureDecrypted();
      if (tab) {
        tab.location.href = decryptedUrl;
      } else {
        window.open(decryptedUrl, "_blank");
      }
    } catch {
      if (tab) tab.close();
      alert("Couldn't decrypt this file — check the passphrase.");
    } finally {
      clearButtonLoading(viewBtn);
    }
  });

  downloadBtn.addEventListener("click", async () => {
    const filenameBase = (meta.idType || "id-document").replace(/\s+/g, "-").toLowerCase();
    // iOS Safari ignores the `download` attribute on blob URLs — it just
    // navigates to the file instead of saving it. So on iOS we open the
    // file (same synchronous-tab trick as View) and let the person use
    // the native share sheet's "Save to Files" / "Save Image" action.
    // Android Chrome honors `download` correctly, so it keeps the
    // straightforward anchor-click approach.
    const tab = isIOS() ? window.open("", "_blank") : null;
    setButtonLoading(downloadBtn, "Downloading…");
    try {
      await ensureDecrypted();
      const ext = extFromMimetype(meta.mimetype);
      if (tab) {
        tab.location.href = decryptedUrl;
        setStatus(document.getElementById("listStatus"),
          "Opened the file — use the share icon to save it to Files/Photos.", "success");
      } else {
        const a = document.createElement("a");
        a.href = decryptedUrl;
        a.download = `${filenameBase}.${ext}`;
        a.click();
      }
    } catch {
      if (tab) tab.close();
      alert("Couldn't decrypt this file — check the passphrase.");
    } finally {
      clearButtonLoading(downloadBtn);
    }
  });

  shareBtn.addEventListener("click", async () => {
    setButtonLoading(shareBtn, "Preparing…");
    try {
      const blob = await ensureDecrypted();
      const ext = extFromMimetype(meta.mimetype);
      const fileForShare = new File([blob], `id-document.${ext}`, { type: blob.type });
      if (navigator.canShare && navigator.canShare({ files: [fileForShare] })) {
        await navigator.share({ files: [fileForShare], title: "ID document" });
      } else {
        const a = document.createElement("a");
        a.href = decryptedUrl;
        a.download = `id-document.${ext}`;
        a.click();
      }
    } catch (err) {
      if (err && err.name === "AbortError") {
        // Person just canceled the native share sheet — not a real error.
        return;
      }
      alert("Couldn't decrypt this file — check the passphrase.");
    } finally {
      clearButtonLoading(shareBtn);
    }
  });

  return card;
}

/* ============================================================
   Startup — attempt to restore a persisted session
   ------------------------------------------------------------
   Runs once when the script first loads (including on every refresh).
   The saved idToken is always re-verified against the backend before
   being trusted — it could have quietly expired since it was saved,
   and this is also what stops a tampered/stale sessionStorage value
   from silently granting access.
   ============================================================ */
(async function restoreSessionOnLoad() {
  const savedAuthRaw = sessionStorage.getItem(SESSION_AUTH_KEY);
  if (!savedAuthRaw) return; // nothing saved — default screenSignIn stays showing

  let savedAuth;
  try {
    savedAuth = JSON.parse(savedAuthRaw);
  } catch {
    clearPersistedAuth();
    return;
  }
  if (!savedAuth.idToken || !savedAuth.currentUser) {
    clearPersistedAuth();
    return;
  }

  let checkRes;
  try {
    checkRes = await callBackend("checkAccess", { idToken: savedAuth.idToken });
  } catch {
    // Transient network issue — leave the sign-in screen showing rather
    // than wiping a possibly-still-valid saved session over a hiccup.
    return;
  }
  if (!checkRes.ok) {
    clearPersistedAuth();
    clearPersistedVaultKey();
    return;
  }

  idToken = savedAuth.idToken;
  currentUser = savedAuth.currentUser;
  document.getElementById("userName").textContent = currentUser.name;
  document.getElementById("userBadge").classList.remove("hidden");

  const savedKeyBase64 = sessionStorage.getItem(SESSION_VAULTKEY_KEY);
  if (savedKeyBase64) {
    try {
      vaultKey = await crypto.subtle.importKey(
        "raw", base64ToBytes(savedKeyBase64), { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
      );
      showScreen("screenVault");
      loadFileList();
      loadDependents();
      return;
    } catch {
      clearPersistedVaultKey(); // fall through to the passphrase screen below
    }
  }
  showScreen("screenPassphrase");
})();