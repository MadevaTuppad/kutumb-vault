/* ============================================================
   Family ID Vault — frontend logic
   ------------------------------------------------------------
   SET THESE THREE VALUES BEFORE DEPLOYING:
   ============================================================ */
const APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbximmaznIUcuFJh5lklZ5Rls10qx3e3BfzDhfl7IcGVLXyat7rasaFr0OAEQAdWfGD5WA/exec";
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

// Drop-in replacements for confirm()/alert() that match the app's own
// dark theme instead of a plain system dialog. Same calling shape
// (returns a Promise the caller awaits) so each call site only needed
// "confirm(...)" -> "await customConfirm(...)" and "alert(...)" ->
// "await customAlert(...)", not a restructure.
function customConfirm(message) {
  return new Promise(resolve => {
    const overlay = document.getElementById("customModalOverlay");
    const cancelBtn = document.getElementById("customModalCancelBtn");
    const confirmBtn = document.getElementById("customModalConfirmBtn");
    const previouslyFocused = document.activeElement;
    document.getElementById("customModalMessage").textContent = message;
    cancelBtn.classList.remove("hidden");
    confirmBtn.textContent = "OK";
    overlay.classList.remove("hidden");
    cancelBtn.focus(); // safer default focus for a destructive-action confirm

    function onKeydown(e) {
      if (e.key === "Escape") { cleanup(false); return; }
      if (e.key !== "Tab") return;
      e.preventDefault(); // only two buttons — a minimal trap between them
      (document.activeElement === cancelBtn ? confirmBtn : cancelBtn).focus();
    }
    function cleanup(result) {
      overlay.classList.add("hidden");
      cancelBtn.removeEventListener("click", onCancel);
      confirmBtn.removeEventListener("click", onConfirm);
      document.removeEventListener("keydown", onKeydown);
      if (previouslyFocused && previouslyFocused.focus) previouslyFocused.focus();
      resolve(result);
    }
    function onCancel() { cleanup(false); }
    function onConfirm() { cleanup(true); }
    cancelBtn.addEventListener("click", onCancel);
    confirmBtn.addEventListener("click", onConfirm);
    document.addEventListener("keydown", onKeydown);
  });
}
function customAlert(message) {
  return new Promise(resolve => {
    const overlay = document.getElementById("customModalOverlay");
    const cancelBtn = document.getElementById("customModalCancelBtn");
    const confirmBtn = document.getElementById("customModalConfirmBtn");
    const previouslyFocused = document.activeElement;
    document.getElementById("customModalMessage").textContent = message;
    cancelBtn.classList.add("hidden"); // alert only ever needs the one button
    confirmBtn.textContent = "OK";
    overlay.classList.remove("hidden");
    confirmBtn.focus();

    function onKeydown(e) {
      if (e.key === "Escape") { cleanup(); return; }
      if (e.key === "Tab") { e.preventDefault(); confirmBtn.focus(); } // only one button — trap on it
    }
    function cleanup() {
      overlay.classList.add("hidden");
      confirmBtn.removeEventListener("click", onConfirm);
      document.removeEventListener("keydown", onKeydown);
      if (previouslyFocused && previouslyFocused.focus) previouslyFocused.focus();
      resolve();
    }
    function onConfirm() { cleanup(); }
    confirmBtn.addEventListener("click", onConfirm);
    document.addEventListener("keydown", onKeydown);
  });
}

function showScreen(id) {
  ["screenSignIn", "screenPassphrase", "screenVault", "screenUpload"].forEach(s => {
    document.getElementById(s).classList.toggle("hidden", s !== id);
  });
  // offsetHeight below forces a synchronous layout read, which is safe
  // and accurate immediately after the classList change above — the
  // browser flushes layout on demand for a read like this, no need to
  // wait a tick. Only relevant once #screenVault is no longer hidden.
  if (id === "screenVault") measureTabRowHeight();
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

// Fills the tab opened synchronously (to dodge iOS Safari's popup
// blocker — see isIOS() usage below) with a visible loading message,
// instead of leaving it truly blank while the file decrypts. A large
// PDF over a slow connection can take a real, noticeable amount of
// time here, and a blank white tab looks identical to a broken one.
function showTabLoading(tab) {
  if (!tab) return;
  try {
    tab.document.write(
      '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
      '<title>Kutumb Vault</title>' +
      '<style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;' +
      'background:#12181f;color:#8b93a1;font-family:system-ui,sans-serif;font-size:15px;}' +
      '.s{display:inline-block;width:16px;height:16px;border:2px solid rgba(237,232,222,.25);' +
      'border-top-color:#c9a227;border-radius:50%;margin-right:8px;animation:sp .7s linear infinite;' +
      'vertical-align:-3px;}@keyframes sp{to{transform:rotate(360deg);}}</style></head>' +
      '<body><div><span class="s"></span>Decrypting your document…</div></body></html>'
    );
    tab.document.close();
  } catch (err) {
    // Non-fatal — worst case it's just blank until navigation happens.
  }
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
const DEFAULT_TIMEOUT_MS = 60000;
const LARGE_PAYLOAD_TIMEOUT_MS = 120000;

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
  // Must happen before idToken is cleared below — otherwise a pending
  // delete's deferred backend call would fire later with either a null
  // idToken (silent failure, document never actually deleted) or worse,
  // a DIFFERENT family member's idToken if someone else signs in on
  // this same device before the undo window naturally expires.
  finalizePendingDelete();
  idToken = null;
  currentUser = null;
  vaultKey = null;
  allFiles = [];
  fileListLoadedOnce = false;
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

// Keeps --header-height accurate so the sticky tab-row (see styles.css)
// sits directly below the header, never overlapping or gapped — the
// header's real height varies by device (safe-area-inset-top differs
// on a notched phone vs. a plain one), so this can't be a fixed guess.
function measureHeaderHeight() {
  const header = document.querySelector(".topbar");
  if (header) {
    document.documentElement.style.setProperty("--header-height", header.offsetHeight + "px");
  }
}
measureHeaderHeight();
window.addEventListener("resize", measureHeaderHeight);

// Same idea for the sticky per-person group headers on the Family tab
// — they need to dock directly below the (also sticky) tab-row, not
// guess a fixed pixel value. Unlike the header, the tab-row lives
// inside #screenVault, which is display:none until unlock — reading
// offsetHeight while hidden always returns 0 — so this can't just run
// once at script startup like measureHeaderHeight does. showScreen()
// calls this specifically whenever the vault screen becomes visible.
function measureTabRowHeight() {
  const tabRow = document.querySelector("#screenVault .tab-row");
  if (tabRow) {
    document.documentElement.style.setProperty("--tabrow-height", tabRow.offsetHeight + "px");
  }
}
window.addEventListener("resize", () => {
  if (!document.getElementById("screenVault").classList.contains("hidden")) measureTabRowHeight();
});


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
  loadMemberOrderPreference();
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
      // Same reasoning as loadMemberOrderPreference — only re-render if
      // the first real render already happened, otherwise skip (avoids
      // a premature empty-state flash; loadFileList's own upcoming
      // render will pick this up regardless). Needed here too since
      // myDependentNames affects whether the delete menu shows on a
      // guardian-owned document's card.
      if (fileListLoadedOnce) renderFileList();
    } else {
      console.warn("listDependents failed:", res.error || "unknown backend error");
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

  if (previousValue && [...select.options].some(o => o.value === previousValue)) {
    select.value = previousValue;
  }
}

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
  const subjectName = subjectSelect.value; // "" = myself

  if (!idType) {
    setStatus(statusEl, "Choose a document type before uploading.", "error");
    inputEl.value = "";
    return;
  }

  const fileType = (file.type || "").toLowerCase();
  if (!fileType.startsWith("image/") && fileType !== "application/pdf") {
    setStatus(statusEl, "Only images and PDFs are allowed — no videos or other file types.", "error");
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
    const proceed = await customConfirm(`${subjectName ? subjectName : "You"} already ${subjectName ? "has" : "have"} a ${idType} (${kindLabel}) in the vault. Replace it with this new one?`);
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
    await loadFileList();
    setTimeout(() => {
      showScreen("screenVault");
      highlightNewCard(res.fileId);
    }, 700);
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
let fileListLoadedOnce = false; // guards against other parallel loaders (dependents, order preference) rendering before allFiles has real data
let activeTab = "mine"; // "mine" | "family"
let memberFilter = ""; // uploader email, "" = all

// Delete is optimistic with a brief undo window, rather than an
// immediate irreversible call — the document disappears from view
// right away, but the actual backend deletion is deferred until the
// window expires without an Undo tap. Only one pending delete at a
// time, since there's only one toast to show it in; starting a new
// delete while one is already pending finalizes the older one first.
let pendingDelete = null; // { meta } or null
let pendingDeleteTimeoutId = null;

function showUndoToast(meta) {
  document.getElementById("undoToastMessage").textContent = `Deleted ${meta.idType || "document"}.`;
  document.getElementById("undoToast").classList.remove("hidden");
}
function hideUndoToast() {
  document.getElementById("undoToast").classList.add("hidden");
}
function finalizePendingDelete() {
  if (!pendingDelete) return;
  const { meta } = pendingDelete;
  clearTimeout(pendingDeleteTimeoutId);
  pendingDelete = null;
  pendingDeleteTimeoutId = null;
  hideUndoToast();
  callBackend("deleteFile", { idToken, driveFileId: meta.driveFileId }).catch(err => {
    // Best-effort — the document already looks deleted in the UI (and
    // stays that way until the next refresh); the undo window has
    // already closed, so there's nothing more useful to surface here
    // than a console note for debugging.
    console.warn("Couldn't finalize delete:", err);
  });
}
document.getElementById("undoDeleteBtn").addEventListener("click", () => {
  if (!pendingDelete) return;
  const { meta } = pendingDelete;
  clearTimeout(pendingDeleteTimeoutId);
  pendingDelete = null;
  pendingDeleteTimeoutId = null;
  hideUndoToast();
  allFiles.push(meta);
  populateMemberFilter();
  renderFileList();
});

// Closes any open per-card "⋯" menu — called both when a click lands
// outside every menu, and before opening a different one (so at most
// one menu is ever open at a time).
function closeAllFileMenus() {
  document.querySelectorAll(".file-menu-dropdown.open").forEach(d => d.classList.remove("open"));
}
document.addEventListener("click", closeAllFileMenus);

const cardCleanups = new WeakMap(); // card element -> cleanup function, run just before the card is discarded

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

/* ------------------------------------------------------------
   Family-view ordering: dependents always come first by default,
   with an optional PERSONAL override. Stored on the backend, keyed to
   the caller's own verified email, so it follows the person across
   devices — same as everything else in this app. Loaded once per
   session into memberOrderPreference (see loadMemberOrderPreference,
   called alongside loadDependents), then read synchronously here.
   ------------------------------------------------------------ */
let memberOrderPreference = []; // cached in-memory after loading from the backend once per session

async function loadMemberOrderPreference() {
  try {
    const res = await callBackend("getMemberOrderPreference", { idToken });
    if (res.ok) {
      memberOrderPreference = Array.isArray(res.order) ? res.order : [];
      // Only re-render if loadFileList's own first render already
      // happened — otherwise allFiles is still empty and rendering now
      // would flash a false "you haven't uploaded any documents yet"
      // before the real data arrives. If loadFileList hasn't rendered
      // yet, its own upcoming render will correctly pick up this
      // already-updated preference regardless, no separate call needed.
      if (fileListLoadedOnce) {
        populateMemberFilter();
        renderFileList();
      }
    }
  } catch (err) {
    // Non-fatal — falls back to the default order for this session.
  }
}

async function saveMemberOrderPreference(orderedKeys) {
  memberOrderPreference = orderedKeys; // apply locally right away, don't wait on the network
  try {
    await callBackend("setMemberOrderPreference", { idToken, order: orderedKeys });
  } catch (err) {
    // Non-fatal — it's still applied for this session; just might not
    // have saved server-side this time (e.g. a network hiccup).
  }
}

// Every distinct subject currently in the vault, unordered — used both
// to build the ordered list below and to populate the reorder panel.
// Deliberately excludes the current user's own (non-dependent)
// documents — those are already fully covered by My IDs, so offering
// "yourself" as a filterable/orderable Family member would be
// pointless. A dependent you're a guardian of still appears normally,
// since that's a different person, not you.
function getAllDistinctSubjects() {
  const seen = new Map(); // subjectKey -> display name
  for (const f of allFiles) {
    const key = subjectKeyOf(f);
    if (key === currentUser.email) continue;
    if (!seen.has(key)) seen.set(key, subjectDisplayNameOf(f));
  }
  return seen;
}

// Combines the personal preference (if any) with the default order
// (dependents first, then alphabetical) for whoever wasn't explicitly
// placed. Used by both the member filter dropdown and the Family-tab
// document list, so they always agree with each other.
function getOrderedSubjects() {
  const seen = getAllDistinctSubjects();
  const allKeys = [...seen.keys()];

  const defaultOrder = allKeys.slice().sort((a, b) => {
    const aIsDep = a.startsWith("dep:");
    const bIsDep = b.startsWith("dep:");
    if (aIsDep !== bIsDep) return aIsDep ? -1 : 1;
    return seen.get(a).localeCompare(seen.get(b));
  });

  const preference = memberOrderPreference.filter(k => seen.has(k)); // drop stale keys no longer present
  const remaining = defaultOrder.filter(k => !preference.includes(k));
  return [...preference, ...remaining].map(key => ({ key, name: seen.get(key) }));
}

function populateMemberFilter() {
  const select = document.getElementById("memberFilterSelect");
  const previousValue = select.value;
  const ordered = getOrderedSubjects();

  select.innerHTML = '<option value="">All family members</option>';
  for (const { key, name } of ordered) {
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = name;
    select.appendChild(opt);
  }
  // Keep the previous selection if that member still has files.
  if (previousValue && ordered.some(o => o.key === previousValue)) {
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
    fileListLoadedOnce = true;
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

  let scoped;
  if (activeTab === "mine") {
    scoped = allFiles.filter(f => !f.subjectName && f.uploader === currentUser.email);
  } else {
    // Family never includes the current user's own (non-dependent)
    // documents — those are already fully covered by My IDs, so
    // showing them here too would just be redundant. A dependent's
    // document you uploaded still shows normally, since that belongs
    // to the dependent, not you.
    const familyFiles = allFiles.filter(f => subjectKeyOf(f) !== currentUser.email);
    scoped = memberFilter ? familyFiles.filter(f => subjectKeyOf(f) === memberFilter) : familyFiles;
  }

  const filtered = filterVal ? scoped.filter(f => f.idType === filterVal) : scoped;

  // Dependents first, then personal-preference order, matching the
  // member filter dropdown — only meaningful on Family (My IDs is
  // always just one person, so there's nothing to reorder).
  if (activeTab === "family") {
    const rank = new Map(getOrderedSubjects().map((o, i) => [o.key, i]));
    filtered.sort((a, b) => (rank.get(subjectKeyOf(a)) ?? 999) - (rank.get(subjectKeyOf(b)) ?? 999));
  }

  // Release resources held by the cards about to be discarded: revoke any
  // decrypted blob URL, and stop observing thumbnails that never scrolled
  // into view (otherwise IntersectionObserver keeps a reference to the
  // detached element forever, leaking memory across repeated re-renders).
  for (const oldCard of listEl.children) {
    const cleanup = cardCleanups.get(oldCard);
    if (cleanup) cleanup();
  }
  listEl.innerHTML = "";
  if (activeTab === "family") {
    // Group by person so it's easy to tell whose documents you're
    // looking at, instead of scanning a flat mixed list. Works
    // correctly whether unfiltered (multiple groups) or filtered to
    // one person (naturally produces exactly one group/header — still
    // sticky, so the "whose documents" context never scrolls away,
    // even when there's only one person in view). `filtered` is
    // already sorted by the dependents-first/preference order above,
    // and Map preserves insertion order, so the groups come out in
    // that same order for free — no extra sort needed here.
    const groups = new Map(); // subjectKey -> { name, files: [] }
    for (const meta of filtered) {
      const key = subjectKeyOf(meta);
      if (!groups.has(key)) groups.set(key, { name: subjectDisplayNameOf(meta), files: [] });
      groups.get(key).files.push(meta);
    }
    for (const group of groups.values()) {
      const header = document.createElement("div");
      header.className = "member-group-header";
      header.textContent = `${group.name} (${group.files.length})`;
      listEl.appendChild(header);
      for (const meta of group.files) {
        listEl.appendChild(buildFileCard(meta));
      }
    }
  } else {
    for (const meta of filtered) {
      listEl.appendChild(buildFileCard(meta));
    }
  }
  setStatus(listStatus, filtered.length ? "" :
    (activeTab === "mine" ? "You haven't uploaded any documents yet." : "No documents match this filter."));
}

document.getElementById("filterSelect").addEventListener("change", renderFileList);

document.getElementById("memberFilterSelect").addEventListener("change", (e) => {
  memberFilter = e.target.value;
  renderFileList();
});

/* ------------------------------------------------------------
   "Order family members" panel — tap chips in the order you want;
   tap again to remove one (the rest renumber automatically).
   ------------------------------------------------------------ */
let pendingMemberOrder = []; // subject keys, in tap order, only while the panel is open

function renderMemberOrderChips() {
  const container = document.getElementById("memberOrderChips");
  container.innerHTML = "";
  const seen = getAllDistinctSubjects();
  // Show in the current default order so the chips themselves aren't
  // jumping around as you tap — only the badges/selection change.
  const displayOrder = [...seen.keys()].sort((a, b) => {
    const aIsDep = a.startsWith("dep:");
    const bIsDep = b.startsWith("dep:");
    if (aIsDep !== bIsDep) return aIsDep ? -1 : 1;
    return seen.get(a).localeCompare(seen.get(b));
  });

  for (const key of displayOrder) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "member-order-chip";
    const idx = pendingMemberOrder.indexOf(key);
    if (idx !== -1) {
      chip.classList.add("selected");
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = String(idx + 1);
      chip.appendChild(badge);
    }
    chip.appendChild(document.createTextNode(seen.get(key)));
    chip.addEventListener("click", () => {
      const i = pendingMemberOrder.indexOf(key);
      if (i !== -1) {
        pendingMemberOrder.splice(i, 1); // tap again to remove — remaining renumber
      } else {
        pendingMemberOrder.push(key);
      }
      renderMemberOrderChips();
    });
    container.appendChild(chip);
  }
}

document.getElementById("orderMembersBtn").addEventListener("click", () => {
  pendingMemberOrder = memberOrderPreference.filter(k => getAllDistinctSubjects().has(k));
  renderMemberOrderChips();
  document.getElementById("memberOrderPanel").classList.remove("hidden");
});

document.getElementById("saveMemberOrderBtn").addEventListener("click", async (e) => {
  setButtonLoading(e.target, "Saving…");
  await saveMemberOrderPreference(pendingMemberOrder);
  clearButtonLoading(e.target);
  document.getElementById("memberOrderPanel").classList.add("hidden");
  populateMemberFilter();
  renderFileList();
  setStatus(document.getElementById("listStatus"), "Order saved.", "success");
});

document.getElementById("resetMemberOrderBtn").addEventListener("click", () => {
  pendingMemberOrder = [];
  renderMemberOrderChips();
});

document.getElementById("cancelMemberOrderBtn").addEventListener("click", () => {
  document.getElementById("memberOrderPanel").classList.add("hidden");
});

function setActiveTab(tab) {
  activeTab = tab;
  const mineBtn = document.getElementById("tabMine");
  const familyBtn = document.getElementById("tabFamily");
  const memberSelect = document.getElementById("memberFilterSelect");
  const orderBtn = document.getElementById("orderMembersBtn");
  mineBtn.classList.toggle("active", tab === "mine");
  familyBtn.classList.toggle("active", tab === "family");
  mineBtn.setAttribute("aria-selected", tab === "mine");
  familyBtn.setAttribute("aria-selected", tab === "family");
  memberSelect.classList.toggle("hidden", tab !== "family");
  orderBtn.classList.toggle("hidden", tab !== "family");
  if (tab !== "family") {
    memberFilter = "";
    memberSelect.value = "";
    document.getElementById("memberOrderPanel").classList.add("hidden");
  }
  // Document-type filter is active on BOTH tabs (unlike the member
  // filter, which only exists on Family) — a value picked on one tab
  // was silently carrying over to the other, filtering out documents
  // with no visible explanation why. Reset it on every switch so each
  // tab always starts from a clean, predictable "All document types".
  document.getElementById("filterSelect").value = "";
  renderFileList();
}
document.getElementById("tabMine").addEventListener("click", () => setActiveTab("mine"));
document.getElementById("tabFamily").addEventListener("click", () => setActiveTab("family"));

// Scrolls a freshly uploaded document into view and gives it a brief
// highlight flash, closing the "did it work, and where did it go" gap
// — especially relevant now that documents land inside a specific
// person's group rather than obviously at the top of a flat list. If
// the current tab/filter doesn't happen to show this document, this
// silently does nothing rather than force-switching the person's view.
function highlightNewCard(driveFileId) {
  if (!driveFileId) return;
  const card = document.querySelector(`.file-card[data-drive-file-id="${CSS.escape(driveFileId)}"]`);
  if (!card) return;
  card.scrollIntoView({ behavior: "smooth", block: "center" });
  card.classList.add("file-card-highlight");
  setTimeout(() => card.classList.remove("file-card-highlight"), 2000);
}

function buildFileCard(meta) {
  const card = document.createElement("div");
  card.className = "file-card";
  card.dataset.driveFileId = meta.driveFileId;

  const thumb = document.createElement("div");
  thumb.className = "file-thumb file-thumb-label";
  if (ID_TYPE_CATEGORIES.official.includes(meta.idType)) {
    thumb.classList.add("file-thumb-official");
  }
  const isPdf = (meta.mimetype || "").toLowerCase().includes("pdf");
  // Fully static markup (never derived from meta/user data), matching
  // the existing precedent elsewhere in this file of using innerHTML
  // only for fixed, trusted strings — same reasoning as the "All
  // family members" option markup a few lines below.
  const PDF_ICON_SVG = '<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path d="M6 3h9l4 4v14a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M15 3v4h4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><line x1="8" y1="13" x2="16" y2="13" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/><line x1="8" y1="16" x2="13" y2="16" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>';
  const IMG_ICON_SVG = '<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="8.5" cy="9.5" r="1.6" fill="currentColor"/><path d="M3 16l5-5 4 4 3-3 6 6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/></svg>';
  thumb.innerHTML = (isPdf ? PDF_ICON_SVG : IMG_ICON_SVG) + "<span>" + (isPdf ? "PDF" : "IMG") + "</span>";
  card.appendChild(thumb);

  const metaEl = document.createElement("div");
  metaEl.className = "file-meta";

  const whoEl = document.createElement("div");
  whoEl.className = "who";
  // Built with textContent, not innerHTML — meta.idType is technically
  // attacker-controllable (a family member could bypass the <select> and
  // POST an arbitrary string to the backend), so it must never be treated
  // as HTML here.
  whoEl.textContent = meta.idType || "Document";
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
      if (!(await customConfirm(`Delete this ${label}?`))) return;

      // Only one pending delete at a time — if a previous one is still
      // in its undo window, finalize it now before starting this one.
      finalizePendingDelete();

      allFiles = allFiles.filter(f => f.driveFileId !== meta.driveFileId);
      populateMemberFilter();
      renderFileList(); // also runs the usual cardCleanups for every discarded card, including this one

      pendingDelete = { meta };
      pendingDeleteTimeoutId = setTimeout(finalizePendingDelete, 6000);
      showUndoToast(meta);
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
  let decryptedUrl = null;  // one object URL reused by View/Download/Share, revoked on cleanup
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
      return decryptedBlob;
    })();
    // Don't permanently cache a failure — let the next call (e.g. a manual
    // "View" tap after a previous attempt failed) retry from scratch.
    decryptPromise.catch(() => { decryptPromise = null; });
    return decryptPromise;
  }

  cardCleanups.set(card, () => {
    if (decryptedUrl) URL.revokeObjectURL(decryptedUrl);
  });

  viewBtn.addEventListener("click", async () => {
    // iOS Safari's popup blocker only allows window.open() when called
    // synchronously from the click — not after an awaited decrypt. So we
    // open a blank tab right away and fill in its location once ready.
    const tab = isIOS() ? window.open("", "_blank") : null;
    showTabLoading(tab);
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
      await customAlert("Couldn't decrypt this file — check the passphrase.");
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
    showTabLoading(tab);
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
      await customAlert("Couldn't decrypt this file — check the passphrase.");
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
      await customAlert("Couldn't decrypt this file — check the passphrase.");
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
      loadMemberOrderPreference();
      return;
    } catch {
      clearPersistedVaultKey(); // fall through to the passphrase screen below
    }
  }
  showScreen("screenPassphrase");
})();