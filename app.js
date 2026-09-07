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
   State (kept only in memory — never persisted to disk/storage)
   ============================================================ */
let idToken = null;
let currentUser = null; // { email, name }
let vaultKey = null;    // CryptoKey, only exists after passphrase unlock

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
async function callBackend(action, payload) {
  const res = await fetch(APPS_SCRIPT_URL, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ action, ...payload }),
  });
  if (!res.ok) throw new Error("Network error: " + res.status);
  return res.json();
}

/* ============================================================
   Google Sign-In
   ============================================================ */
function handleCredentialResponse(response) {
  const statusEl = document.getElementById("signInStatus");
  idToken = response.credential;
  setStatus(statusEl, "Checking access…");

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
      showScreen("screenPassphrase");
    })
    .catch(() => setStatus(statusEl, "Couldn't reach the vault backend. Try again.", "error"));
}

/** Clears all auth/session state. Shared by explicit sign-out and by
 *  the automatic expired-session detection below. */
function resetAuthState() {
  idToken = null;
  currentUser = null;
  vaultKey = null;
  document.getElementById("userBadge").classList.add("hidden");
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
  if (document.visibilityState === "visible") verifySessionOnResume();
});
window.addEventListener("pageshow", verifySessionOnResume);

document.getElementById("lockBtn").addEventListener("click", () => {
  vaultKey = null; // drop the key from memory; passphrase must be re-entered
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
    false,
    ["encrypt", "decrypt"]
  );
}

document.getElementById("passphraseForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const statusEl = document.getElementById("passphraseStatus");
  const passphrase = document.getElementById("passphraseInput").value;
  document.getElementById("passphraseInput").value = "";
  setStatus(statusEl, "Unlocking…");
  try {
    const candidateKey = await deriveKeyFromPassphrase(passphrase);
    const checkRes = await callBackend("getPassphraseCheck", { idToken });

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
        return;
      }
    } else if (!checkRes.ok) {
      // Couldn't reach the check at all — fail safe by refusing to
      // proceed rather than silently skipping verification.
      setStatus(statusEl, "Couldn't verify the passphrase right now. Try again.", "error");
      return;
    }
    // else: no canary configured yet — proceed unverified (nothing to
    // check against; see generate-passphrase-check.html to set one up).

    vaultKey = candidateKey;
    setStatus(statusEl, "");
    showScreen("screenVault");
    loadFileList();
  } catch {
    setStatus(statusEl, "Couldn't derive a key from that passphrase.", "error");
  }
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

  inputEl.disabled = true;
  setStatus(statusEl, "Encrypting on this device…");
  try {
    const arrayBuffer = await file.arrayBuffer();
    const { ciphertext, iv } = await encryptBytes(new Uint8Array(arrayBuffer));
    setStatus(statusEl, "Uploading encrypted file…");
    const res = await callBackend("uploadFile", {
      idToken,
      ciphertextBase64: bytesToBase64(ciphertext),
      ivBase64: bytesToBase64(iv),
      mimetype: file.type || "image/jpeg",
      idType,
    });
    if (!res.ok) {
      setStatus(statusEl, "Upload failed: " + (res.error || "unknown error"), "error");
      return;
    }
    setStatus(statusEl, "Saved to the vault.", "success");
    inputEl.value = "";
    idTypeSelect.selectedIndex = 0;
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
let activeTab = "mine"; // "mine" | "family"
let memberFilter = ""; // uploader email, "" = all

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

function populateMemberFilter() {
  const select = document.getElementById("memberFilterSelect");
  const previousValue = select.value;

  // Distinct uploaders, sorted by display name.
  const seen = new Map(); // email -> name
  for (const f of allFiles) {
    if (!seen.has(f.uploader)) seen.set(f.uploader, f.uploaderName || f.uploader);
  }
  const members = [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]));

  select.innerHTML = '<option value="">All family members</option>';
  for (const [email, name] of members) {
    const opt = document.createElement("option");
    opt.value = email;
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
  setStatus(listStatus, "Loading…");
  try {
    const res = await callBackend("listFiles", { idToken });
    if (!res.ok) {
      setStatus(listStatus, "Couldn't load documents.", "error");
      return;
    }
    allFiles = res.files;
    populateMemberFilter();
    renderFileList();
  } catch {
    setStatus(listStatus, "Couldn't reach the vault backend.", "error");
  }
}

function renderFileList() {
  const listEl = document.getElementById("fileList");
  const listStatus = document.getElementById("listStatus");
  const filterVal = document.getElementById("filterSelect").value;

  let scoped = activeTab === "mine"
    ? allFiles.filter(f => f.uploader === currentUser.email)
    : (memberFilter ? allFiles.filter(f => f.uploader === memberFilter) : allFiles);

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
  whoEl.textContent = (meta.idType ? meta.idType + " — " : "") + (meta.uploaderName || meta.uploader);
  metaEl.appendChild(whoEl);

  const whenEl = document.createElement("div");
  whenEl.className = "when";
  whenEl.textContent = new Date(meta.date).toLocaleString();
  metaEl.appendChild(whenEl);

  card.appendChild(metaEl);

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
    }
  });

  shareBtn.addEventListener("click", async () => {
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
    } catch {
      alert("Couldn't decrypt this file — check the passphrase.");
    }
  });

  return card;
}
