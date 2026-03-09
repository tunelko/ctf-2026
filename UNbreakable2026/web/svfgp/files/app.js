const boot = (() => {
  try {
    const raw = document.body.getAttribute("data-boot");
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    }
  } catch (_) {}
  return {};
})();

const NOTES_KEY = "svfgp.notes.v1";
const MILS = 3;
const THOUSANDS = 1000;
const KDF_ITERATIONS = THOUSANDS * THOUSANDS * MILS;
function param(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
}

function loadNotes() {
  try {
    const raw = JSON.parse(localStorage.getItem(NOTES_KEY));
    if (!Array.isArray(raw)) return [];
    return raw.filter(
      (n) =>
        n &&
        typeof n === "object" &&
        typeof n.id === "string" &&
        typeof n.title === "string" &&
        typeof n.content === "string",
    );
  } catch (_) {
    return [];
  }
}

function saveNotes(notes) {
  localStorage.setItem(NOTES_KEY, JSON.stringify(notes));
}

function addNote(title, content, sealed) {
  const notes = loadNotes();
  notes.unshift({
    id: `n-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`,
    title,
    content,
    sealed: Boolean(sealed),
  });
  saveNotes(notes);
}

function loadSecret() {
  const sealed = loadNotes().find((n) => n.sealed === true);
  return sealed ? sealed.content : "";
}

async function deriveHash(value) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(value),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: KDF_ITERATIONS },
    key,
    256,
  );
}

function encodeNote(title, content) {
  return btoa(unescape(encodeURIComponent(JSON.stringify({ t: title, c: content }))));
}

function decodeNote(encoded) {
  try {
    const parsed = JSON.parse(decodeURIComponent(escape(atob(encoded))));
    if (parsed && typeof parsed.t === "string" && typeof parsed.c === "string") {
      return { title: parsed.t, content: parsed.c };
    }
  } catch (_) {}
  return null;
}

function shareUrl(note) {
  return `${location.origin}/?note=${encodeURIComponent(encodeNote(note.title, note.content))}`;
}

function sanitize(html) {
  return DOMPurify.sanitize(html);
}

function noteMatchesQuery(note, q) {
  if (!q) return true;
  if (note.sealed) return note.content.startsWith(q);
  return note.title.includes(q) || note.content.includes(q);
}

function renderNotes(q) {
  const list = document.getElementById("resultList");
  const meta = document.getElementById("searchMeta");
  list.innerHTML = "";

  const notes = loadNotes().filter((n) => noteMatchesQuery(n, q));
  if (notes.length === 0) {
    meta.textContent = q ? "No results." : "No notes yet.";
    return;
  }

  meta.textContent = `${notes.length} note(s).`;

  for (const note of notes) {
    const card = document.createElement("article");
    card.className = "note-card";

    const h = document.createElement("h3");
    h.textContent = note.title;
    if (note.sealed) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = "sealed";
      h.append(" ", badge);
    }
    card.appendChild(h);

    const body = document.createElement("div");
    body.className = "note-body";
    if (note.sealed) {
      body.textContent = "Content sealed.";
    } else {
      body.innerHTML = sanitize(note.content);
    }
    card.appendChild(body);

    if (!note.sealed) {
      const share = document.createElement("button");
      share.className = "btn-share";
      share.textContent = "share";
      share.addEventListener("click", () => {
        const url = shareUrl(note);
        navigator.clipboard.writeText(url).then(
          () => {
            share.textContent = "copied!";
            setTimeout(() => { share.textContent = "share"; }, 1500);
          },
          () => { prompt("Share link:", url); },
        );
      });
      card.appendChild(share);
    }

    list.appendChild(card);
  }
}

function handleSharedNote() {
  const encoded = boot.note || param("note");
  if (!encoded) return;

  const note = decodeNote(encoded);
  if (!note) return;

  const section = document.getElementById("sharedNote");
  const titleEl = document.getElementById("sharedTitle");
  const contentEl = document.getElementById("sharedContent");

  titleEl.textContent = note.title;
  contentEl.innerHTML = sanitize(note.content);
  section.hidden = false;

  document.getElementById("saveShared").addEventListener("click", () => {
    addNote(note.title, note.content, false);
    section.hidden = true;
    renderNotes("");
  });
}

function initViewMode() {
  document.getElementById("notesPane").hidden = false;

  const searchInput = document.getElementById("searchInput");
  const q = boot.q || param("q");
  searchInput.value = q;
  renderNotes(q);
  handleSharedNote();

  document.getElementById("createForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const titleEl = document.getElementById("noteTitle");
    const bodyEl = document.getElementById("noteBody");
    const title = titleEl.value.trim();
    const content = bodyEl.value.trim();
    if (!title || !content) return;

    addNote(title, content, false);
    titleEl.value = "";
    bodyEl.value = "";
    renderNotes(searchInput.value.trim());
  });

  document.getElementById("searchForm").addEventListener("submit", (e) => {
    e.preventDefault();
    renderNotes(searchInput.value.trim());
  });
}

async function runProbeMode() {
  document.getElementById("probePane").hidden = false;
  document.getElementById("notesPane").hidden = true;

  const candidate = boot.q || param("q");
  const sid = boot.sid || param("sid");
  const rid = boot.rid || param("rid");
  const secret = loadSecret();

  if (secret && candidate && secret.startsWith(candidate)) {
    await deriveHash(secret);
  }

  try {
    window.opener.postMessage({ type: "svfgp-probe-done", sid, rid }, "*");
  } catch (_) {}
}

window.addEventListener("DOMContentLoaded", () => {
  const mode = boot.mode || param("mode");
  if (mode === "probe") {
    runProbeMode();
  } else {
    initViewMode();
  }
});
