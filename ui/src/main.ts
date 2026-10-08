import "./style.css";
import {
  blockPolls, identity, identityFrom, listPoll, loadRegistry, loadState, newInvites, onRemoteChange, publish, rename, sendResponse, signAnswers, storeGet, storePut, watch,
  type Answers, type FormState, type Kind, type Question, type Schema,
} from "./lib";

const app = document.getElementById("app")!;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const $ = <T extends HTMLElement>(sel: string, root: ParentNode = app) => root.querySelector(sel) as T;

// route: #/ (builder)  |  #/f/<instanceB58>.<paramsHex>[/i/<inviteSecretHex>] (poll)
function route() {
  // inside the Freenet container, keep the address bar in sync so the URL is shareable
  if (window.parent !== window) parent.postMessage({ __freenet_shell__: true, type: "hash", hash: location.hash || "#/" }, "*");
  if (location.hash === "#/explore") return explore();
  if (location.hash === "#/admin") return admin(); // not linked anywhere
  const m = location.hash.match(/^#\/f\/([1-9A-HJ-NP-Za-km-z]+)\.([0-9a-f]{96})(?:\/i\/([0-9a-f]{64}))?$/);
  return m ? form(m[1], m[2], m[3]) : builder();
}
// page URL without the container's ?__sandbox=1 query
const pageUrl = (hash: string) => `${location.protocol}//${location.host}${location.pathname}${hash}`;

// ---------------- my polls (kept by the identity delegate, or localStorage as a fallback) ----------------
type Saved = { title: string; hash: string };
const myForms = async (): Promise<Saved[]> => { try { return JSON.parse((await storeGet("polls")) ?? "[]"); } catch { return []; } };
const saveForm = async (f: Saved) => storePut("polls", JSON.stringify([f, ...(await myForms())]));

// ---------------- builder ----------------
function builder() {
  const qs: Question[] = [{ id: "q1", kind: "single", text: "", options: ["", ""], required: true }];
  let title = "", inviteOnly = false, listed = false, nInvites = 10, mine: Saved[] = [];
  const draw = () => {
    app.innerHTML = `
      <h1>FreePolls <small>polls and forms on Freenet</small></h1>
      <p><a href="#/explore">Explore public polls &rarr;</a></p>
      <input id="title" placeholder="Title" value="${esc(title)}" />
      ${qs.map((q, i) => `
        <section class="card" data-i="${i}">
          <input class="qt" placeholder="Question" value="${esc(q.text)}" />
          <select class="qk">${(["single", "multi", "avail", "text"] as Kind[]).map((k) =>
            `<option value="${k}" ${k === q.kind ? "selected" : ""}>${{ single: "Single choice", multi: "Multiple choice", avail: "Availability (dates/times)", text: "Text" }[k]}</option>`).join("")}</select>
          ${q.kind === "text" ? "" : `<textarea class="qo" placeholder="${q.kind === "avail" ? "One slot per line, e.g. Mon Oct 12 6pm" : "One option per line"}">${esc(q.options.join("\n"))}</textarea>`}
          <label><input type="checkbox" class="qr" ${q.required ? "checked" : ""}/> required</label>
          <button class="up" type="button" ${i === 0 ? "disabled" : ""}>↑</button>
          <button class="down" type="button" ${i === qs.length - 1 ? "disabled" : ""}>↓</button>
          <button class="del" type="button">Remove</button>
        </section>`).join("")}
      <label><input type="checkbox" id="io" ${inviteOnly ? "checked" : ""}/> Invite only: one personal link = one vote</label>
      ${inviteOnly ? `<label>Number of invites <input id="ni" type="number" min="1" max="200" value="${nInvites}" /></label>` : ""}
      <label><input type="checkbox" id="ls" ${listed && !inviteOnly ? "checked" : ""} ${inviteOnly ? "disabled" : ""}/> List in the public directory (the title and your owner key become discoverable)</label>
      <p><button id="add" type="button">+ Question</button> <button id="pub" type="button" class="primary">Publish</button></p>
      <p id="msg"></p>
      <div id="mine"></div>`;
    $("#mine").innerHTML = mine.length ? `<h2>My polls</h2><ul>${mine.map((f) => `<li><a href="${esc(f.hash)}">${esc(f.title)}</a></li>`).join("")}</ul>` : "";
    $<HTMLInputElement>("#title").oninput = (e) => (title = (e.target as HTMLInputElement).value);
    $<HTMLInputElement>("#io").onchange = (e) => { inviteOnly = (e.target as HTMLInputElement).checked; if (inviteOnly) listed = false; draw(); };
    $<HTMLInputElement>("#ls").onchange = (e) => (listed = (e.target as HTMLInputElement).checked);
    const ni = app.querySelector<HTMLInputElement>("#ni");
    if (ni) ni.oninput = () => (nInvites = Math.min(200, Math.max(1, +ni.value || 1)));
    app.querySelectorAll<HTMLElement>("section.card").forEach((s) => {
      const i = +s.dataset.i!, q = qs[i];
      $<HTMLInputElement>(".qt", s).oninput = (e) => (q.text = (e.target as HTMLInputElement).value);
      $<HTMLSelectElement>(".qk", s).onchange = (e) => { q.kind = (e.target as HTMLSelectElement).value as Kind; draw(); };
      const o = s.querySelector<HTMLTextAreaElement>(".qo");
      if (o) o.oninput = () => (q.options = o.value.split("\n"));
      $<HTMLInputElement>(".qr", s).onchange = (e) => (q.required = (e.target as HTMLInputElement).checked);
      const move = (d: number) => { [qs[i], qs[i + d]] = [qs[i + d], qs[i]]; draw(); };
      $<HTMLButtonElement>(".up", s).onclick = () => move(-1);
      $<HTMLButtonElement>(".down", s).onclick = () => move(1);
      $<HTMLButtonElement>(".del", s).onclick = () => { qs.splice(i, 1); draw(); };
    });
    $("#add").onclick = () => { qs.push({ id: `q${Date.now().toString(36)}`, kind: "single", text: "", options: ["", ""], required: false }); draw(); };
    $("#pub").onclick = async () => {
      const schema: Schema = {
        title: title.trim(),
        questions: qs.map((q) => ({ ...q, options: q.kind === "text" ? [] : q.options.map((o) => o.trim()).filter(Boolean) })),
      };
      const bad = !schema.title || !schema.questions.length ||
        schema.questions.some((q) => !q.text.trim() || (q.kind !== "text" && q.options.length < (q.kind === "avail" ? 1 : 2)));
      const msg = $("#msg");
      if (bad) return void (msg.textContent = "A title, question text and at least 2 options per choice question (1 slot for availability).");
      msg.textContent = "Publishing...";
      try {
        const invites = inviteOnly ? await newInvites(nInvites) : [];
        if (invites.length) schema.allowed = invites.map((i) => i.pk);
        const { instance, params } = await publish(schema);
        const hash = `#/f/${instance}.${params}`;
        await saveForm({ title: schema.title, hash });
        if (listed && !invites.length) {
          msg.textContent = "Listing in the public directory (a few seconds of proof-of-work)...";
          try { await listPoll(instance, params, schema.title.slice(0, 120)); }
          catch (e) { return void (msg.innerHTML = `Published, but listing failed: ${esc(String(e))}. <a href="${esc(hash)}">Open the poll</a>`); }
        }
        if (!invites.length) return void (location.hash = hash);
        const secrets = invites.map((i) => i.secret);
        await storePut(`inv:${instance}`, JSON.stringify(secrets));
        showInvites(hash, secrets);
      } catch (e) { msg.textContent = `Error: ${e}`; }
    };
  };
  draw();
  void myForms().then((m) => { if (m.length) { mine = m; draw(); } });
}

// ---------------- public directory ----------------
async function explore() {
  app.innerHTML = `<p><a href="#/">\u2190 New poll</a></p><h1>Public polls</h1><div id="list">Loading... (the first visit on a node can take up to 30 s)</div>`;
  try {
    const rows = Object.entries((await loadRegistry()).entries).sort(([, a], [, b]) => b.ts - a.ts);
    $("#list").innerHTML = rows.length
      ? `<ul>${rows.map(([id, e]) => `<li><a href="#/f/${esc(id)}.${esc(e.params)}">${esc(e.title)}</a> <small class="muted">${new Date(e.ts).toLocaleDateString()}</small></li>`).join("")}</ul>`
      : "<p>No public polls yet.</p>";
  } catch (e) { $("#list").textContent = `Could not load the directory: ${e}`; }
}

// admin page: hide polls from the directory with the admin key (hash #/admin)
async function admin() {
  app.innerHTML = `
    <p><a href="#/">\u2190 Back</a></p>
    <h1>Directory admin</h1>
    <p class="muted">Admin secret (hex) and the poll ids to hide, one per line. This replaces the whole blocklist.</p>
    <input id="sk" type="password" autocomplete="off" placeholder="Admin secret" />
    <textarea id="bl" rows="6"></textarea>
    <p><button id="go" class="primary" type="button">Publish blocklist</button> <span id="msg"></span></p>`;
  try { $<HTMLTextAreaElement>("#bl").value = (await loadRegistry()).blocked.list.join("\n"); }
  catch (e) { $("#msg").textContent = `Could not load the directory: ${e}`; }
  $("#go").onclick = async () => {
    const list = $<HTMLTextAreaElement>("#bl").value.split("\n").map((l) => l.trim()).filter(Boolean);
    $("#msg").textContent = "Sending...";
    try { await blockPolls($<HTMLInputElement>("#sk").value.trim(), list); $("#msg").textContent = `Done: ${list.length} blocked.`; }
    catch (e) { $("#msg").textContent = `Error: ${e}`; }
  };
}

// ---------------- invite links (secrets exist only in the browser that created the poll) ----------------
const inviteLinks = (hash: string, secrets: string[]) => secrets.map((s) => pageUrl(`${hash}/i/${s}`));

function showInvites(hash: string, secrets: string[]) {
  const links = inviteLinks(hash, secrets);
  app.innerHTML = `
    <h1>Poll published</h1>
    <p>${links.length} invites, one link per person. <b>Save them now</b>: personal links cannot be rebuilt and will not be shown again unless this browser remembers them.</p>
    <textarea id="links" readonly rows="${Math.min(links.length, 12) + 1}">${esc(links.join("\n"))}</textarea>
    <p><button id="copy" class="primary" type="button">Copy all</button> <a href="${esc(hash)}">Open the poll</a></p>`;
  $("#copy").onclick = async () => {
    const t = $<HTMLTextAreaElement>("#links");
    t.select();
    try { await navigator.clipboard.writeText(t.value); } catch { document.execCommand("copy"); }
  };
}

// ---------------- form: fill + live results ----------------
async function form(instance: string, params: string, invite?: string) {
  app.innerHTML = "<p>Loading...</p>";
  const me = invite ? await identityFrom(invite) : await identity();
  let st: FormState, schema: Schema;
  try {
    st = await loadState(instance);
    schema = JSON.parse(st.schema_json);
    void watch(instance).catch(console.warn); // subscribe() may not resolve in local mode; don't block on it
  } catch (e) { return void (app.innerHTML = `<p class="err">Could not load the poll: ${esc(String(e))}</p>`); }

  const link = pageUrl(`#/f/${instance}.${params}`);
  const invited = !schema.allowed || schema.allowed.includes(me.pk);
  let savedInvites: string[] = [];
  try { savedInvites = JSON.parse((await storeGet(`inv:${instance}`)) ?? "[]"); } catch { /* unreadable: no saved invites */ }
  const draw = () => {
    const mine = st.responses[me.pk];
    const prev: Answers = mine ? JSON.parse(mine.answers_json) : {};
    const n = Object.keys(st.responses).length;
    const own = me.pk === params.slice(0, 64);
    const intro = !schema.allowed
      ? `<p class="muted">${own ? "You are the owner. " : ""}Link to share: <input readonly value="${esc(link)}" onfocus="this.select()" /></p>` +
        (own ? `<p><button id="list-btn" type="button">List in the public directory</button> <span id="list-msg" class="muted">Public and permanent: anyone can see the title.</span></p>` : "")
      : `<p class="muted">${own ? `You are the owner. Invite-only poll: ${schema.allowed.length} invites.` : invited ? "You have a personal invite: keep this link to change your answer later." : "Invite-only poll: you need your personal link to answer."}</p>` +
        (own && savedInvites.length ? `<details><summary>Invite links (${savedInvites.length})</summary><textarea readonly rows="6" onfocus="this.select()">${esc(inviteLinks(`#/f/${instance}.${params}`, savedInvites).join("\n"))}</textarea></details>` : "");
    app.innerHTML = `
      <p><a href="#/">← New poll</a></p>
      <h1>${esc(schema.title)}</h1>
      ${own ? `<p><button id="ren" type="button">Rename</button> <span id="ren-msg" class="muted"></span></p>` : ""}
      ${intro}
      ${me.persisted || !invited ? "" : `<p class="muted">⚠ Temporary identity: you can update your answer until you close the page; after that you will count as a new respondent.</p>`}
      <form id="f" ${invited ? "" : "hidden"}>
        ${schema.questions.map((q) => `
          <fieldset><legend>${esc(q.text)}${q.required ? " *" : ""}</legend>
          ${q.kind === "text"
            ? `<textarea name="${q.id}" maxlength="2000">${esc(String(prev[q.id] ?? ""))}</textarea>`
            : q.kind === "avail"
            ? q.options.map((o, i) => {
                const cur = ((prev[q.id] as number[]) ?? [])[i] ?? 0;
                return `<label class="slot"><span>${esc(o)}</span><select name="${q.id}">${([[1, "Yes"], [2, "Maybe"], [0, "No"]] as const).map(([v, t]) =>
                  `<option value="${v}" ${cur === v ? "selected" : ""}>${t}</option>`).join("")}</select></label>`;
              }).join("")
            : q.options.map((o, i) => {
                const on = q.kind === "multi" ? ((prev[q.id] as number[]) ?? []).includes(i) : prev[q.id] === i;
                return `<label><input type="${q.kind === "multi" ? "checkbox" : "radio"}" name="${q.id}" value="${i}" ${on ? "checked" : ""}/> ${esc(o)}</label>`;
              }).join("")}
          </fieldset>`).join("")}
        <button class="primary">${mine ? "Update answer" : "Submit"}</button> <span id="msg"></span>
      </form>
      <h2>Results (${n} ${n === 1 ? "response" : "responses"})</h2>
      ${results()}`;
    const renBtn = app.querySelector<HTMLButtonElement>("#ren");
    if (renBtn) renBtn.onclick = async () => {
      const t = prompt("New title", schema.title)?.trim();
      if (!t || t === schema.title) return;
      try { await rename(instance, params, schema, t); await refresh(); }
      catch (err) { $("#ren-msg").textContent = `Rename failed: ${err}`; }
    };
    const listBtn = app.querySelector<HTMLButtonElement>("#list-btn");
    if (listBtn) listBtn.onclick = async () => {
      const m = $("#list-msg");
      listBtn.disabled = true;
      m.textContent = "Mining the proof of work (a few seconds)...";
      try { await listPoll(instance, params, schema.title.slice(0, 120)); m.textContent = "Listed: it now shows under Explore."; }
      catch (err) { m.textContent = `Listing failed: ${err}`; listBtn.disabled = false; }
    };
    $<HTMLFormElement>("#f").onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target as HTMLFormElement), a: Answers = {};
      for (const q of schema.questions) {
        const v = fd.getAll(q.id).map(String);
        if (q.kind === "text") { if (v[0]) a[q.id] = v[0]; }
        else if (q.kind === "multi" || q.kind === "avail") { if (v.length) a[q.id] = v.map(Number); }
        else if (v.length) a[q.id] = +v[0];
        if (q.required && !(q.id in a)) return void ($("#msg").textContent = `Missing: ${q.text}`);
      }
      $("#msg").textContent = "Sending...";
      try { await sendResponse(instance, me.pk, await signAnswers(me, params, a)); await refresh(); }
      catch (err) { $("#msg").textContent = /timeout/i.test(String(err)) ? "The node did not accept the answer (invite-only poll: you need your personal link)." : `Errore: ${err}`; }
    };
  };

  const results = () => schema.questions.map((q) => {
    const all = Object.values(st.responses).map((r) => (JSON.parse(r.answers_json) as Answers)[q.id]).filter((v) => v !== undefined);
    if (q.kind === "text") return `<h3>${esc(q.text)}</h3><ul>${all.map((t) => `<li>${esc(String(t))}</li>`).join("")}</ul>`;
    if (q.kind === "avail") {
      const yes = q.options.map(() => 0), maybe = q.options.map(() => 0);
      all.forEach((v) => (v as number[]).forEach((x, i) => { if (x === 1) yes[i]++; else if (x === 2) maybe[i]++; }));
      // best slot = most "yes", ties broken by "maybe"; none highlighted until someone says yes or maybe
      const score = (i: number) => yes[i] * 1000 + maybe[i];
      const best = Math.max(...q.options.map((_, i) => score(i)));
      const max = Math.max(1, ...yes.map((y, i) => y + maybe[i]));
      return `<h3>${esc(q.text)}</h3>` + q.options.map((o, i) =>
        `<div class="bar${best > 0 && score(i) === best ? " best" : ""}"><span>${best > 0 && score(i) === best ? "★ " : ""}${esc(o)}</span>` +
        `<i style="width:${(yes[i] / max) * 100}%"></i><u style="left:${(yes[i] / max) * 100}%;width:${(maybe[i] / max) * 100}%"></u>` +
        `<b>${yes[i]} yes${maybe[i] ? ` · ${maybe[i]} maybe` : ""}</b></div>`).join("");
    }
    const counts = q.options.map(() => 0);
    all.forEach((v) => ([] as number[]).concat(v as number | number[]).forEach((i) => counts[i]++));
    const max = Math.max(1, ...counts);
    return `<h3>${esc(q.text)}</h3>` + q.options.map((o, i) =>
      `<div class="bar"><span>${esc(o)}</span><i style="width:${(counts[i] / max) * 100}%"></i><b>${counts[i]}</b></div>`).join("");
  }).join("");

  const refresh = async () => {
    // skip redraw while the user is typing in the form
    const typing = app.contains(document.activeElement) && document.activeElement instanceof HTMLTextAreaElement;
    st = await loadState(instance);
    schema = JSON.parse(st.schema_json);
    if (!typing) draw();
  };
  onRemoteChange(() => void refresh()); // ponytail: refetch full state on notification; use deltas if responses get large
  draw();
}

// start last: route() uses consts declared above (TDZ otherwise)
addEventListener("hashchange", route);
route();
