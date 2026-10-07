import "./style.css";
import {
  identity, loadState, onRemoteChange, publish, sendResponse, signAnswers, watch,
  type Answers, type FormState, type Kind, type Question, type Schema,
} from "./lib";

const app = document.getElementById("app")!;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const $ = <T extends HTMLElement>(sel: string, root: ParentNode = app) => root.querySelector(sel) as T;

// route: #/ (builder)  |  #/f/<instanceB58>.<ownerHex> (form)
function route() {
  const m = location.hash.match(/^#\/f\/([1-9A-HJ-NP-Za-km-z]+)\.([0-9a-f]{64})$/);
  return m ? form(m[1], m[2]) : builder();
}
// ---------------- my forms (per-browser list; ponytail: localStorage, lost if site data is cleared) ----------------
type Saved = { title: string; hash: string };
const myForms = (): Saved[] => { try { return JSON.parse(localStorage.getItem("fp-polls") ?? "[]"); } catch { return []; } };
const saveForm = (f: Saved) => { try { localStorage.setItem("fp-polls", JSON.stringify([f, ...myForms()])); } catch { /* storage blocked */ } };

// ---------------- builder ----------------
function builder() {
  const qs: Question[] = [{ id: "q1", kind: "single", text: "", options: ["", ""], required: true }];
  let title = "";
  const draw = () => {
    app.innerHTML = `
      <h1>FreePolls <small>sondaggi e form su Freenet</small></h1>
      <input id="title" placeholder="Titolo" value="${esc(title)}" />
      ${qs.map((q, i) => `
        <section class="card" data-i="${i}">
          <input class="qt" placeholder="Domanda" value="${esc(q.text)}" />
          <select class="qk">${(["single", "multi", "avail", "text"] as Kind[]).map((k) =>
            `<option value="${k}" ${k === q.kind ? "selected" : ""}>${{ single: "Scelta singola", multi: "Scelta multipla", avail: "Disponibilità (date/orari)", text: "Testo" }[k]}</option>`).join("")}</select>
          ${q.kind === "text" ? "" : `<textarea class="qo" placeholder="${q.kind === "avail" ? "Uno slot per riga, es. Lun 12 ott 18:00" : "Una opzione per riga"}">${esc(q.options.join("\n"))}</textarea>`}
          <label><input type="checkbox" class="qr" ${q.required ? "checked" : ""}/> obbligatoria</label>
          <button class="up" type="button" ${i === 0 ? "disabled" : ""}>↑</button>
          <button class="down" type="button" ${i === qs.length - 1 ? "disabled" : ""}>↓</button>
          <button class="del" type="button">Rimuovi</button>
        </section>`).join("")}
      <p><button id="add" type="button">+ Domanda</button> <button id="pub" type="button" class="primary">Pubblica</button></p>
      <p id="msg"></p>
      ${myForms().length ? `<h2>I miei sondaggi</h2><ul>${myForms().map((f) => `<li><a href="${esc(f.hash)}">${esc(f.title)}</a></li>`).join("")}</ul>` : ""}`;
    $<HTMLInputElement>("#title").oninput = (e) => (title = (e.target as HTMLInputElement).value);
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
      if (bad) return void (msg.textContent = "Titolo, testo domande e almeno 2 opzioni per le scelte (1 slot per la disponibilità).");
      msg.textContent = "Pubblicazione...";
      try {
        const { instance, owner } = await publish(schema);
        const hash = `#/f/${instance}.${owner}`;
        saveForm({ title: schema.title, hash });
        location.hash = hash;
      } catch (e) { msg.textContent = `Errore: ${e}`; }
    };
  };
  draw();
}

// ---------------- form: fill + live results ----------------
async function form(instance: string, owner: string) {
  app.innerHTML = "<p>Caricamento...</p>";
  const me = await identity();
  let st: FormState, schema: Schema;
  try {
    st = await loadState(instance);
    schema = JSON.parse(st.schema_json);
    void watch(instance).catch(console.warn); // subscribe() may not resolve in local mode; don't block on it
  } catch (e) { return void (app.innerHTML = `<p class="err">Impossibile caricare il form: ${esc(String(e))}</p>`); }

  const link = location.href;
  const draw = () => {
    const mine = st.responses[me.pk];
    const prev: Answers = mine ? JSON.parse(mine.answers_json) : {};
    const n = Object.keys(st.responses).length;
    app.innerHTML = `
      <p><a href="#/">← Nuovo sondaggio</a></p>
      <h1>${esc(schema.title)}</h1>
      <p class="muted">${me.pk === owner ? "Sei il proprietario. " : ""}Link da condividere: <input readonly value="${esc(link)}" onfocus="this.select()" /></p>
      ${me.persisted ? "" : `<p class="muted">⚠ Identità temporanea: finché chiudi la pagina puoi aggiornare la tua risposta, dopo conterà come un nuovo rispondente.</p>`}
      <form id="f">
        ${schema.questions.map((q) => `
          <fieldset><legend>${esc(q.text)}${q.required ? " *" : ""}</legend>
          ${q.kind === "text"
            ? `<textarea name="${q.id}" maxlength="2000">${esc(String(prev[q.id] ?? ""))}</textarea>`
            : q.kind === "avail"
            ? q.options.map((o, i) => {
                const cur = ((prev[q.id] as number[]) ?? [])[i] ?? 0;
                return `<label class="slot"><span>${esc(o)}</span><select name="${q.id}">${([[1, "Sì"], [2, "Forse"], [0, "No"]] as const).map(([v, t]) =>
                  `<option value="${v}" ${cur === v ? "selected" : ""}>${t}</option>`).join("")}</select></label>`;
              }).join("")
            : q.options.map((o, i) => {
                const on = q.kind === "multi" ? ((prev[q.id] as number[]) ?? []).includes(i) : prev[q.id] === i;
                return `<label><input type="${q.kind === "multi" ? "checkbox" : "radio"}" name="${q.id}" value="${i}" ${on ? "checked" : ""}/> ${esc(o)}</label>`;
              }).join("")}
          </fieldset>`).join("")}
        <button class="primary">${mine ? "Aggiorna risposta" : "Invia"}</button> <span id="msg"></span>
      </form>
      <h2>Risultati (${n} ${n === 1 ? "risposta" : "risposte"})</h2>
      ${results()}`;
    $<HTMLFormElement>("#f").onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target as HTMLFormElement), a: Answers = {};
      for (const q of schema.questions) {
        const v = fd.getAll(q.id).map(String);
        if (q.kind === "text") { if (v[0]) a[q.id] = v[0]; }
        else if (q.kind === "multi" || q.kind === "avail") { if (v.length) a[q.id] = v.map(Number); }
        else if (v.length) a[q.id] = +v[0];
        if (q.required && !(q.id in a)) return void ($("#msg").textContent = `Manca: ${q.text}`);
      }
      $("#msg").textContent = "Invio...";
      try { await sendResponse(instance, me.pk, await signAnswers(me.sk, owner, me.pk, a)); await refresh(); }
      catch (err) { $("#msg").textContent = `Errore: ${err}`; }
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
        `<b>${yes[i]} sì${maybe[i] ? ` · ${maybe[i]} forse` : ""}</b></div>`).join("");
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
    if (!typing) draw();
  };
  onRemoteChange(() => void refresh()); // ponytail: refetch full state on notification; use deltas if responses get large
  draw();
}

// start last: route() uses consts declared above (TDZ otherwise)
addEventListener("hashchange", route);
route();
