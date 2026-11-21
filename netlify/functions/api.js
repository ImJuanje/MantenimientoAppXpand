import crypto from "node:crypto";
import { db, json, hashPw, checkPw, makeToken, sessionOf, cookie } from "./lib.js";

export const config = { path: "/api/*" };

const MAX_TRIES = 5, BLOCK_MS = 15 * 60 * 1000, DAY = 86400000;
const DEFAULT_SETTINGS = { tipos: ["Caldera", "Climatización", "Extintores", "Protección contra incendios", "Ascensor"].map((nombre) => ({ nombre, meses: 12, checklist: [] })) };
const clean = (s) => String(s || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 32);

async function limited(key) {
  const r = (await db("rate").get(key, { type: "json" })) || { n: 0, until: 0 };
  return { r, blocked: r.until > Date.now() };
}
async function fail(key, r) {
  r.n += 1;
  if (r.n >= MAX_TRIES) { r.until = Date.now() + BLOCK_MS; r.n = 0; }
  await db("rate").setJSON(key, r);
}

class Conflict extends Error {}

const handle = async (req) => {
  const action = new URL(req.url).pathname.replace(/^\/api\//, "");
  const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
  const users = db("users"), invites = db("invites"), cfg = db("settings");
  const ses = sessionOf(req);
  const ip = req.headers.get("x-nf-client-connection-ip") || "x";

  if (action === "login") {
    const user = clean(body.user), key = `${ip}:${user}`, { r, blocked } = await limited(key);
    if (blocked) return json({ error: "Demasiados intentos. Prueba en 15 minutos." }, 429);
    let ok = false, role = "tecnico", c;
    if (user === "admin") {
      const a = Buffer.from(String(body.password || "")), b = Buffer.from(process.env.ADMIN_PASSWORD || "");
      ok = !!b.length && a.length === b.length && crypto.timingSafeEqual(a, b); role = "admin";
    } else {
      const u = await users.get(user, { type: "json" });
      ok = !!u && checkPw(String(body.password || ""), u.hash);
      c = u && u.created;
    }
    if (!ok) { await fail(key, r); return json({ error: "Usuario o contraseña incorrectos." }, 401); }
    await db("rate").delete(key);
    const age = body.remember ? 30 * DAY : DAY;
    return json({ user, role }, 200, { "set-cookie": cookie(makeToken({ user, role, c, exp: Date.now() + age }), body.remember ? age / 1000 : 0) });
  }

  if (action === "activate") {
    const user = clean(body.user), code = String(body.code || "").trim().toUpperCase();
    if (user.length < 3 || user === "admin" || String(body.password || "").length < 8)
      return json({ error: "Usuario mínimo 3 caracteres y contraseña mínimo 8." }, 400);
    const ck = `${ip}:code`, cl = await limited(ck);
    if (cl.blocked) return json({ error: "Demasiados intentos. Prueba en 15 minutos." }, 429);
    const inv = code ? await invites.get(code, { type: "json" }) : null;
    if (!inv || inv.reset || inv.exp < Date.now()) { await fail(ck, cl.r); return json({ error: "Código no válido o caducado." }, 400); }
    if (await users.get(user)) return json({ error: "Ese usuario ya existe." }, 409);
    await users.setJSON(user, { hash: hashPw(body.password), created: Date.now() });
    await invites.delete(code);
    return json({ ok: true });
  }

  if (action === "reset-password") {
    const code = String(body.code || "").trim().toUpperCase();
    if (String(body.password || "").length < 8) return json({ error: "La contraseña necesita mínimo 8 caracteres." }, 400);
    const ck = `${ip}:code`, cl = await limited(ck);
    if (cl.blocked) return json({ error: "Demasiados intentos. Prueba en 15 minutos." }, 429);
    const inv = code ? await invites.get(code, { type: "json" }) : null;
    const u = inv && inv.reset && inv.exp > Date.now() ? await users.get(inv.reset, { type: "json" }) : null;
    if (!u) { await fail(ck, cl.r); return json({ error: "Código no válido o caducado." }, 400); }
    await users.setJSON(inv.reset, { ...u, hash: hashPw(body.password), created: Date.now() });
    await invites.delete(code);
    return json({ ok: true });
  }

  if (action === "logout") return json({ ok: true }, 200, { "set-cookie": cookie("", 0) + "; Max-Age=0" });
  if (!ses) return json({ error: "Sesión no válida." }, 401);
  if (ses.role !== "admin") {
    const u = await users.get(ses.user, { type: "json" });
    if (!u || u.created !== ses.c) return json({ error: "Tu acceso ya no está activo. Entra de nuevo." }, 401);
  }
  if (action === "me") return json({ user: ses.user, role: ses.role });
  if (action === "settings-get") return json((await cfg.get("main", { type: "json" })) || DEFAULT_SETTINGS);

  if (ses.role !== "admin") return json({ error: "Solo el administrador puede hacer esto." }, 403);

  if (action === "settings-set") {
    const tipos = (body.tipos || []).slice(0, 30).map((t) => ({
      nombre: String(t.nombre || "").trim().slice(0, 60), meses: Math.round(Number(t.meses)),
      checklist: (t.checklist || []).map((x) => String(x).trim().slice(0, 120)).filter(Boolean).slice(0, 40) })).filter((t) => t.nombre);
    if (!tipos.length || tipos.some((t) => !(t.meses >= 1 && t.meses <= 120)) || new Set(tipos.map((t) => t.nombre.toLowerCase())).size !== tipos.length)
      return json({ error: "Revisa los tipos: nombre único y periodicidad de 1 a 120 meses." }, 400);
    await cfg.setJSON("main", { tipos });
    return json({ ok: true });
  }
  if (action === "reset-create") {
    const user = clean(body.user);
    if (!user || !(await users.get(user))) return json({ error: "Ese técnico no existe." }, 404);
    const code = crypto.randomBytes(4).toString("hex").toUpperCase();
    await invites.setJSON(code, { exp: Date.now() + DAY, reset: user });
    return json({ code });
  }
  if (action === "invite-create") {
    const code = crypto.randomBytes(4).toString("hex").toUpperCase();
    await invites.setJSON(code, { exp: Date.now() + 3 * DAY });
    return json({ code });
  }
  if (action === "invite-delete") { await invites.delete(String(body.code || "")); return json({ ok: true }); }
  if (action === "team-list") {
    const u = (await users.list()).blobs.map((b) => b.key);
    const i = await Promise.all((await invites.list()).blobs.map(async (b) => ({ code: b.key, ...(await invites.get(b.key, { type: "json" })) })));
    return json({ users: u, invites: i.filter((x) => x.exp > Date.now()) });
  }
  if (action === "user-delete") {
    const u = clean(body.user);
    if (!u || u === "admin") return json({ error: "Usuario no válido." }, 400);
    await users.delete(u);
    return json({ ok: true });
  }

  return json({ error: "No encontrado." }, 404);
};

export default async (req) => {
  try { return await handle(req); }
  catch (e) {
    if (e instanceof Conflict) return json({ error: "Otra persona ha modificado esto a la vez. Vuelve a intentarlo." }, 409);
    console.error(e);
    return json({ error: "Algo ha fallado. Inténtalo de nuevo en unos segundos." }, 500);
  }
};
