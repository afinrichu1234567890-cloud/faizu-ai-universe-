const SESSION_SECONDS = 60 * 60 * 24 * 14;
const encoder = new TextEncoder();
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
async function digest(value) { return hex(await crypto.subtle.digest("SHA-256", encoder.encode(value))); }
function cookie(token, maxAge = SESSION_SECONDS) { return `fa_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`; }
function randomToken() { const a = new Uint8Array(32); crypto.getRandomValues(a); return [...a].map(x => x.toString(16).padStart(2,"0")).join(""); }
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: encoder.encode(salt), iterations: 210000, hash: "SHA-256" }, key, 256);
  return hex(bits);
}
async function body(request) { try { return await request.json(); } catch { return {}; } }
function getCookie(request, name) { const all = request.headers.get("cookie") || ""; const found = all.split(";").map(x => x.trim()).find(x => x.startsWith(name + "=")); return found ? found.slice(name.length + 1) : ""; }
async function currentUser(request, env) {
  const token = getCookie(request, "fa_session"); if (!token) return null;
  const row = await env.DB.prepare("SELECT users.id, users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?").bind(await digest(token), Date.now()).first();
  return row || null;
}
async function route(request, env, next) {
  const url = new URL(request.url), path = url.pathname;
  if (request.method === "POST" && path === "/api/register") {
    const { email, password } = await body(request);
    if (typeof email !== "string" || !/^\S+@\S+\.\S+$/.test(email) || typeof password !== "string" || password.length < 10) return json({ error: "ശരിയായ email നൽകുക; password കുറഞ്ഞത് 10 അക്ഷരമാകണം." }, 400);
    const normalized = email.trim().toLowerCase(), id = crypto.randomUUID(), salt = id;
    try { await env.DB.prepare("INSERT INTO users(id,email,password_hash,created_at) VALUES(?,?,?,?)").bind(id, normalized, `${salt}:${await passwordHash(password,salt)}`, Date.now()).run(); }
    catch { return json({ error: "ഈ email ഇതിനകം രജിസ്റ്റർ ചെയ്തിരിക്കാം." }, 409); }
    return createSession(id, normalized, env);
  }
  if (request.method === "POST" && path === "/api/login") {
    const { email, password } = await body(request);
    if (typeof email !== "string" || typeof password !== "string") return json({ error: "Email, password നൽകുക." }, 400);
    const user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email.trim().toLowerCase()).first();
    if (!user) return json({ error: "Email അല്ലെങ്കിൽ password ശരിയല്ല." }, 401);
    const [salt, stored] = user.password_hash.split(":");
    if (await passwordHash(password,salt) !== stored) return json({ error: "Email അല്ലെങ്കിൽ password ശരിയല്ല." }, 401);
    return createSession(user.id, user.email, env);
  }
  if (request.method === "POST" && path === "/api/logout") {
    const token = getCookie(request,"fa_session"); if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return json({ ok: true }, 200, { "set-cookie": cookie("",0) });
  }
  if (request.method === "GET" && path === "/api/me") {
    const user = await currentUser(request,env); return user ? json({ user }) : json({ user: null },401);
  }
  if (request.method === "POST" && path === "/api/chat") {
    const user = await currentUser(request,env); if (!user) return json({ error: "ആദ്യം Login ചെയ്യുക." },401);
    const { messages = [], model } = await body(request);
    if (!Array.isArray(messages) || !messages.length || messages.length > 30) return json({ error: "Chat സന്ദേശം ശരിയല്ല." },400);
    if (!env.OLLAMA_ORIGIN) return json({ error: "സ്വന്തം AI server ഇതുവരെ ബന്ധിപ്പിച്ചിട്ടില്ല. SETUP.md വായിക്കുക." },503);
    const allowed = ["qwen2.5:3b", "llama3.2:3b", "gemma2:2b"];
    const chosen = allowed.includes(model) ? model : "qwen2.5:3b";
    try {
      const upstream = await fetch(new URL("/api/chat", env.OLLAMA_ORIGIN), { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({ model:chosen, messages:messages.slice(-20), stream:false }) });
      if (!upstream.ok) return json({ error: `AI server പ്രതികരിച്ചില്ല (${upstream.status}).` },502);
      const result = await upstream.json(); return json({ reply: result.message?.content || "ഉത്തരം ലഭിച്ചില്ല.", model:chosen });
    } catch { return json({ error: "AI server-നെ ബന്ധപ്പെടാൻ കഴിഞ്ഞില്ല." },502); }
  }
  return next();
}
async function createSession(id,email,env) {
  const token = randomToken(), now = Date.now();
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await digest(token),id,now+SESSION_SECONDS*1000,now).run();
  return json({ user:{id,email} },200,{"set-cookie":cookie(token)});
}
export async function onRequest(context) {
  try { return await route(context.request, context.env, context.next); }
  catch (error) { return json({ error: "Server പിശക് സംഭവിച്ചു." }, 500); }
}
