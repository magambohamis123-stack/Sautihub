const COOKIE_NAME = "sautihub_session";
const MAX_AUDIO_SIZE = 25 * 1024 * 1024;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers
    }
  });
}

function randomId() {
  return crypto.randomUUID();
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  return new Uint8Array(
    hex.match(/.{1,2}/g).map(x => parseInt(x, 16))
  );
}

function base64url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 150000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return bytesToHex(result);
}

async function signToken(user, secret) {
  const payload = {
    id: user.id,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  };

  const data = base64url(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return data + "." + base64url(signature);
}

async function verifyToken(token, secret) {
  try {
    const [data, signature] = token.split(".");
    if (!data || !signature) return null;

    const decode = value => {
      const normalized = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      return Uint8Array.from(
        atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)),
        c => c.charCodeAt(0)
      );
    };

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      decode(signature),
      new TextEncoder().encode(data)
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(decode(data))
    );

    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function cookie(token, maxAge = 604800) {
  return ${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge};
}

function getCookie(request) {
  const value = request.headers.get("Cookie") || "";
  const item = value.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(COOKIE_NAME + "="));

  return item
    ? item.substring(COOKIE_NAME.length + 1)
    : null;
}

async function getUser(request, env) {
  const token = getCookie(request);
  if (!token) return null;

  const payload = await verifyToken(token, env.JWT_SECRET);
  if (!payload) return null;

  return await env.DB.prepare(
    "SELECT id, name, email FROM users WHERE id = ?"
  ).bind(payload.id).first();
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email
  };
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!env.DB || !env.AUDIO || !env.JWT_SECRET) {
    return json({
      error: "Database, storage au JWT_SECRET bado hazijaunganishwa."
    }, 503);
  }

  if (path === "/api/health" && method === "GET") {
    return json({ status: "SAUTI HUB API iko tayari." });
  }

  if (path === "/api/register" && method === "POST") {
    const body = await request.json();
    const name = String(body.name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (!name || !email || password.length < 8) {
      return json({
        error: "Jaza jina, email na password yenye angalau herufi 8."
      }, 400);
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return json({ error: "Email si sahihi." }, 400);
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(email).first();

    if (existing) {
      return json({ error: "Email hii tayari imesajiliwa." }, 409);
    }

    const id = randomId();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await passwordHash(password, salt);

    await env.DB.prepare(
      `INSERT INTO users
      (id, name, email, password_hash, salt, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      id, name, email, hash, bytesToHex(salt),
      new Date().toISOString()
    ).run();

    const token = await signToken({ id }, env.JWT_SECRET);

    return json(
      { message: "Usajili umefanikiwa.", user: { id, name, email } },
      201,
      { "Set-Cookie": cookie(token) }
    );
  }

  if (path === "/api/login" && method === "POST") {
    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).bind(email).first();

    if (!user) {
      return json({ error: "Email au password si sahihi." }, 401);
    }

    const hash = await passwordHash(
      password,
      hexToBytes(user.salt)
    );

    if (hash !== user.password_hash) {
      return json({ error: "Email au password si sahihi." }, 401);
    }

    const token = await signToken(user, env.JWT_SECRET);

    return json(
      { message: "Umeingia vizuri.", user: safeUser(user) },
      200,
      { "Set-Cookie": cookie(token) }
    );
  }

  if (path === "/api/logout" && method === "POST") {
    return json(
      { message: "Umetoka kwenye akaunti." },
      200,
      { "Set-Cookie": cookie("", 0) }
    );
  }

  if (path === "/api/me" && method === "GET") {
    const user = await getUser(request, env);
    if (!user) {
      return json({ error: "Hujaingia kwenye akaunti." }, 401);
    }
    return json({ user: safeUser(user) });
  }

  if (path === "/api/shows" && method === "GET") {
    const result = await env.DB.prepare(
      `SELECT id, title, description, category, created_at
       FROM shows ORDER BY created_at DESC`
    ).all();

    return json({ shows: result.results || [] });
  }

  if (path === "/api/mine" && method === "GET") {
    const user = await getUser(request, env);
    if (!user) return json({ error: "Ingia kwanza." }, 401);

    const result = await env.DB.prepare(
      `SELECT id, title, description, category, created_at
       FROM shows WHERE owner_id = ? ORDER BY created_at DESC`
    ).bind(user.id).all();

    return json({ shows: result.results || [] });
  }

  if (path === "/api/upload" && method === "POST") {
    const user = await getUser(request, env);
    if (!user) return json({ error: "Ingia kwanza." }, 401);

    const form = await request.formData();
    const file = form.get("audio");
    const title = String(form.get("title") || "").trim();
    const description = String(form.get("description") || "").trim();
    const category = String(form.get("category") || "Tamthilia").trim();

    if (!title || !file || typeof file.arrayBuffer !== "function") {
      return json({
        error: "Weka jina la kazi na faili la sauti."
      }, 400);
    }

    if (file.size > MAX_AUDIO_SIZE) {
      return json({ error: "Faili limezidi MB 25." }, 413);
    }

    const allowed = [
      "audio/mpeg", "audio/mp3", "audio/wav",
      "audio/mp4", "audio/aac", "audio/ogg",
      "audio/webm"
    ];

    if (!allowed.includes(file.type)) {
      return json({
        error: "Aina hii ya faili la sauti hairuhusiwi."
      }, 400);
    }

    const id = randomId();
    const key = audio/${id};

    await env.AUDIO.put(key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });

    try {
      await env.DB.prepare(
        `INSERT INTO shows
        (id, title, description, category, filename,
         content_type, r2_key, owner_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        id, title, description, category,
        file.name || "audio", file.type, key,
        user.id, new Date().toISOString()
      ).run();
    } catch (error) {
      await env.AUDIO.delete(key);
      throw error;
    }

    return json({ message: "Kazi imepakiwa.", id }, 201);
  }

  if (path.startsWith("/api/audio/") && method === "GET") {
    const id = path.split("/").pop();

    const show = await env.DB.prepare(
      "SELECT r2_key, content_type FROM shows WHERE id = ?"
    ).bind(id).first();

    if (!show) {
      return json({ error: "Sauti haijapatikana." }, 404);
    }

    const object = await env.AUDIO.get(show.r2_key);
    if (!object) {
      return json({ error: "Faili la sauti halijapatikana." }, 404);
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("Content-Type", show.content_type || "audio/mpeg");
    headers.set("Cache-Control", "public, max-age=3600");

    return new Response(object.body, { headers });
  }

  if (path.startsWith("/api/delete/") && method === "DELETE") {
    const user = await getUser(request, env);
    if (!user) return json({ error: "Ingia kwanza." }, 401);

    const id = path.split("/").pop();

    const show = await env.DB.prepare(
      "SELECT r2_key FROM shows WHERE id = ? AND owner_id = ?"
    ).bind(id, user.id).first();

    if (!show) {
      return json({ error: "Kazi haijapatikana." }, 404);
    }

    await env.AUDIO.delete(show.r2_key);

    await env.DB.prepare(
      "DELETE FROM shows WHERE id = ? AND owner_id = ?"
    ).bind(id, user.id).run();

    return json({ message: "Kazi imefutwa." });
  }

  return json({ error: "Ukurasa haujapatikana." }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      console.error(error);
      return json({
        error: "Hitilafu imetokea. Jaribu tena."
      }, 500);
    }
  }
};
