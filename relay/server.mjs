/**
 * Relay de vídeo — roda dentro de um job do GitHub Actions (workflow
 * relay.yml) atrás de um túnel cloudflared. Existe porque as CDNs das
 * fontes (VaPlayer/Vidlink) bloqueiam o IP de egresso do Cloudflare
 * (403/427/428) e o navegador leva 403 em segmento HLS com qualquer
 * Origin — mas o IP do runner (Azure) alcança tudo (sondado em
 * egress-probe.yml, 2026-10-01: master/media/segmento = 200).
 *
 * Não é relay aberto: cada URL carrega sig = HMAC-SHA256(url) com o
 * segredo RELAY_SIG (secret do repo; MESMO valor do SEGREDO_PROXY do
 * bundle server do app, para as URLs assinadas pelo app valerem aqui).
 * Sem sig válido → 403.
 *
 * Playlists HLS são reescritas: cada URI interna vira URL assinada
 * deste relay (filhos de master ganham fmt=hls), senão o navegador
 * buscaria o segmento direto e cairia no bloqueio de Origin.
 */

import { createServer } from "node:http";
import { webcrypto } from "node:crypto";

const PORT = Number(process.env.PORT || 8388);
const SEGREDO = process.env.RELAY_SIG || "";
const UA_NEUTRO = "Filminho/1.0 (stream-proxy)";

if (!SEGREDO) {
  console.error("RELAY_SIG ausente — nada será aceito (só /health).");
}

const subtle = webcrypto.subtle;
const enc = new TextEncoder();

async function sigDe(alvo) {
  const key = await subtle.importKey("raw", enc.encode(SEGREDO), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const buf = await subtle.sign("HMAC", key, enc.encode(alvo));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

function basePublica(req) {
  // Atrás do túnel, o Host visto é o do trycloudflare.com.
  const proto = req.headers["cf-visitor"]?.includes("https") ? "https" : (req.headers["x-forwarded-proto"] || "https");
  return `${proto}://${req.headers.host}`;
}

async function urlDoRelay(base, alvo, fmt) {
  const sig = await sigDe(alvo);
  const p = new URLSearchParams({ url: alvo, sig });
  if (fmt) p.set("fmt", fmt);
  return `${base}/proxy?${p.toString()}`;
}

function alvoSaneo(alvo) {
  try {
    const u = new URL(alvo);
    if (u.protocol !== "https:") return false;
    if (/^[\d.]+$/.test(u.hostname) || u.hostname === "localhost") return false;
    if (/(^|\.)(local|internal|home|lan|arpa|localhost)$/.test(u.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

const ehPlaylist = (url, tipo) => (tipo || "").includes("mpegurl") || /\.m3u8($|\?)/i.test(url);

async function reescreverPlaylist(texto, baseUrl, baseRelay) {
  const linhas = texto.split(/\r?\n/);
  const ehMaster = linhas.some((l) => l.startsWith("#EXT-X-STREAM-INF"));
  const out = [];
  for (const l of linhas) {
    const t = l.trim();
    if (!t || t.startsWith("#")) {
      out.push(l);
      continue;
    }
    try {
      out.push(await urlDoRelay(baseRelay, new URL(t, baseUrl).toString(), ehMaster ? "hls" : undefined));
    } catch {
      out.push(l);
    }
  }
  return out.join("\n");
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "*",
  "access-control-expose-headers": "Content-Length,Content-Range",
};

const server = createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname === "/health") {
    res.writeHead(200, { "content-type": "text/plain", "cache-control": "no-store", ...CORS });
    res.end("ok " + new Date().toISOString());
    return;
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    res.end();
    return;
  }
  if (u.pathname !== "/proxy" || req.method !== "GET") {
    res.writeHead(404, { "content-type": "text/plain", ...CORS });
    res.end("nada aqui");
    return;
  }

  const alvo = u.searchParams.get("url") || "";
  const sig = u.searchParams.get("sig") || "";
  const esperado = SEGREDO ? await sigDe(alvo) : "";
  if (!alvo.startsWith("https://") || !esperado || sig !== esperado || !alvoSaneo(alvo)) {
    res.writeHead(403, { "content-type": "text/plain", ...CORS });
    res.end("alvo não permitido");
    return;
  }

  const cabecalhos = { "user-agent": UA_NEUTRO };
  if (req.headers.range) cabecalhos.range = req.headers.range;

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 20_000);
    const upstream = await fetch(alvo, { signal: ctrl.signal, headers: cabecalhos, redirect: "follow" });
    clearTimeout(timer);

    if (!upstream.ok && upstream.status !== 206) {
      res.writeHead(502, { "content-type": "text/plain", ...CORS });
      res.end(`upstream respondeu ${upstream.status}`);
      return;
    }

    const tipo = upstream.headers.get("content-type") || "video/mp4";

    if (ehPlaylist(alvo, tipo)) {
      const texto = await upstream.text();
      const reescrito = await reescreverPlaylist(texto, alvo, basePublica(req));
      res.writeHead(200, {
        "content-type": tipo,
        "cache-control": "public, max-age=120",
        ...CORS,
      });
      res.end(reescrito);
      return;
    }

    const h = { "content-type": tipo, "cache-control": "public, max-age=300", "accept-ranges": "bytes", ...CORS };
    const cr = upstream.headers.get("content-range");
    if (cr) h["content-range"] = cr;
    const cl = upstream.headers.get("content-length");
    if (cl) h["content-length"] = cl;
    res.writeHead(upstream.status, h);
    const reader = upstream.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
    }
    res.end();
  } catch (e) {
    console.error("falha no proxy:", alvo.slice(0, 80), e?.message);
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "text/plain", ...CORS });
      res.end("upstream inacessível");
    } else {
      res.end();
    }
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`relay ouvindo em 127.0.0.1:${PORT} (segredo ${SEGREDO ? "ok" : "AUSENTE"})`);
});
