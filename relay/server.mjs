/** Relay HTTP assinado. Infraestrutura apenas — não contém código do app. */
import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { pathToFileURL } from "node:url";

const UA = "Filminho/1.0 (stream-proxy)";
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "Range, Content-Type",
  "access-control-allow-methods": "GET, OPTIONS",
  "access-control-expose-headers": "Content-Length, Content-Range, X-Relay-Started-At, X-Relay-Version",
};

export function assinar(alvo, segredo) {
  return createHmac("sha256", segredo).update(alvo).digest("hex").slice(0, 32);
}

function assinaturaValida(alvo, sig, segredo) {
  if (!segredo || !/^[a-f0-9]{32}$/.test(sig)) return false;
  return timingSafeEqual(Buffer.from(sig), Buffer.from(assinar(alvo, segredo)));
}

function alvoSaneo(alvo) {
  try {
    const u = new URL(alvo);
    return u.protocol === "https:" && !u.username && !u.password &&
      (!u.port || u.port === "443") && !/^[\d.]+$/.test(u.hostname) &&
      !u.hostname.includes(":") && u.hostname !== "localhost" &&
      !/(^|\.)(local|internal|home|lan|arpa|localhost)$/.test(u.hostname);
  } catch {
    return false;
  }
}

function ehPlaylist(url, tipo) {
  return /mpegurl/i.test(tipo || "") || /\.m3u8(?:$|\?)/i.test(url);
}

function urlDoRelay(base, alvo, segredo, fmt) {
  const hls = fmt === "hls" || ehPlaylist(alvo, "");
  // ExoPlayer antigo infere o formato pelo PATH, não pelo query string.
  const path = hls ? "/proxy/playlist.m3u8" : /\.mp4(?:$|\?)/i.test(alvo) ? "/proxy/video.mp4" : "/proxy";
  const p = new URLSearchParams({ url: alvo, sig: assinar(alvo, segredo) });
  if (hls) p.set("fmt", "hls");
  return `${base}${path}?${p}`;
}

export function reescreverPlaylist(texto, origem, base, segredo) {
  const linhas = texto.replace(/^\uFEFF/, "").split(/\r?\n/);
  let proximaEhPlaylist = false;
  return linhas.map((linha) => {
    const t = linha.trim();
    if (!t) return linha;
    if (t.startsWith("#")) {
      if (t.startsWith("#EXT-X-STREAM-INF:")) proximaEhPlaylist = true;
      // Faixas alternativas, chaves AES e init segments também precisam
      // passar pelo relay. Reescrever só linhas de URI não é suficiente.
      const hls = /^#EXT-X-(MEDIA|I-FRAME-STREAM-INF|RENDITION-REPORT):/.test(t);
      return linha.replace(/\bURI="([^"]+)"/g, (_m, uri) => {
        if (/^(data|skd):/i.test(uri)) return `URI="${uri}"`;
        return `URI="${urlDoRelay(base, new URL(uri, origem).href, segredo, hls ? "hls" : undefined)}"`;
      });
    }
    const fmt = proximaEhPlaylist ? "hls" : undefined;
    proximaEhPlaylist = false;
    return urlDoRelay(base, new URL(t, origem).href, segredo, fmt);
  }).join("\n");
}

function headersDaOrigem(alvo, range) {
  const h = { "user-agent": UA, "accept-encoding": "identity" };
  if (range) h.range = range;
  const url = new URL(alvo);
  if (url.hostname === "streamdata.vaplayer.ru") {
    h.referer = "https://nextgencloudfabric.com/";
    h.origin = "https://nextgencloudfabric.com";
  } else if (url.hostname === "vidlink.pro") {
    h.referer = "https://vidlink.pro/";
  }
  // NUNCA encaminhar o Origin/UA do navegador aos segmentos de vídeo.
  return h;
}

export function criarRelay({ segredo, buscar = fetch, iniciadoEm = Date.now() } = {}) {
  return createServer(async (req, res) => {
    const u = new URL(req.url, "http://relay.invalid");
    if (u.pathname === "/health") {
      res.writeHead(200, {
        ...CORS, "content-type": "text/plain; charset=utf-8", "cache-control": "no-store",
        "x-relay-started-at": new Date(iniciadoEm).toISOString(), "x-relay-version": "2",
      });
      res.end(`ok ${new Date().toISOString()}`);
      return;
    }
    if (req.method === "OPTIONS") {
      res.writeHead(204, CORS);
      res.end();
      return;
    }
    if (!/^\/proxy(?:\/(?:playlist\.m3u8|video\.mp4))?$/.test(u.pathname) || req.method !== "GET") {
      res.writeHead(404, { ...CORS, "content-type": "text/plain" });
      res.end("nada aqui");
      return;
    }
    const alvo = u.searchParams.get("url") || "";
    const sig = u.searchParams.get("sig") || "";
    if (!alvoSaneo(alvo) || !assinaturaValida(alvo, sig, segredo)) {
      res.writeHead(403, { ...CORS, "content-type": "text/plain" });
      res.end("alvo não permitido");
      return;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 20_000);
    const aoFechar = () => { if (!res.writableEnded) ctrl.abort(); };
    res.once("close", aoFechar);
    try {
      const upstream = await buscar(alvo, {
        signal: ctrl.signal, headers: headersDaOrigem(alvo, req.headers.range), redirect: "follow",
      });
      clearTimeout(timer);
      if (!upstream.ok) {
        await upstream.body?.cancel();
        res.writeHead(502, { ...CORS, "content-type": "text/plain", "cache-control": "no-store" });
        res.end(`upstream respondeu ${upstream.status}`);
        return;
      }
      const tipo = upstream.headers.get("content-type") || "application/octet-stream";
      const fmt = u.searchParams.get("fmt");
      // fmt=raw: inspeção server-side deve ler o ORIGINAL, para resolver as
      // URIs relativas contra a CDN correta e não assinar um relay dentro de outro.
      if (fmt !== "raw" && (fmt === "hls" || ehPlaylist(alvo, tipo))) {
        const texto = await upstream.text();
        if (!texto.replace(/^\uFEFF/, "").trimStart().startsWith("#EXTM3U")) {
          res.writeHead(502, { ...CORS, "content-type": "text/plain" });
          res.end("resposta não é playlist HLS");
          return;
        }
        const base = `https://${req.headers.host}`;
        res.writeHead(200, {
          ...CORS, "content-type": "application/vnd.apple.mpegurl", "cache-control": "public, max-age=30",
        });
        res.end(reescreverPlaylist(texto, upstream.url || alvo, base, segredo));
        return;
      }
      const h = { ...CORS, "content-type": tipo, "cache-control": fmt === "raw" ? "no-store" : "public, max-age=120", "accept-ranges": "bytes" };
      for (const nome of ["content-range", "content-length"]) {
        const valor = upstream.headers.get(nome);
        // fetch descomprime gzip/br automaticamente. O Content-Length
        // original seria o tamanho COMPRIMIDO, truncando o corpo raw.
        const descomprimido = /gzip|br|deflate/i.test(upstream.headers.get("content-encoding") || "");
        if (valor && !(nome === "content-length" && descomprimido)) h[nome] = valor;
      }
      res.writeHead(upstream.status, h);
      if (!upstream.body) { res.end(); return; }
      // pipeline respeita backpressure e cancela a leitura ao sair/seek do
      // player. Não acumular um MP4 de gigabytes em RAM depois que o cliente saiu.
      await pipeline(Readable.fromWeb(upstream.body), res);
    } catch (e) {
      if (!ctrl.signal.aborted && !res.destroyed) console.error("falha no proxy:", new URL(alvo).hostname, e?.message);
      if (!res.headersSent && !res.destroyed) {
        res.writeHead(502, { ...CORS, "content-type": "text/plain", "cache-control": "no-store" });
        res.end("upstream inacessível");
      } else if (!res.destroyed) {
        res.destroy();
      }
    } finally {
      clearTimeout(timer);
      res.off("close", aoFechar);
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const segredo = process.env.RELAY_SIG || "";
  if (!segredo) throw new Error("RELAY_SIG ausente");
  const port = Number(process.env.PORT || 8388);
  criarRelay({ segredo }).listen(port, "127.0.0.1", () => {
    console.log(`relay v2 ouvindo em 127.0.0.1:${port}`);
  });
}
