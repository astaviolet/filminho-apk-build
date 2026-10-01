import test from "node:test";
import assert from "node:assert/strict";
import { criarRelay, assinar, reescreverPlaylist } from "./server.mjs";

const segredo = "segredo-apenas-do-teste";
const origem = "https://cdn.example.org/movie/master.m3u8";
const base = "https://test.trycloudflare.com";
const master = '#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="a",URI="audio/index.m3u8"\n#EXT-X-STREAM-INF:BANDWIDTH=4000000,RESOLUTION=1920x1080\n1080/index.m3u8';

async function comServer(buscar, executar) {
  const server = criarRelay({ segredo, buscar });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  const prox = (alvo, path = "/proxy", fmt) => `${url}${path}?${new URLSearchParams({ url: alvo, sig: assinar(alvo, segredo), ...(fmt ? { fmt } : {}) })}`;
  try { await executar({ url, prox }); }
  finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
}

test("reescreve variantes, áudio, AES, init segment e URLs relativas", () => {
  const rewrite = reescreverPlaylist(master, origem, base, segredo);
  assert.match(rewrite, /URI="https:\/\/test.trycloudflare.com\/proxy\/playlist.m3u8\?/);
  const child = new URL(rewrite.split("\n").at(-1));
  assert.equal(child.pathname, "/proxy/playlist.m3u8");
  assert.equal(child.searchParams.get("url"), "https://cdn.example.org/movie/1080/index.m3u8");
  assert.equal(child.searchParams.get("fmt"), "hls");
  const media = '#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI="../key.bin"\n#EXT-X-MAP:URI="init.mp4"\n#EXTINF:5,\nseg.html';
  const resultado = reescreverPlaylist(media, "https://cdn.example.org/movie/1080/index.m3u8", base, segredo);
  const uris = [...resultado.matchAll(/URI="([^"]+)"/g)].map((m) => new URL(m[1]).searchParams.get("url"));
  assert.deepEqual(uris, ["https://cdn.example.org/movie/key.bin", "https://cdn.example.org/movie/1080/init.mp4"]);
  assert.equal(new URL(resultado.split("\n").at(-1)).searchParams.get("url"), "https://cdn.example.org/movie/1080/seg.html");
});

test("health informa versão/início; assinatura ruim e alvos privados são negados", async () => {
  await comServer(() => { throw new Error("não deveria buscar"); }, async ({ url, prox }) => {
    const health = await fetch(`${url}/health`);
    assert.equal(health.status, 200);
    assert.match(await health.text(), /^ok /);
    assert.equal(health.headers.get("x-relay-version"), "2");
    assert.ok(Date.parse(health.headers.get("x-relay-started-at")));
    const bad = await fetch(prox(origem).replace(/sig=[a-f0-9]+/, "sig=" + "0".repeat(32)));
    assert.equal(bad.status, 403);
    assert.equal((await fetch(prox("https://127.0.0.1/"))).status, 403);
    assert.equal((await fetch(prox("https://[::1]/"))).status, 403);
    assert.equal((await fetch(prox("https://localhost/"))).status, 403);
  });
});

test("fmt=raw mantém playlist original; path .m3u8 funciona no ExoPlayer antigo", async () => {
  await comServer(async () => new Response(master, { headers: { "content-type": "text/html" } }), async ({ prox }) => {
    const raw = await fetch(prox(origem, "/proxy/playlist.m3u8", "raw"));
    assert.equal(raw.status, 200);
    assert.equal(await raw.text(), master);
    const hls = await fetch(prox(origem, "/proxy/playlist.m3u8", "hls"));
    assert.equal(hls.status, 200);
    assert.equal(hls.headers.get("content-type"), "application/vnd.apple.mpegurl");
    assert.match(await hls.text(), /proxy\/playlist.m3u8/);
  });
});

test("MP4 encaminha Range, não encaminha Origin/UA do navegador e libera CORS", async () => {
  const bytes = Uint8Array.of(0, 0, 0, 8, 102, 116, 121, 112);
  await comServer(async (_alvo, options) => {
    assert.equal(options.headers.range, "bytes=0-7");
    assert.equal(options.headers.origin, undefined);
    assert.equal(options.headers["user-agent"], "Filminho/1.0 (stream-proxy)");
    return new Response(bytes, { status: 206, headers: { "content-type": "video/mp4", "content-range": "bytes 0-7/1000000", "content-length": "8" } });
  }, async ({ prox }) => {
    const r = await fetch(prox("https://cdn.example.org/video.mp4", "/proxy/video.mp4"), { headers: { range: "bytes=0-7", origin: "https://app.example.org", "user-agent": "Chrome" } });
    assert.equal(r.status, 206);
    assert.equal(r.headers.get("access-control-allow-origin"), "*");
    assert.equal(r.headers.get("content-range"), "bytes 0-7/1000000");
    assert.deepEqual(new Uint8Array(await r.arrayBuffer()), bytes);
  });
});

test("API recebe o referer próprio; vídeo nunca recebe Origin", async () => {
  await comServer(async (alvo, options) => {
    if (alvo.includes("streamdata.vaplayer.ru")) {
      assert.equal(options.headers.origin, "https://nextgencloudfabric.com");
      assert.equal(options.headers.referer, "https://nextgencloudfabric.com/");
    } else assert.equal(options.headers.origin, undefined);
    return new Response('{"ok":true}', { headers: { "content-type": "application/json" } });
  }, async ({ prox }) => {
    assert.equal((await fetch(prox("https://streamdata.vaplayer.ru/api.php?imdb=tt1234567", "/proxy", "raw"))).status, 200);
    assert.equal((await fetch(prox("https://cdn.example.org/seg.ts"))).status, 200);
  });
});

test("falha upstream é 502 com CORS e não fica cacheada", async () => {
  await comServer(async () => new Response("bloqueado", { status: 403 }), async ({ prox }) => {
    const r = await fetch(prox(origem));
    assert.equal(r.status, 502);
    assert.equal(r.headers.get("cache-control"), "no-store");
    assert.equal(r.headers.get("access-control-allow-origin"), "*");
  });
});
