import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

const PAGE = Buffer.from(`<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src ipc: http://ipc.localhost; style-src 'unsafe-inline'">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SSDEV Windows business page probe</title>
    <style>body { font: 16px system-ui; margin: 2rem; }</style>
  </head>
  <body><main>SSDEV Windows business page probe</main></body>
</html>`, "utf8");

export function createBusinessPageProbeServer() {
  const server = createServer((request, response) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, {
        Allow: "GET, HEAD",
        "Cache-Control": "no-store",
      });
      response.end();
      return;
    }
    if (request.url !== "/") {
      response.writeHead(404, { "Cache-Control": "no-store" });
      response.end();
      return;
    }
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Length": PAGE.length,
      "Content-Type": "text/html; charset=utf-8",
      "X-SSDEV-Business-Probe": "1",
    });
    response.end(request.method === "HEAD" ? undefined : PAGE);
  });
  server.on("clientError", (_error, socket) => socket.destroy());
  return server;
}

function readPort(arguments_) {
  if (arguments_.length !== 2 || arguments_[0] !== "--port") {
    throw new Error("usage: node business-page-probe-server.mjs --port <1024-65535>");
  }
  const port = Number(arguments_[1]);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw new Error("probe port must be an integer from 1024 through 65535");
  }
  return port;
}

async function main() {
  const port = readPort(process.argv.slice(2));
  const server = createBusinessPageProbeServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
