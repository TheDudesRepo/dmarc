import { createScannerServer } from "./server.mjs";

const port = Number.parseInt(process.env.PORT ?? "8080", 10);
if (!Number.isInteger(port) || port < 1_024 || port > 65_535) {
  throw new Error("PORT must be an unprivileged TCP port");
}

const server = createScannerServer();
server.listen(port, "0.0.0.0");

const shutdown = () => server.close(() => process.exit(0));
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
