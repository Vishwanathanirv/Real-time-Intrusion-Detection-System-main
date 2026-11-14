import { buildApp } from "./app";

const port = Number(process.env.PORT ?? 8080);
const { app, live } = await buildApp({ logger: process.env.LOG_LEVEL !== "silent", autopilot: process.env.AUTOPILOT !== "off" });
await app.listen({ port, host: process.env.HOST ?? "0.0.0.0" });
app.log.info(`PacketEye running in ${live.state.mode} mode`);

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, async () => {
    await app.close();
    process.exit(0);
  });
}
