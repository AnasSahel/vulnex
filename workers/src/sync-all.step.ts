import type { StepConfig, Handlers } from "motia";

export const config = {
  name: "sync-all",
  description: "Orchestrates all vulnerability data sync jobs",
  triggers: [
    { type: "cron", expression: "0 0 */6 * * *" },
    { type: "http", path: "/api/sync", method: "POST" },
  ],
  enqueues: [
    "sync.nvd",
    "sync.epss",
    "sync.kev",
    "sync.ghsa",
    "sync.exploits",
  ],
  flows: ["vulnerability-sync"],
} as const satisfies StepConfig;

export const handler: Handlers<typeof config> = async (input, { enqueue, logger, traceId, is }) => {
  logger.info("Starting vulnerability data sync", { traceId });

  const sources = ["sync.nvd", "sync.epss", "sync.kev", "sync.ghsa", "sync.exploits"] as const;

  for (const topic of sources) {
    await enqueue({ topic, data: { triggeredBy: traceId } });
    logger.info(`Enqueued ${topic}`);
  }

  if (is.http(input)) {
    return {
      status: 200,
      body: { message: "Sync triggered", traceId },
    };
  }
};
