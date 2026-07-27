import express from "express";
import { randomUUID } from "crypto";
import cors from "cors";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { createMcpServer } from "./mcp.js";
import { sessions } from "./storage.js";
import { oauthRouter } from "./oauth.js";
import { requireBearer } from "./auth.js";
import { initializeJwt } from "./jwt.js";
import { sessionMiddleware } from "./session.js";
import { AuthenticatedRequest } from "./types.js";

async function main() {

  await initializeJwt();

  const app = express();
  app.use(
    cors()
  );

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(sessionMiddleware);
  app.use(oauthRouter);
  app.use(express.urlencoded({
    extended: true,
  }));



  app.all("/mcp", requireBearer, async (req: AuthenticatedRequest, res) => {
    try {
      const sessionId = req.header("mcp-session-id");
      
      let transport: StreamableHTTPServerTransport;

      console.log(`AuthenticatedRequest: ${JSON.stringify(req)}`);

      console.log(`Logged In User: ${req.user?.username}`)

      if (sessionId && sessions.has(sessionId)) {
        transport = sessions.get(sessionId)!.transport;
      } else {
        const server = createMcpServer(req.user);

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
        });

        await server.connect(transport);

        transport.onclose = async () => {
          if (transport.sessionId) {
            sessions.delete(transport.sessionId);
          }

          await server.close();
        };

        if (req.method === "POST") {
          await transport.handleRequest(req, res, req.body);

          if (transport.sessionId) {
            sessions.set(transport.sessionId, {
              transport,
            });
          }

          return;
        }

        return res.sendStatus(405);
      }

      await transport.handleRequest(
        req,
        res,
        req.method === "POST" ? req.body : undefined
      );
    } catch (err) {
      console.error(err);

      if (!res.headersSent) {
        res.status(500).json({
          error: err instanceof Error ? err.message : "Unknown Error",
        });
      }
    }
  });
  app.listen(3000, () => {
    console.log("🚀 MCP Server running");
    console.log("http://localhost:3000/mcp");
  });
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});