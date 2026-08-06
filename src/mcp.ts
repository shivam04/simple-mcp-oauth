import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAppResource, registerAppTool, RESOURCE_MIME_TYPE } from "@modelcontextprotocol/ext-apps/server";
import type { CallToolResult, ReadResourceResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import fs from "node:fs/promises";
import path from "node:path";
import { AuthenticatedUser } from "./types";

const APP_RESOURCE_URI = "ui://hello-user/mcp-app.html";
const APP_HTML_PATH = path.join(__dirname, "..", "app", "dist", "mcp-app.html");

export function createMcpServer(user?: AuthenticatedUser) {
  const server = new McpServer({
    name: "simple-mcp",
    version: "1.0.0",
  });

  server.registerTool(
    "whoami",
    {
      title: "Who Am I",
      description: "Returns the authenticated user",
      inputSchema: {},
    },
    async () => ({
      content: [
        {
          type: "text",
          text: user ? `Hello ${user.username}` : "Anonymous",
        }
      ],
    })
  )

  server.registerTool(
    "hello",
    {
      title: "Hello Tool",
      description: "Returns a greeting",
      inputSchema: {
        name: z.string(),
      },
    },
    async ({ name }) => {
      return {
        content: [
          {
            type: "text",
            text: `Hello ${name}!`,
          },
        ],
      };
    }
  );

  // MCP App: tool + resource pair. The tool returns the greeting, and the
  // resource serves the bundled HTML UI that displays it (see app/).
  //
  // NOTE: `@modelcontextprotocol/ext-apps` is ESM-only while this project is
  // CommonJS. TypeScript resolves the SDK's `McpServer` type differently
  // depending on which package imports it, producing two structurally
  // incompatible declarations of the same runtime class (a dual-package
  // hazard). The cast below is safe at runtime; both sides load the same
  // `@modelcontextprotocol/sdk` instance.
  registerAppTool(
    server as unknown as Parameters<typeof registerAppTool>[0],
    "hello-user",
    {
      title: "Hello User",
      description: "Says hello to the authenticated user",
      inputSchema: {},
      outputSchema: z.object({
        greeting: z.string(),
      }),
      _meta: { ui: { resourceUri: APP_RESOURCE_URI } },
    },
    async (): Promise<CallToolResult> => {
      const greeting = user ? `Hello ${user.username}!` : "Hello, anonymous!";

      return {
        content: [{ type: "text", text: greeting }],
        structuredContent: { greeting },
      };
    }
  );

  registerAppResource(
    server as unknown as Parameters<typeof registerAppResource>[0],
    "Hello User View",
    APP_RESOURCE_URI,
    { mimeType: RESOURCE_MIME_TYPE },
    async (): Promise<ReadResourceResult> => {
      const html = await fs.readFile(APP_HTML_PATH, "utf-8");

      return {
        contents: [
          { uri: APP_RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html },
        ],
      };
    }
  );

  return server;
}