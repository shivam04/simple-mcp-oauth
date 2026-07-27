import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { AuthenticatedUser } from "./types";

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

  return server;
}