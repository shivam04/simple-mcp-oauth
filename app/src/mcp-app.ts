/**
 * Client-side script for the "hello" MCP App.
 * Calls the `hello-user` tool and renders the greeting it returns.
 */
import { App, type McpUiHostContext, applyDocumentTheme } from "@modelcontextprotocol/ext-apps";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

const greetingEl = document.getElementById("greeting")!;

function extractGreeting(result: CallToolResult): string {
  const { greeting } = (result.structuredContent as { greeting?: string }) ?? {};
  return greeting ?? "[ERROR]";
}

function handleHostContextChanged(ctx: McpUiHostContext) {
  if (ctx.theme) {
    applyDocumentTheme(ctx.theme);
  }
}

// 1. Create the app instance.
const app = new App({ name: "Hello App", version: "1.0.0" });

// 2. Register handlers BEFORE connecting.
app.ontoolresult = (result) => {
  greetingEl.textContent = extractGreeting(result);
};

app.onerror = console.error;

app.onhostcontextchanged = handleHostContextChanged;

// 3. Connect to the host, then trigger the initial tool call.
app.connect().then(async () => {
  const ctx = app.getHostContext();
  if (ctx) {
    handleHostContextChanged(ctx);
  }

  try {
    const result = await app.callServerTool({ name: "hello-user", arguments: {} });
    greetingEl.textContent = extractGreeting(result);
  } catch (e) {
    console.error(e);
    greetingEl.textContent = "[ERROR]";
  }
});
