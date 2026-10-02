import readline from "node:readline";

const endpoint = "https://openrouter.ai/api/v1/chat/completions";
const defaultModel = "nex-agi/nex-n2.5-pro:free";

function send(message) {
    process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function askOpenRouter({ question, model = defaultModel }) {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
        throw new Error("OPENROUTER_API_KEY is not set");
    }

    const response = await fetch(endpoint, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            model,
            messages: [{ role: "user", content: question }],
            stream: true,
            provider: {
                only: ["nex-agi/fp8"],
                allow_fallbacks: false,
            },
        }),
    });

    if (!response.ok) {
        throw new Error(`OpenRouter returned ${response.status}: ${await response.text()}`);
    }

    let answer = "";
    let usage;
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    for (; ;) {
        const { done, value } = await reader.read();
        buffer += decoder.decode(value ?? new Uint8Array(), { stream: !done });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const payload = line.slice(6).trim();
            if (payload === "[DONE]") continue;

            const chunk = JSON.parse(payload);
            answer += chunk.choices?.[0]?.delta?.content ?? "";
            usage = chunk.usage ?? usage;
        }

        if (done) break;
    }

    return { answer, reasoningTokens: usage?.completion_tokens_details?.reasoning_tokens };
}

async function handle(request) {
    if (request.method === "initialize") {
        return {
            protocolVersion: request.params?.protocolVersion ?? "2024-11-05",
            capabilities: { tools: {} },
            serverInfo: { name: "openrouter-agent", version: "1.0.0" },
        };
    }

    if (request.method === "notifications/initialized") return null;

    if (request.method === "tools/list") {
        return {
            tools: [
                {
                    name: "ask_openrouter",
                    description: "Ask the configured OpenRouter model a question.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            question: { type: "string", description: "The question to ask." },
                            model: { type: "string", description: "Optional OpenRouter model override." },
                        },
                        required: ["question"],
                    },
                },
            ],
        };
    }

    if (request.method === "tools/call") {
        if (request.params?.name !== "ask_openrouter") {
            throw new Error(`Unknown tool: ${request.params?.name}`);
        }

        const result = await askOpenRouter(request.params.arguments ?? {});
        const usage = result.reasoningTokens == null
            ? "Reasoning tokens: unavailable"
            : `Reasoning tokens: ${result.reasoningTokens}`;
        return {
            content: [{ type: "text", text: `${result.answer}\n\n${usage}` }],
        };
    }

    throw new Error(`Unsupported method: ${request.method}`);
}

const input = readline.createInterface({ input: process.stdin });
input.on("line", async (line) => {
    if (!line.trim()) return;
    let request;
    try {
        request = JSON.parse(line);
        if (request.method?.startsWith("notifications/")) {
            await handle(request);
            return;
        }
        const result = await handle(request);
        send({ jsonrpc: "2.0", id: request.id, result });
    } catch (error) {
        send({
            jsonrpc: "2.0",
            id: request?.id ?? null,
            error: { code: -32603, message: error instanceof Error ? error.message : String(error) },
        });
    }
});