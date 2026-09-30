import OpenAI from "openai";

const client = new OpenAI({ maxRetries: 0 });
const messages = [{ role: "user", content: "hi" }];

const reply = await client.chat.completions.create({ model: "gpt-mock", messages });
console.log(reply.choices[0].message.content);

const stream = await client.chat.completions.create({ model: "gpt-mock", messages, stream: true });
let text = "";
for await (const chunk of stream) {
  text += chunk.choices[0]?.delta?.content ?? "";
}
console.log(text);
