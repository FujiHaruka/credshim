# /// script
# requires-python = ">=3.13"
# dependencies = ["openai>=1.0"]
# ///
import openai

client = openai.OpenAI(max_retries=0)
messages = [{"role": "user", "content": "hi"}]

reply = client.chat.completions.create(model="gpt-mock", messages=messages)
print(reply.choices[0].message.content)

stream = client.chat.completions.create(model="gpt-mock", messages=messages, stream=True)
print("".join(chunk.choices[0].delta.content or "" for chunk in stream if chunk.choices))
