# /// script
# requires-python = ">=3.13"
# dependencies = ["openai>=1.0", "httpx[http2]"]
# ///
import sys

import openai

http2 = "--http2" in sys.argv[1:]
client = openai.OpenAI(
    max_retries=0,
    http_client=openai.DefaultHttpxClient(http2=True) if http2 else None,
)
messages = [{"role": "user", "content": "hi"}]

raw = client.chat.completions.with_raw_response.create(model="gpt-mock", messages=messages)
expected_version = "HTTP/2" if http2 else "HTTP/1.1"
if raw.http_response.http_version != expected_version:
    sys.exit(f"expected {expected_version}, got {raw.http_response.http_version}")
print(raw.parse().choices[0].message.content)

stream = client.chat.completions.create(model="gpt-mock", messages=messages, stream=True)
print("".join(chunk.choices[0].delta.content or "" for chunk in stream if chunk.choices))
