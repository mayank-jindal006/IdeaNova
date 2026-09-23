"""Manual check: does our key + model + llm.py actually work? Run from the backend folder."""
import time

from app.ai.llm import complete_json

start = time.time()
result = complete_json(
    system="You are a security assistant. Reply only with a JSON object.",
    user='In one sentence, why is hardcoding an API key in source code dangerous? '
         'Return exactly: {"answer": "<your sentence>"}',
)
print("Reply:", result)
print(f"Took {time.time() - start:.1f} seconds")