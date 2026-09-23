"""Debug: call Gemini directly, no timeout, no wrapper. Run from backend folder."""
import os
import time

from dotenv import load_dotenv
from google import genai

load_dotenv()
print("Using model:", os.getenv("LLM_MODEL"))
client = genai.Client(api_key=os.getenv("LLM_API_KEY"))

start = time.time()
response = client.models.generate_content(
    model=os.getenv("LLM_MODEL"),
    contents="Say hello in 3 words.",
)
print("Reply:", response.text)
print(f"Took {time.time() - start:.1f} seconds")