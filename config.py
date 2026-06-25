import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen3:14b")
NUM_CTX = int(os.getenv("NUM_CTX", "32768"))
NUM_PREDICT = int(os.getenv("NUM_PREDICT", "4096"))
MAX_TOOL_TURNS = int(os.getenv("MAX_TOOL_TURNS", "5"))

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def load_system_prompt() -> str:
    return (_PROMPTS_DIR / "phase2_system.txt").read_text(encoding="utf-8")
