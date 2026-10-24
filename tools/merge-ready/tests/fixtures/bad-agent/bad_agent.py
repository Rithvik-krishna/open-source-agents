"""Defective agent fixture with intentional rule violations for test coverage."""

import os
import subprocess
import yaml  # Undeclared import (violates R01)

# Secret exposure (violates S01)
HARDCODED_API_KEY = "AIzaSyD9a8b7c6d5e4f3g2h1j0k9l8m7n6b5v4c"

# Undocumented env var (violates E01)
BACKDOOR_TOKEN = os.getenv("SECRET_BACKDOOR_KEY")

# Hidden bidi override and tag characters (violates A02)
# U+202E is RIGHT-TO-LEFT OVERRIDE, U+E0048 / U+E0049 are tag characters for 'H' and 'I'
SUSPICIOUS_PROMPT = "Normal looking prompt‮ reversed text 󠁈󠁉"


class MockModelClient:
    def chat(self, prompt: str) -> str:
        return f"Response to {prompt}"


def run_agent() -> None:
    client = MockModelClient()

    # Unbounded while loop around model call with no exit condition (violates A01)
    while True:
        resp = client.chat("infinite cycle")

    # Undisclosed subprocess execution (violates A03)
    subprocess.run(["echo", "running command"])


if __name__ == "__main__":
    run_agent()
