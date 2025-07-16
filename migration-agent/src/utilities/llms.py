""" This defines LLM related utility functions """

import requests
import logging
from global_config import *

# Suppress all warnings for cleaner output
import warnings

warnings.filterwarnings("ignore")


class LLM:
    def __init__(self):
        """Initialize LLM instance with the model ID and API headers."""
        self.headers = {
            "Authorization": self.get_api_token(),
            "Content-Type": "application/json",
        }
        self.model_id = get_model_id()

    def get_api_token(self) -> str:
        """Return the API token required for authorization."""
        return f"Bearer {llm_api_token}"

    def get_model_id(self):
        """Return the current LLM model ID."""
        return self.model_id

    def set_model_id(self, model_id: str):
        """Set the model ID for the LLM."""
        self.model_id = model_id

    def inference(self, prompt):
        payload = {
            "model": self.model_id,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0.3,
        }

        response = requests.request(
            "POST",
            llm_url,
            json=payload,
            headers=self.headers,
            verify=False,
        )
        # Successfully getting the inference response
        if response.status_code == 200:
            return response
        else:
            return None
