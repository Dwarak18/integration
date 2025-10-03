import os
from dotenv import load_dotenv
import logging

# Configure logging for config module
logging.basicConfig(level=logging.INFO)
config_logger = logging.getLogger("Config")

load_dotenv()  # loads .env file

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = "gemini-1.5-flash"

# Validation
if not GEMINI_API_KEY:
    config_logger.error("GEMINI_API_KEY not found in environment variables")
    raise ValueError("GEMINI_API_KEY must be set in .env file")

if len(GEMINI_API_KEY.strip()) < 10:  # Basic sanity check
    config_logger.error("GEMINI_API_KEY appears to be invalid (too short)")
    raise ValueError("GEMINI_API_KEY appears to be invalid")

config_logger.info(f"Configuration loaded successfully. Model: {MODEL_NAME}")
