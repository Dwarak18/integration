import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GEMINI_API_KEY, MODEL_NAME
from utils.logger import logger
import google.generativeai as genai
from google.api_core import exceptions

class AttackAgent:
    def __init__(self):
        try:
            if not GEMINI_API_KEY:
                raise ValueError("GEMINI_API_KEY is not configured")
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel(MODEL_NAME)
            logger.info("AttackAgent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AttackAgent: {e}")
            raise

    def detect_attack(self, api_request: str) -> str:
        """Analyzes an API request log and detects possible attacks."""
        try:
            # Input validation
            if not api_request or not isinstance(api_request, str):
                logger.warning("Invalid or empty API request provided")
                return "ERROR: Invalid input - API request is empty or invalid"
            
            if len(api_request.strip()) == 0:
                logger.warning("Empty API request after stripping whitespace")
                return "ERROR: Empty API request provided"
            
            logger.info(f"Analyzing API request: {api_request[:100]}...")
            
            prompt = f"""
            You are a cybersecurity agent. Analyze the following API request:
            {api_request}
            
            Check for:
            - SQL injection
            - XSS
            - Command Injection
            - Malicious payloads
            Provide a verdict: SAFE or ATTACK, with reasoning.
            """
            
            response = self.model.generate_content(prompt)
            
            if not response or not response.text:
                logger.error("Empty response from Gemini API")
                return "ERROR: Failed to get analysis from AI model"
            
            logger.info("AttackAgent analysis complete.")
            return response.text
            
        except exceptions.ResourceExhausted:
            logger.error("API quota exceeded for AttackAgent")
            return "ERROR: API quota exceeded. Please try again later."
        except exceptions.InvalidArgument as e:
            logger.error(f"Invalid argument provided to API: {e}")
            return f"ERROR: Invalid request - {e}"
        except exceptions.ServiceUnavailable:
            logger.error("Gemini API service unavailable")
            return "ERROR: AI service temporarily unavailable"
        except Exception as e:
            logger.error(f"Unexpected error in AttackAgent: {e}")
            return f"ERROR: Analysis failed - {str(e)}"
