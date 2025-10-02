import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GEMINI_API_KEY, MODEL_NAME
from utils.logger import logger
import google.generativeai as genai
from google.api_core import exceptions

class NetworkAgent:
    def __init__(self):
        try:
            if not GEMINI_API_KEY:
                raise ValueError("GEMINI_API_KEY is not configured")
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel(MODEL_NAME)
            logger.info("NetworkAgent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize NetworkAgent: {e}")
            raise

    def analyze_traffic(self, network_log: str) -> str:
        """Detects suspicious network activity."""
        try:
            # Input validation
            if not network_log or not isinstance(network_log, str):
                logger.warning("Invalid or empty network log provided")
                return "ERROR: Invalid input - Network log is empty or invalid"
            
            if len(network_log.strip()) == 0:
                logger.warning("Empty network log after stripping whitespace")
                return "ERROR: Empty network log provided"
            
            logger.info(f"Analyzing network log: {network_log[:100]}...")
            
            prompt = f"""
            You are a network security agent. Analyze the following network traffic log:
            {network_log}
            
            Look for:
            - Port scans
            - DDoS attempts
            - Suspicious IPs
            - DNS tunneling
            Provide a verdict: NORMAL or THREAT, with reasoning.
            """
            
            response = self.model.generate_content(prompt)
            
            if not response or not response.text:
                logger.error("Empty response from Gemini API")
                return "ERROR: Failed to get analysis from AI model"
            
            logger.info("NetworkAgent analysis complete.")
            return response.text
            
        except exceptions.ResourceExhausted:
            logger.error("API quota exceeded for NetworkAgent")
            return "ERROR: API quota exceeded. Please try again later."
        except exceptions.InvalidArgument as e:
            logger.error(f"Invalid argument provided to API: {e}")
            return f"ERROR: Invalid request - {e}"
        except exceptions.ServiceUnavailable:
            logger.error("Gemini API service unavailable")
            return "ERROR: AI service temporarily unavailable"
        except Exception as e:
            logger.error(f"Unexpected error in NetworkAgent: {e}")
            return f"ERROR: Analysis failed - {str(e)}"
