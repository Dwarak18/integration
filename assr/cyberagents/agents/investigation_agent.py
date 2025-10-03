import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GEMINI_API_KEY, MODEL_NAME
from utils.logger import logger
import google.generativeai as genai
from google.api_core import exceptions

class InvestigationAgent:
    def __init__(self):
        try:
            if not GEMINI_API_KEY:
                raise ValueError("GEMINI_API_KEY is not configured")
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel(MODEL_NAME)
            logger.info("InvestigationAgent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize InvestigationAgent: {e}")
            raise

    def investigate(self, findings: list) -> str:
        """Correlates findings from Attack & Network agents."""
        try:
            # Input validation
            if not findings or not isinstance(findings, list):
                logger.warning("Invalid or empty findings list provided")
                return "ERROR: Invalid input - Findings list is empty or invalid"
            
            if len(findings) == 0:
                logger.warning("Empty findings list provided")
                return "ERROR: No findings to analyze"
            
            # Filter out None or empty findings
            valid_findings = [f for f in findings if f and str(f).strip()]
            if not valid_findings:
                logger.warning("All findings are empty or invalid")
                return "ERROR: All findings are empty or invalid"
            
            logger.info(f"Investigating {len(valid_findings)} findings")
            
            prompt = f"""
            You are a cyber forensic investigator. Correlate these findings:
            {valid_findings}
            
            Tasks:
            - Identify if multiple alerts are related to one larger attack.
            - Suggest severity level (LOW, MEDIUM, HIGH, CRITICAL).
            - Recommend next steps for response.
            """
            
            response = self.model.generate_content(prompt)
            
            if not response or not response.text:
                logger.error("Empty response from Gemini API")
                return "ERROR: Failed to get analysis from AI model"
            
            logger.info("InvestigationAgent analysis complete.")
            return response.text
            
        except exceptions.ResourceExhausted:
            logger.error("API quota exceeded for InvestigationAgent")
            return "ERROR: API quota exceeded. Please try again later."
        except exceptions.InvalidArgument as e:
            logger.error(f"Invalid argument provided to API: {e}")
            return f"ERROR: Invalid request - {e}"
        except exceptions.ServiceUnavailable:
            logger.error("Gemini API service unavailable")
            return "ERROR: AI service temporarily unavailable"
        except Exception as e:
            logger.error(f"Unexpected error in InvestigationAgent: {e}")
            return f"ERROR: Investigation failed - {str(e)}"
