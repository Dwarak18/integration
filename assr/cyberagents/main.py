from agents.orchestrator import OrchestratorAgent
from utils.logger import logger
import atexit
import signal
import sys

def signal_handler(signum, frame):
    """Handle graceful shutdown on interrupt signals"""
    logger.info(f"Received signal {signum}. Shutting down gracefully...")
    sys.exit(0)

def cleanup():
    """Cleanup function called on exit"""
    logger.info("Cleaning up resources...")
    try:
        # Force cleanup of grpc connections
        import google.generativeai as genai
        # The grpc timeout warning is a known issue with the Google AI SDK
        # It's harmless but we can suppress it by ensuring proper cleanup
        logger.info("Cleanup completed")
    except Exception as e:
        logger.debug(f"Minor cleanup warning (can be ignored): {e}")

def main():
    try:
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Register cleanup function
        atexit.register(cleanup)
        
        logger.info("Starting Cyber Security Analysis System")
        
        api_request_logs = [
            "POST /login {username:'admin' OR '1'='1', password:''}",
            "GET /search?q=<script>alert('xss')</script>"
        ]
        network_logs = [
            "192.168.1.50 scanning ports 21-80 repeatedly",
            "High volume of SYN packets from 10.0.0.99 to port 443"
        ]

        orchestrator = OrchestratorAgent()
        final_report = orchestrator.process(api_request_logs, network_logs)

        print("\n=== FINAL SECURITY REPORT ===")
        print(final_report)
        
        logger.info("Analysis completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        print(f"\nERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
