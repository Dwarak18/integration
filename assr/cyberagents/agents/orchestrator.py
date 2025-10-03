from agents.attack_agent import AttackAgent
from agents.network_agent import NetworkAgent
from agents.investigation_agent import InvestigationAgent
from utils.logger import logger

class OrchestratorAgent:
    def __init__(self):
        logger.info("Initializing OrchestratorAgent...")
        try:
            self.attack_agent = AttackAgent()
            self.network_agent = NetworkAgent()
            self.investigation_agent = InvestigationAgent()
            logger.info("OrchestratorAgent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OrchestratorAgent: {e}")
            raise

    def process(self, api_logs: list, network_logs: list) -> str:
        """
        Process API and network logs in batches through respective agents,
        then correlate results with the investigation agent.
        """
        try:
            findings = []

            # Input validation
            if not api_logs and not network_logs:
                logger.warning("No logs provided for analysis")
                return "ERROR: No logs provided for analysis"

            if api_logs:
                if not isinstance(api_logs, list):
                    logger.error("API logs must be a list")
                    return "ERROR: API logs must be provided as a list"
                
                # Filter out empty logs
                valid_api_logs = [log for log in api_logs if log and str(log).strip()]
                if valid_api_logs:
                    combined_api_logs = "\n".join(valid_api_logs)
                    logger.info(f"Processing {len(valid_api_logs)} API logs in batch...")
                    attack_result = self.attack_agent.detect_attack(combined_api_logs)
                    findings.append(attack_result)
                else:
                    logger.warning("All API logs are empty")

            if network_logs:
                if not isinstance(network_logs, list):
                    logger.error("Network logs must be a list")
                    return "ERROR: Network logs must be provided as a list"
                
                # Filter out empty logs
                valid_network_logs = [log for log in network_logs if log and str(log).strip()]
                if valid_network_logs:
                    combined_network_logs = "\n".join(valid_network_logs)
                    logger.info(f"Processing {len(valid_network_logs)} Network logs in batch...")
                    network_result = self.network_agent.analyze_traffic(combined_network_logs)
                    findings.append(network_result)
                else:
                    logger.warning("All network logs are empty")

            if not findings:
                logger.warning("No valid findings to correlate")
                return "ERROR: No valid logs found for analysis"

            logger.info("Correlating findings with InvestigationAgent...")
            final_report = self.investigation_agent.investigate(findings)

            return final_report
            
        except Exception as e:
            logger.error(f"Error in OrchestratorAgent.process: {e}")
            return f"ERROR: Processing failed - {str(e)}"
