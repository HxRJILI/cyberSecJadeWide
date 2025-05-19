package agents;

import jade.core.Agent;
import jade.core.behaviours.CyclicBehaviour;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ResponseAgent extends Agent {
    private static final Logger logger = Logger.getLogger(ResponseAgent.class.getName());
    
    private ExecutorService executorService;
    private EmailSender emailSender;
    private FirewallManager firewallManager;
    private SiemLogger siemLogger;

    @Override
    protected void setup() {
        logger.info("ResponseAgent " + getLocalName() + " is starting up");
        
        // Register this agent as a response service
        Utils.registerService(this, Utils.cfg.jade.services.respond);
        
        // Initialize executor service for async response actions
        executorService = Executors.newFixedThreadPool(3);
        
        // Initialize response modules
        emailSender = new EmailSender(Utils.cfg.response.email);
        firewallManager = new FirewallManager(Utils.cfg.response.firewall);
        siemLogger = new SiemLogger(Utils.cfg.response.siem);
        
        // Add alert handler behaviour
        addBehaviour(new AlertHandlerBehaviour());
        
        logger.info("ResponseAgent initialized successfully");
    }

    @Override
    protected void takeDown() {
        logger.info("ResponseAgent " + getLocalName() + " is shutting down");
        
        // Shutdown executor service
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
        
        // Close SIEM logger
        if (siemLogger != null) {
            siemLogger.close();
        }
    }

    /**
     * Behaviour for handling anomaly alerts
     */
    private class AlertHandlerBehaviour extends CyclicBehaviour {
        @Override
        public void action() {
            // Wait for incoming anomaly alerts
            MessageTemplate template = MessageTemplate.MatchPerformative(ACLMessage.REQUEST);
            ACLMessage msg = receive(template);
            
            if (msg != null) {
                try {
                    // Parse the anomaly from the message content
                    Anomaly anomaly = Utils.parseMessage(msg.getContent(), Anomaly.class);
                    
                    if (anomaly != null) {
                        logger.info("Received anomaly alert: " + anomaly);
                        
                        // Send acknowledgment
                        ACLMessage reply = msg.createReply();
                        reply.setPerformative(ACLMessage.AGREE);
                        reply.setContent("Alert received and processing");
                        send(reply);
                        
                        // Handle the anomaly asynchronously
                        executorService.submit(() -> handleAnomaly(anomaly, msg));
                    } else {
                        logger.warning("Received null anomaly from " + msg.getSender().getLocalName());
                        
                        // Send error response
                        ACLMessage reply = msg.createReply();
                        reply.setPerformative(ACLMessage.FAILURE);
                        reply.setContent("Error: Null anomaly received");
                        send(reply);
                    }
                    
                } catch (Exception e) {
                    logger.log(Level.WARNING, "Error processing anomaly alert: " + e.getMessage(), e);
                    
                    // Send error response
                    ACLMessage reply = msg.createReply();
                    reply.setPerformative(ACLMessage.FAILURE);
                    reply.setContent("Error processing alert: " + e.getMessage());
                    send(reply);
                }
            } else {
                // Block for a short time if no message is available
                block(100);
            }
        }
    }

    /**
     * Handle an anomaly with appropriate responses
     */
    private void handleAnomaly(Anomaly anomaly, ACLMessage originalMsg) {
        try {
            logger.info("Processing anomaly: " + anomaly.toDetailedString());
            
            // Track response actions
            boolean emailSent = false;
            boolean firewallUpdated = false;
            boolean siemLogged = false;
            
            // 1. Log to SIEM (always do this first for audit trail)
            siemLogged = siemLogger.logAnomaly(anomaly);
            
            // 2. Send email for HIGH and CRITICAL severity
            if (anomaly.getSeverity().equals("HIGH") || anomaly.getSeverity().equals("CRITICAL")) {
                emailSent = emailSender.sendAnomalyAlert(anomaly);
            }
            
            // 3. Update firewall for network-related anomalies
            if (anomaly.getSeverity().equals("HIGH") || anomaly.getSeverity().equals("CRITICAL")) {
                if (isNetworkAnomaly(anomaly) && anomaly.getTriggerMetrics() != null) {
                    String ipToBlock = determineIPToBlock(anomaly);
                    if (ipToBlock != null) {
                        firewallUpdated = firewallManager.blockIP(ipToBlock);
                        
                        // Add blocking info to anomaly data
                        anomaly.addData("ip_blocked", ipToBlock);
                        anomaly.addData("firewall_action", firewallUpdated ? "SUCCESS" : "FAILED");
                        
                        // Update SIEM with blocking information
                        siemLogger.logAnomaly(anomaly);
                    }
                }
            }
            
            // Send success response
            ACLMessage reply = originalMsg.createReply();
            reply.setPerformative(ACLMessage.INFORM);
            reply.setContent(String.format(
                "Anomaly handled: email=%b, firewall=%b, siem=%b", 
                emailSent, firewallUpdated, siemLogged
            ));
            send(reply);
            
            logger.info(String.format(
                "Anomaly %s handled: email=%b, firewall=%b, siem=%b", 
                anomaly.getId(), emailSent, firewallUpdated, siemLogged
            ));
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error handling anomaly: " + e.getMessage(), e);
            
            // Send error response
            ACLMessage reply = originalMsg.createReply();
            reply.setPerformative(ACLMessage.FAILURE);
            reply.setContent("Error handling anomaly: " + e.getMessage());
            send(reply);
        }
    }

    /**
     * Determine if an anomaly is network-related
     */
    private boolean isNetworkAnomaly(Anomaly anomaly) {
        String type = anomaly.getType();
        return type.contains("NETWORK") || 
               type.contains("TRAFFIC") || 
               type.contains("CONNECTION") || 
               type.contains("PORT_SCAN") ||
               type.contains("ERROR_RATE");
    }

    /**
     * Determine which IP to block for a network anomaly
     */
    private String determineIPToBlock(Anomaly anomaly) {
        // For connection flood, use the provided source IP
        if (anomaly.getType().equals("CONNECTION_FLOOD")) {
            Object sourceIP = anomaly.getData("source_ip");
            if (sourceIP != null) {
                return sourceIP.toString();
            }
        }
        
        // For other cases, try to get IP from metrics
        Metrics metrics = anomaly.getTriggerMetrics();
        if (metrics != null) {
            // If we have a source IP that's not our host, block it
            if (metrics.getSourceIp() != null && !metrics.getSourceIp().equals(metrics.getHost())) {
                return metrics.getSourceIp();
            }
            
            // Otherwise, if we have a dest IP that's not our host, block it
            if (metrics.getDestIp() != null && !metrics.getDestIp().equals(metrics.getHost())) {
                return metrics.getDestIp();
            }
        }
        
        // No suitable IP found
        return null;
    }
}