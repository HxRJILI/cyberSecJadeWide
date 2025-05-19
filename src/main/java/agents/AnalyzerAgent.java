package agents;

import jade.core.Agent;
import jade.core.behaviours.CyclicBehaviour;
import jade.core.behaviours.TickerBehaviour;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AnalyzerAgent extends Agent {
    private static final Logger logger = Logger.getLogger(AnalyzerAgent.class.getName());
    
    private ConcurrentLinkedQueue<Metrics> metricsWindow;
    private Detector detector;
    private final ReentrantLock windowLock = new ReentrantLock();
    private int maxWindowSize;

    @Override
    protected void setup() {
        logger.info("AnalyzerAgent " + getLocalName() + " is starting up");
        
        // Register this agent as an analysis service
        Utils.registerService(this, Utils.cfg.jade.services.analyze);
        
        // Initialize the metrics window
        maxWindowSize = Utils.cfg.detection.windowSize;
        metricsWindow = new ConcurrentLinkedQueue<>();
        
        // Initialize the detector
        detector = new Detector(Utils.cfg.detection);
        
        // Add data ingestion behaviour
        addBehaviour(new DataIngestBehaviour());
        
        // Add detection behaviour that runs periodically
        addBehaviour(new DetectionBehaviour(this, Utils.cfg.metrics.sampleIntervalMs * 2));
        
        logger.info("AnalyzerAgent initialized successfully with window size: " + maxWindowSize);
    }

    @Override
    protected void takeDown() {
        logger.info("AnalyzerAgent " + getLocalName() + " is shutting down");
    }

    /**
     * Behaviour for receiving metrics data
     */
    private class DataIngestBehaviour extends CyclicBehaviour {
    	@Override
    	public void action() {
    	    // Wait for incoming messages with metrics
    	    MessageTemplate template = MessageTemplate.MatchPerformative(ACLMessage.INFORM);
    	    ACLMessage msg = receive(template);
    	    
    	    if (msg != null) {
    	        try {
    	            // Skip response messages (non-JSON responses from ResponseAgent)
    	            if (msg.getSender().getLocalName().equals("resp")) {
    	                // Just log the response without parsing
    	                logger.info("Received response: " + msg.getContent());
    	                return;
    	            }
    	            
    	            // Parse the metrics from the message content
    	            Metrics metrics = Utils.parseMessage(msg.getContent(), Metrics.class);
    	            
    	            if (metrics != null) {
    	                // Add to the sliding window (thread-safe)
    	                windowLock.lock();
    	                try {
    	                    metricsWindow.offer(metrics);
    	                    
    	                    // Maintain window size
    	                    while (metricsWindow.size() > maxWindowSize) {
    	                        metricsWindow.poll();
    	                    }
    	                } finally {
    	                    windowLock.unlock();
    	                }
    	                
    	                logger.info("Received metrics from " + msg.getSender().getLocalName() + 
    	                           ", window size: " + metricsWindow.size());
    	            } else {
    	                logger.warning("Received null metrics from " + msg.getSender().getLocalName());
    	            }
    	            
    	        } catch (Exception e) {
    	            logger.log(Level.WARNING, "Error processing received metrics: " + e.getMessage(), e);
    	        }
    	    } else {
    	        // Block for a short time if no message is available
    	        block(100);
    	    }
    	}
    }

    /**
     * Behaviour for periodic anomaly detection
     */
    private class DetectionBehaviour extends TickerBehaviour {
        public DetectionBehaviour(Agent a, long period) {
            super(a, period);
        }

        @Override
        protected void onTick() {
            try {
                // Create a snapshot of the current window for analysis
                List<Metrics> windowSnapshot = new ArrayList<>();
                
                windowLock.lock();
                try {
                    windowSnapshot.addAll(metricsWindow);
                } finally {
                    windowLock.unlock();
                }
                
                if (windowSnapshot.isEmpty()) {
                    logger.info("No metrics available for detection");
                    return;
                }
                
                logger.info("Running anomaly detection on " + windowSnapshot.size() + " metrics...");
                
                // Run anomaly detection
                List<Anomaly> anomalies = detector.check(windowSnapshot);
                
                if (!anomalies.isEmpty()) {
                    logger.info("Detected " + anomalies.size() + " anomalies");
                    
                    // Send each anomaly to the response agent
                    for (Anomaly anomaly : anomalies) {
                        logger.info("Anomaly detected: " + anomaly);
                        Utils.sendToService(myAgent, Utils.cfg.jade.services.respond, 
                                          ACLMessage.REQUEST, anomaly);
                    }
                } else {
                    logger.info("No anomalies detected in current window");
                }
                
                // Clear old data from window (sliding window approach)
                clearOldMetrics();
                
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error during anomaly detection: " + e.getMessage(), e);
            }
        }

        /**
         * Clear older metrics to maintain window size
         */
        private void clearOldMetrics() {
            windowLock.lock();
            try {
                // Keep only the most recent half of the window for next iteration
                int targetSize = maxWindowSize / 2;
                while (metricsWindow.size() > targetSize) {
                    metricsWindow.poll();
                }
            } finally {
                windowLock.unlock();
            }
        }
    }
}