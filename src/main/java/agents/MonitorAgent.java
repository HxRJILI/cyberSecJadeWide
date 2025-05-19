package agents;

import jade.core.Agent;
import jade.core.behaviours.CyclicBehaviour;
import jade.core.behaviours.TickerBehaviour;
import jade.core.behaviours.TickerBehaviour;
import jade.lang.acl.ACLMessage;

//Replace the problematic import:
//import org.pcap4j.core.TimeoutException;

//With these alternatives:
import java.util.concurrent.TimeoutException; // Standard Java timeout
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.net.NetworkInterface;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MonitorAgent extends Agent {
    private static final Logger logger = Logger.getLogger(MonitorAgent.class.getName());
    
    private PcapHandle handle;
    private AtomicBoolean capturing = new AtomicBoolean(false);
    private Thread captureThread;

    // @Override
    // protected void setup() {
    //    logger.info("MonitorAgent " + getLocalName() + " is starting up");
    //    
    //    // Register this agent as a monitoring service
    //    Utils.registerService(this, Utils.cfg.jade.services.monitor);
    //    
    //    // Add system metrics collection behaviour
    //    addBehaviour(new SystemMetricsBehaviour(this, Utils.cfg.metrics.sampleIntervalMs));
    //    
    //    // Add packet capture behaviour
    //    initializePacketCapture();
    //    
    //    logger.info("MonitorAgent initialized successfully");
    //}

    @Override
    protected void setup() {
        logger.info("MonitorAgent " + getLocalName() + " is starting up");
        
        // Register this agent as a monitoring service
        Utils.registerService(this, Utils.cfg.jade.services.monitor);
        
        // Add system metrics collection behaviour
        addBehaviour(new SystemMetricsBehaviour(this, Utils.cfg.metrics.sampleIntervalMs));
        
        // Add simulated packet capture (no need for WinPcap/Npcap)
        addBehaviour(new TickerBehaviour(this, 2000) {
            @Override
            protected void onTick() {
                try {
                    // Create simulated packet metrics
                    Metrics metrics = new Metrics();
                    metrics.setHost(java.net.InetAddress.getLocalHost().getHostName());
                    metrics.setMetricType("NETWORK");
                    metrics.setBytes((long)(Math.random() * 1500) + 64);
                    metrics.setPackets(1);
                    metrics.setErrors(Math.random() < 0.05 ? 1 : 0); // 5% error rate
                    
                    // Simulate IP addresses and protocols
                    metrics.setSourceIp("192.168.1." + (int)(Math.random() * 254 + 1));
                    metrics.setDestIp("10.0.0." + (int)(Math.random() * 254 + 1));
                    metrics.setProtocol(Math.random() > 0.5 ? "TCP" : "UDP");
                    metrics.setSourcePort((int)(Math.random() * 60000 + 1024));
                    metrics.setDestPort((int)(Math.random() * 65000 + 1));
                    
                    // Send to analyzer
                    Utils.sendToService(myAgent, Utils.cfg.jade.services.analyze, ACLMessage.INFORM, metrics);
                    
                    logger.info("Simulated packet: " + metrics);
                    
                } catch (Exception e) {
                    logger.log(Level.WARNING, "Error in simulated packet capture: " + e.getMessage(), e);
                }
            }
        });
        
        logger.info("MonitorAgent initialized with simulated packet capture");
    }
    
    @Override
    protected void takeDown() {
        logger.info("MonitorAgent " + getLocalName() + " is shutting down");
        
        // Stop packet capture
        capturing.set(false);
        if (captureThread != null) {
            captureThread.interrupt();
        }
        
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    /**
     * Initialize packet capture on a separate thread
     */
    private void initializePacketCapture() {
        try {
            // Find a suitable network interface
            NetworkInterface networkInterface = Utils.findSuitableInterface();
            if (networkInterface == null) {
                logger.warning("No suitable network interface found for packet capture");
                return;
            }
            
            // Convert Java NetworkInterface to Pcap4j PcapNetworkInterface
            PcapNetworkInterface nif = Pcaps.getDevByName(networkInterface.getName());
            if (nif == null) {
                logger.warning("Could not find Pcap device for interface: " + networkInterface.getName());
                return;
            }
            
            logger.info("Setting up packet capture on interface: " + nif.getName());
            
            // Configure packet capture
            int snapshotLength = 65536; // Maximum bytes per packet
            int readTimeout = 10; // Milliseconds
            int bufferSize = Utils.cfg.metrics.packetBufferSize;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            
            // Open the interface for capture
            handle = nif.openLive(snapshotLength, mode, readTimeout);
            
            // Start capture thread
            captureThread = new Thread(this::runPacketCapture);
            captureThread.setDaemon(true); // Don't prevent JVM shutdown
            
            captureThread.start();
            
            logger.info("Packet capture started successfully");
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to initialize packet capture: " + e.getMessage(), e);
            logger.info("Will continue without packet capture. Note that admin/root privileges may be required.");
        }
    }

    /**
     * Continuous packet capture loop
     */
    private void runPacketCapture() {
        capturing.set(true);
        
        try {
            // Main capture loop
            while (capturing.get() && !Thread.currentThread().isInterrupted()) {
            	try {
            	    // Get next packet with timeout
            	    Packet packet = handle.getNextPacketEx();
            	    if (packet != null) {
            	        processPacket(packet);
            	    }
            	} catch (PcapNativeException | NotOpenException e) {
            	    if (capturing.get()) {
            	        logger.log(Level.WARNING, "Error capturing packet: " + e.getMessage(), e);
            	    }
            	} catch (Exception e) {
            	    // Generic catch for any timeout or other exception
            	    // Only log if it's not a normal timeout
            	    if (capturing.get() && !e.getMessage().contains("timeout")) {
            	        logger.log(Level.WARNING, "Packet capture error: " + e.getMessage(), e);
            	    }
            	}
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Packet capture thread error: " + e.getMessage(), e);
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            logger.info("Packet capture stopped");
        }
    }

    /**
     * Process a captured packet
     */
    private void processPacket(Packet packet) {
        try {
            // Convert packet to metrics
            Metrics metrics = Metrics.fromPacket(packet);
            
            // Send to analyzer
            Utils.sendToService(this, Utils.cfg.jade.services.analyze, ACLMessage.INFORM, metrics);
            
            logger.fine("Packet captured: " + metrics);
            
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error processing packet: " + e.getMessage(), e);
        }
    }

    /**
     * Behaviour for collecting system metrics
     */
    private class SystemMetricsBehaviour extends TickerBehaviour {
        public SystemMetricsBehaviour(Agent a, long period) {
            super(a, period);
        }

        @Override
        protected void onTick() {
            try {
                // Collect system metrics
                Metrics systemMetrics = Metrics.fromSystem();
                
                // Send to analyzer
                Utils.sendToService(myAgent, Utils.cfg.jade.services.analyze, ACLMessage.INFORM, systemMetrics);
                
                logger.info("System metrics collected: " + systemMetrics);
                
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error collecting system metrics: " + e.getMessage(), e);
            }
        }
    }
}