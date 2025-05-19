package agents;

import jade.core.Agent;
import jade.core.AID;
import jade.domain.DFService;
import jade.domain.FIPAAgentManagement.DFAgentDescription;
import jade.domain.FIPAAgentManagement.ServiceDescription;
import jade.domain.FIPAException;
import jade.lang.acl.ACLMessage;
import com.google.gson.Gson;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Utils {
    private static final Logger logger = Logger.getLogger(Utils.class.getName());
    public static Config cfg;
    private static final Gson gson = new Gson();

    static {
        try {
            cfg = Config.load("src/main/resources/application.yml");
            logger.info("Configuration loaded successfully");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to load configuration", e);
            cfg = new Config(); // Create default config
        }
    }

    /**
     * Register an agent with the Directory Facilitator (DF)
     */
    public static void registerService(Agent agent, String serviceType) {
        try {
            DFAgentDescription dfd = new DFAgentDescription();
            dfd.setName(agent.getAID());
            ServiceDescription sd = new ServiceDescription();
            sd.setType(serviceType);
            sd.setName(agent.getLocalName());
            dfd.addServices(sd);
            DFService.register(agent, dfd);
            logger.info("Agent " + agent.getLocalName() + " registered service: " + serviceType);
        } catch (FIPAException fe) {
            logger.log(Level.SEVERE, "Error registering service: " + fe.getMessage(), fe);
        }
    }

    /**
     * Find agents providing a specific service
     */
    public static AID[] findServiceAgents(Agent agent, String serviceType) {
        try {
            DFAgentDescription template = new DFAgentDescription();
            ServiceDescription sd = new ServiceDescription();
            sd.setType(serviceType);
            template.addServices(sd);
            DFAgentDescription[] result = DFService.search(agent, template);
            
            AID[] agents = new AID[result.length];
            for (int i = 0; i < result.length; i++) {
                agents[i] = result[i].getName();
            }
            return agents;
        } catch (FIPAException fe) {
            logger.log(Level.SEVERE, "Error searching for service: " + fe.getMessage(), fe);
            return new AID[0];
        }
    }

    /**
     * Send a message to agents providing a specific service
     */
    public static void sendToService(Agent agent, String serviceType, int performative, Object payload) {
        AID[] serviceAgents = findServiceAgents(agent, serviceType);
        if (serviceAgents.length > 0) {
            ACLMessage msg = new ACLMessage(performative);
            for (AID receiver : serviceAgents) {
                msg.addReceiver(receiver);
            }
            msg.setContent(gson.toJson(payload));
            agent.send(msg);
        } else {
            logger.warning("No agents found for service: " + serviceType);
        }
    }

    /**
     * Parse JSON message content to an object
     */
    public static <T> T parseMessage(String content, Class<T> clazz) {
        try {
            // Check if content is a valid JSON object
            if (content == null || !content.trim().startsWith("{")) {
                logger.warning("Invalid JSON format: " + content);
                return null;
            }
            return gson.fromJson(content, clazz);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error parsing message: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * Convert object to JSON
     */
    public static String toJson(Object obj) {
        return gson.toJson(obj);
    }

    /**
     * Find suitable network interface for packet capture
     */
    public static NetworkInterface findSuitableInterface() {
        try {
            String configInterface = cfg.metrics.networkInterface;
            
            // If specific interface requested
            if (configInterface != null && !configInterface.equals("auto")) {
                NetworkInterface nif = NetworkInterface.getByName(configInterface);
                if (nif != null && nif.isUp() && !nif.isLoopback()) {
                    return nif;
                }
                logger.warning("Specified interface not found or not suitable: " + configInterface);
            }
            
            // Auto-select: find first suitable interface
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface nif = interfaces.nextElement();
                if (nif.isUp() && !nif.isLoopback() && !nif.isVirtual() && 
                    !nif.getDisplayName().contains("VMware") && 
                    !nif.getDisplayName().contains("VirtualBox")) {
                    return nif;
                }
            }
            
            // Fallback to any interface
            interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface nif = interfaces.nextElement();
                if (nif.isUp() && !nif.isLoopback()) {
                    return nif;
                }
            }
            
            logger.severe("No suitable network interface found");
            return null;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error finding network interface", e);
            return null;
        }
    }
    
    // Configuration class
    public static class Config {
        public JadeConfig jade = new JadeConfig();
        public MetricsConfig metrics = new MetricsConfig();
        public DetectionConfig detection = new DetectionConfig();
        public ResponseConfig response = new ResponseConfig();

        public static Config load(String filename) {
            try {
                Yaml yaml = new Yaml();
                InputStream inputStream = new FileInputStream(filename);
                
                Map<String, Object> data = yaml.load(inputStream);
                Config config = new Config();
                
                // Parse configuration sections
                if (data.containsKey("jade")) {
                    config.jade = parseJadeConfig((Map<String, Object>) data.get("jade"));
                }
                
                if (data.containsKey("metrics")) {
                    config.metrics = parseMetricsConfig((Map<String, Object>) data.get("metrics"));
                }
                
                if (data.containsKey("detection")) {
                    config.detection = parseDetectionConfig((Map<String, Object>) data.get("detection"));
                }
                
                if (data.containsKey("response")) {
                    config.response = parseResponseConfig((Map<String, Object>) data.get("response"));
                }
                
                return config;
            } catch (Exception e) {
                Logger.getLogger(Config.class.getName()).log(
                    Level.SEVERE, "Failed to load configuration: " + e.getMessage(), e);
                return new Config(); // Return default config on error
            }
        }

        // Parsing methods (similar to what you had before, but with better error handling)
        private static JadeConfig parseJadeConfig(Map<String, Object> jadeData) {
            // Implementation similar to before
            JadeConfig jade = new JadeConfig();
            // Parse main-container
            if (jadeData.containsKey("main-container")) {
                Map<String, Object> containerData = (Map<String, Object>) jadeData.get("main-container");
                if (containerData != null) {
                    jade.mainContainer.host = (String) containerData.getOrDefault("host", "localhost");
                    Object port = containerData.get("port");
                    if (port instanceof Number) {
                        jade.mainContainer.port = ((Number) port).intValue();
                    }
                }
            }
            
            // Parse services
            if (jadeData.containsKey("services")) {
                Map<String, Object> servicesData = (Map<String, Object>) jadeData.get("services");
                if (servicesData != null) {
                    jade.services.monitor = (String) servicesData.getOrDefault("monitor", "monitoring-service");
                    jade.services.analyze = (String) servicesData.getOrDefault("analyze", "analysis-service");
                    jade.services.respond = (String) servicesData.getOrDefault("respond", "response-service");
                }
            }
            
            return jade;
        }

        private static MetricsConfig parseMetricsConfig(Map<String, Object> metricsData) {
            MetricsConfig metrics = new MetricsConfig();
            if (metricsData != null) {
                Object interval = metricsData.get("sample-interval-ms");
                if (interval instanceof Number) {
                    metrics.sampleIntervalMs = ((Number) interval).longValue();
                }
                
                Object bufferSize = metricsData.get("packet-buffer-size");
                if (bufferSize instanceof Number) {
                    metrics.packetBufferSize = ((Number) bufferSize).intValue();
                }
                
                metrics.networkInterface = (String) metricsData.getOrDefault("network-interface", "auto");
            }
            return metrics;
        }

        private static DetectionConfig parseDetectionConfig(Map<String, Object> detectionData) {
            DetectionConfig detection = new DetectionConfig();
            if (detectionData != null) {
                Object windowSize = detectionData.get("window-size");
                if (windowSize instanceof Number) {
                    detection.windowSize = ((Number) windowSize).intValue();
                }
                
                Object threshold = detectionData.get("threshold-score");
                if (threshold instanceof Number) {
                    detection.thresholdScore = ((Number) threshold).doubleValue();
                }
                
                if (detectionData.containsKey("algorithms")) {
                    List<Map<String, Object>> algorithmList = (List<Map<String, Object>>) detectionData.get("algorithms");
                    if (algorithmList != null) {
                        for (Map<String, Object> algoData : algorithmList) {
                            String type = (String) algoData.get("type");
                            boolean enabled = (boolean) algoData.getOrDefault("enabled", false);
                            
                            if ("statistical".equals(type)) {
                                detection.algorithms.statistical = enabled;
                            } else if ("threshold".equals(type)) {
                                detection.algorithms.threshold = enabled;
                            } else if ("ml".equals(type)) {
                                detection.algorithms.ml = enabled;
                                detection.algorithms.modelPath = (String) algoData.getOrDefault("model-path", "");
                            }
                        }
                    }
                }
            }
            return detection;
        }

        private static ResponseConfig parseResponseConfig(Map<String, Object> responseData) {
            ResponseConfig response = new ResponseConfig();
            
            if (responseData != null) {
                // Parse email config
                if (responseData.containsKey("email")) {
                    Map<String, Object> emailData = (Map<String, Object>) responseData.get("email");
                    if (emailData != null) {
                        response.email.enabled = (boolean) emailData.getOrDefault("enabled", false);
                        response.email.smtpHost = (String) emailData.getOrDefault("smtp-host", "smtp.gmail.com");
                        
                        Object port = emailData.get("smtp-port");
                        if (port instanceof Number) {
                            response.email.smtpPort = ((Number) port).intValue();
                        }
                        
                        response.email.username = (String) emailData.getOrDefault("username", "");
                        response.email.password = (String) emailData.getOrDefault("password", "");
                        response.email.to = (String) emailData.getOrDefault("to", "");
                    }
                }
                
                // Parse firewall config
                if (responseData.containsKey("firewall")) {
                    Map<String, Object> firewallData = (Map<String, Object>) responseData.get("firewall");
                    if (firewallData != null) {
                        response.firewall.enabled = (boolean) firewallData.getOrDefault("enabled", false);
                        response.firewall.platform = (String) firewallData.getOrDefault("platform", "linux");
                        response.firewall.blockScript = (String) firewallData.getOrDefault("block-script", "");
                    }
                }
                
                // Parse SIEM config
                if (responseData.containsKey("siem")) {
                    Map<String, Object> siemData = (Map<String, Object>) responseData.get("siem");
                    if (siemData != null) {
                        response.siem.enabled = (boolean) siemData.getOrDefault("enabled", false);
                        response.siem.type = (String) siemData.getOrDefault("type", "elasticsearch");
                        response.siem.endpoint = (String) siemData.getOrDefault("endpoint", "");
                        response.siem.apiKey = (String) siemData.getOrDefault("api-key", "");
                    }
                }
            }
            
            return response;
        }

        public static class JadeConfig {
            public MainContainerConfig mainContainer = new MainContainerConfig();
            public ServiceConfig services = new ServiceConfig();
            
            public static class MainContainerConfig {
                public String host = "localhost";
                public int port = 7890;
            }
            
            public static class ServiceConfig {
                public String monitor = "monitoring-service";
                public String analyze = "analysis-service";
                public String respond = "response-service";
            }
        }

        public static class MetricsConfig {
            public long sampleIntervalMs = 5000;
            public int packetBufferSize = 65536;
            public String networkInterface = "auto";
        }

        public static class DetectionConfig {
            public int windowSize = 100;
            public double thresholdScore = 0.7;
            public AlgorithmConfig algorithms = new AlgorithmConfig();
            
            public static class AlgorithmConfig {
                public boolean statistical = true;
                public boolean threshold = true;
                public boolean ml = false;
                public String modelPath = "";
            }
        }

        public static class ResponseConfig {
            public EmailConfig email = new EmailConfig();
            public FirewallConfig firewall = new FirewallConfig();
            public SiemConfig siem = new SiemConfig();
            
            public static class EmailConfig {
                public boolean enabled = false;
                public String smtpHost = "smtp.gmail.com";
                public int smtpPort = 587;
                public String username = "";
                public String password = "";
                public String to = "";
            }
            
            public static class FirewallConfig {
                public boolean enabled = false;
                public String platform = "linux";
                public String blockScript = "";
            }
            
            public static class SiemConfig {
                public boolean enabled = false;
                public String type = "elasticsearch";
                public String endpoint = "";
                public String apiKey = "";
            }
        }
    }
}