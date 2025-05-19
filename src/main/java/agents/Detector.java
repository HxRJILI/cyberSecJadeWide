package agents;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class Detector {
    private static final Logger logger = Logger.getLogger(Detector.class.getName());
    
    private final double thresholdScore;
    private final boolean useStatistical;
    private final boolean useThreshold;
    private final boolean useML;
    private final String modelPath;
    
    // Historical data for statistical analysis
    private final Map<String, List<Double>> historicalValues;
    
    // Baseline values for various metrics
    private final Map<String, Double> baselineValues;
    
    // Moving averages for trend detection
    private final Map<String, Double> movingAverages;
    
    // Counters for rare events
    private final Map<String, Integer> eventCounters;
    
    // Connection tracking for network analysis
    private final Map<String, Map<String, Integer>> connectionTracking;

    /**
     * Create a detector with configuration
     */
    public Detector(Utils.Config.DetectionConfig config) {
        this.thresholdScore = config.thresholdScore;
        this.useStatistical = config.algorithms.statistical;
        this.useThreshold = config.algorithms.threshold;
        this.useML = config.algorithms.ml;
        this.modelPath = config.algorithms.modelPath;
        
        this.historicalValues = new ConcurrentHashMap<>();
        this.baselineValues = new ConcurrentHashMap<>();
        this.movingAverages = new ConcurrentHashMap<>();
        this.eventCounters = new ConcurrentHashMap<>();
        this.connectionTracking = new ConcurrentHashMap<>();
        
        // Initialize with default baselines
        initializeBaselines();
        
        logger.info("Detector initialized with threshold: " + thresholdScore);
        logger.info("Algorithms enabled: " + 
                   "Statistical=" + useStatistical + 
                   ", Threshold=" + useThreshold + 
                   ", ML=" + useML);
    }

    /**
     * Initialize default baseline values
     */
    private void initializeBaselines() {
        // CPU usage baseline (70% is considered normal upper limit)
        baselineValues.put("cpu_usage", 70.0);
        
        // Memory usage baseline (80% is considered normal upper limit)
        baselineValues.put("memory_percent", 80.0);
        
        // Disk usage baseline (90% is considered normal upper limit)
        baselineValues.put("disk_percent", 90.0);
        
        // Network traffic baselines (will be adjusted based on observations)
        baselineValues.put("network_rx_rate", 1024.0 * 1024.0); // 1 MB/s initial guess
        baselineValues.put("network_tx_rate", 1024.0 * 1024.0); // 1 MB/s initial guess
        
        // Error rate baseline (1% is considered normal upper limit)
        baselineValues.put("error_rate", 0.01);
    }

    /**
     * Check for anomalies in the provided metrics window
     */
    public List<Anomaly> check(List<Metrics> window) {
        List<Anomaly> anomalies = new ArrayList<>();
        
        if (window == null || window.isEmpty()) {
            return anomalies;
        }

        try {
            // Update historical data and baselines
            updateHistoricalData(window);
            
            // Group metrics by host
            Map<String, List<Metrics>> metricsByHost = window.stream()
                    .collect(Collectors.groupingBy(Metrics::getHost));

            // Check each host for anomalies
            for (Map.Entry<String, List<Metrics>> entry : metricsByHost.entrySet()) {
                String host = entry.getKey();
                List<Metrics> hostMetrics = entry.getValue();
                
                // Apply different detection methods based on configuration
                if (useThreshold) {
                    anomalies.addAll(detectThresholdAnomalies(host, hostMetrics));
                }
                
                if (useStatistical) {
                    anomalies.addAll(detectStatisticalAnomalies(host, hostMetrics));
                }
                
                if (useML) {
                    anomalies.addAll(detectMLAnomalies(host, hostMetrics));
                }
                
                // Always run these specialized detections
                anomalies.addAll(detectNetworkAnomalies(host, hostMetrics));
                anomalies.addAll(detectPatternAnomalies(host, hostMetrics));
            }
            
            // Filter out low-scoring anomalies
            return anomalies.stream()
                    .filter(a -> a.getScore() >= thresholdScore)
                    .collect(Collectors.toList());
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error in anomaly detection: " + e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /**
     * Update historical data with new metrics
     */
    private void updateHistoricalData(List<Metrics> metrics) {
        for (Metrics m : metrics) {
            String host = m.getHost();
            
            // Update CPU history
            if (m.getCpuUsage() > 0) {
                updateHistoricalValue(host + "_cpu", m.getCpuUsage());
            }
            
            // Update memory history
            if (m.getMemoryTotal() > 0) {
                double memPercent = (double) m.getMemoryUsed() / m.getMemoryTotal() * 100.0;
                updateHistoricalValue(host + "_mem_percent", memPercent);
            }
            
            // Update disk history
            if (m.getDiskTotal() > 0) {
                double diskPercent = (double) m.getDiskUsed() / m.getDiskTotal() * 100.0;
                updateHistoricalValue(host + "_disk_percent", diskPercent);
            }
            
            // Update network history
            updateHistoricalValue(host + "_network_rx", (double) m.getNetworkRx());
            updateHistoricalValue(host + "_network_tx", (double) m.getNetworkTx());
            
            // Update bytes history
            updateHistoricalValue(host + "_bytes", (double) m.getBytes());
            
            // Update packet history
            updateHistoricalValue(host + "_packets", (double) m.getPackets());
            
            // Update error rate history
            if (m.getPackets() > 0) {
                double errorRate = (double) m.getErrors() / m.getPackets();
                updateHistoricalValue(host + "_error_rate", errorRate);
            }
            
            // Update connection tracking for network metrics
            if (m.getSourceIp() != null && m.getDestIp() != null) {
                updateConnectionTracking(m.getSourceIp(), m.getDestIp(), m.getProtocol());
            }
        }
    }
    
    /**
     * Update a single historical value
     */
    private void updateHistoricalValue(String key, double value) {
        // Create list if it doesn't exist
        historicalValues.putIfAbsent(key, new ArrayList<>());
        
        List<Double> values = historicalValues.get(key);
        values.add(value);
        
        // Keep only the last 1000 values
        while (values.size() > 1000) {
            values.remove(0);
        }
        
        // Update moving average
        if (values.size() >= 10) {
            // Use last 10 values for moving average
            double sum = 0;
            for (int i = values.size() - 10; i < values.size(); i++) {
                sum += values.get(i);
            }
            double movingAvg = sum / 10;
            movingAverages.put(key, movingAvg);
        }
    }
    
    /**
     * Update connection tracking data
     */
    private void updateConnectionTracking(String sourceIp, String destIp, String protocol) {
        String connKey = sourceIp + "_" + destIp;
        
        // Create map for this connection if it doesn't exist
        connectionTracking.putIfAbsent(connKey, new HashMap<>());
        
        // Update protocol counter
        Map<String, Integer> protocolMap = connectionTracking.get(connKey);
        if (protocol != null) {
            protocolMap.put(protocol, protocolMap.getOrDefault(protocol, 0) + 1);
        }
        
        // Increment total counter
        protocolMap.put("TOTAL", protocolMap.getOrDefault("TOTAL", 0) + 1);
    }

    /**
     * Detect anomalies based on simple thresholds
     */
    private List<Anomaly> detectThresholdAnomalies(String host, List<Metrics> metrics) {
        List<Anomaly> anomalies = new ArrayList<>();
        
        // Find latest system metrics
        Optional<Metrics> latestSystem = metrics.stream()
                .filter(m -> "SYSTEM".equals(m.getMetricType()) || "COMBINED".equals(m.getMetricType()))
                .max(Comparator.comparing(Metrics::getTimestamp));
        
        if (latestSystem.isPresent()) {
            Metrics m = latestSystem.get();
            
            // Check CPU usage
            if (m.getCpuUsage() > baselineValues.get("cpu_usage")) {
                double score = Math.min(1.0, m.getCpuUsage() / 100.0);
                
                Anomaly anomaly = new Anomaly(host, "HIGH_CPU_USAGE", score,
                        String.format("High CPU usage detected: %.2f%%", m.getCpuUsage()),
                        m);
                
                anomalies.add(anomaly);
            }
            
            // Check memory usage
            if (m.getMemoryTotal() > 0) {
                double memPercent = (double) m.getMemoryUsed() / m.getMemoryTotal() * 100.0;
                
                if (memPercent > baselineValues.get("memory_percent")) {
                    double score = Math.min(1.0, memPercent / 100.0);
                    
                    Anomaly anomaly = new Anomaly(host, "HIGH_MEMORY_USAGE", score,
                            String.format("High memory usage detected: %.2f%%", memPercent),
                            m);
                    
                    anomalies.add(anomaly);
                }
            }
            
            // Check disk usage
            if (m.getDiskTotal() > 0) {
                double diskPercent = (double) m.getDiskUsed() / m.getDiskTotal() * 100.0;
                
                if (diskPercent > baselineValues.get("disk_percent")) {
                    double score = Math.min(1.0, diskPercent / 100.0);
                    
                    Anomaly anomaly = new Anomaly(host, "HIGH_DISK_USAGE", score,
                            String.format("High disk usage detected: %.2f%%", diskPercent),
                            m);
                    
                    anomalies.add(anomaly);
                }
            }
        }
        
        return anomalies;
    }

    /**
     * Detect anomalies using statistical methods (z-score, moving average)
     */
    private List<Anomaly> detectStatisticalAnomalies(String host, List<Metrics> metrics) {
        List<Anomaly> anomalies = new ArrayList<>();
        
        // Z-score anomaly detection
        for (Metrics m : metrics) {
            // Check CPU usage anomaly
            String cpuKey = host + "_cpu";
            if (historicalValues.containsKey(cpuKey) && m.getCpuUsage() > 0) {
                double zscore = calculateZScore(historicalValues.get(cpuKey), m.getCpuUsage());
                
                if (zscore > 3.0) { // 3 sigma rule
                    double score = Math.min(1.0, zscore / 5.0); // Normalize to 5 sigma
                    
                    Anomaly anomaly = new Anomaly(host, "CPU_STATISTICAL_ANOMALY", score,
                            String.format("Unusual CPU activity detected (Z-score: %.2f)", zscore),
                            m);
                    
                    anomalies.add(anomaly);
                }
            }
            
            // Check memory anomaly
            if (m.getMemoryTotal() > 0) {
                String memKey = host + "_mem_percent";
                double memPercent = (double) m.getMemoryUsed() / m.getMemoryTotal() * 100.0;
                
                if (historicalValues.containsKey(memKey)) {
                    double zscore = calculateZScore(historicalValues.get(memKey), memPercent);
                    
                    if (zscore > 3.0) {
                        double score = Math.min(1.0, zscore / 5.0);
                        
                        Anomaly anomaly = new Anomaly(host, "MEMORY_STATISTICAL_ANOMALY", score,
                                String.format("Unusual memory activity detected (Z-score: %.2f)", zscore),
                                m);
                        
                        anomalies.add(anomaly);
                    }
                }
            }
            
            // Check network traffic anomaly
            String rxKey = host + "_network_rx";
            String txKey = host + "_network_tx";
            
            if (historicalValues.containsKey(rxKey) && m.getNetworkRx() > 0) {
                double zscore = calculateZScore(historicalValues.get(rxKey), (double) m.getNetworkRx());
                
                if (zscore > 3.0) {
                    double score = Math.min(1.0, zscore / 5.0);
                    
                    Anomaly anomaly = new Anomaly(host, "NETWORK_RX_ANOMALY", score,
                            String.format("Unusual inbound network traffic (Z-score: %.2f)", zscore),
                            m);
                    
                    anomalies.add(anomaly);
                }
            }
            
            if (historicalValues.containsKey(txKey) && m.getNetworkTx() > 0) {
                double zscore = calculateZScore(historicalValues.get(txKey), (double) m.getNetworkTx());
                
                if (zscore > 3.0) {
                    double score = Math.min(1.0, zscore / 5.0);
                    
                    Anomaly anomaly = new Anomaly(host, "NETWORK_TX_ANOMALY", score,
                            String.format("Unusual outbound network traffic (Z-score: %.2f)", zscore),
                            m);
                    
                    anomalies.add(anomaly);
                }
            }
        }
        
        return anomalies;
    }

    /**
     * Calculate Z-Score (standard deviations from mean)
     */
    private double calculateZScore(List<Double> data, double value) {
        if (data.size() < 10) {
            return 0.0; // Not enough data for meaningful statistics
        }
        
        // Calculate mean
        double sum = 0;
        for (double d : data) {
            sum += d;
        }
        double mean = sum / data.size();
        
        // Calculate standard deviation
        double varianceSum = 0;
        for (double d : data) {
            varianceSum += Math.pow(d - mean, 2);
        }
        double stdDev = Math.sqrt(varianceSum / data.size());
        
        // Avoid division by zero
        if (stdDev == 0) {
            return 0.0;
        }
        
        // Return z-score
        return Math.abs(value - mean) / stdDev;
    }

    /**
     * Detect network-specific anomalies
     */
    private List<Anomaly> detectNetworkAnomalies(String host, List<Metrics> metrics) {
        List<Anomaly> anomalies = new ArrayList<>();
        
        // Calculate network statistics
        long totalBytes = 0;
        long totalPackets = 0;
        int totalErrors = 0;
        
        for (Metrics m : metrics) {
            totalBytes += m.getBytes();
            totalPackets += m.getPackets();
            totalErrors += m.getErrors();
        }
        
        // Detect high error rate
        if (totalPackets > 0) {
            double errorRate = (double) totalErrors / totalPackets;
            
            if (errorRate > baselineValues.get("error_rate")) {
                double score = Math.min(1.0, errorRate * 100); // Normalize
                
                // Find a representative metric
                Metrics sample = metrics.stream()
                        .filter(m -> m.getErrors() > 0)
                        .findFirst()
                        .orElse(metrics.get(0));
                
                Anomaly anomaly = new Anomaly(host, "HIGH_ERROR_RATE", score,
                        String.format("High network error rate: %.2f%%", errorRate * 100),
                        sample);
                
                anomalies.add(anomaly);
            }
        }
        
        // Detect unusual protocols or ports
        Map<String, Integer> protocolCounts = new HashMap<>();
        Map<Integer, Integer> portCounts = new HashMap<>();
        
        for (Metrics m : metrics) {
            if (m.getProtocol() != null) {
                protocolCounts.put(m.getProtocol(), protocolCounts.getOrDefault(m.getProtocol(), 0) + 1);
            }
            
            if (m.getSourcePort() > 0) {
                portCounts.put(m.getSourcePort(), portCounts.getOrDefault(m.getSourcePort(), 0) + 1);
            }
            
            if (m.getDestPort() > 0) {
                portCounts.put(m.getDestPort(), portCounts.getOrDefault(m.getDestPort(), 0) + 1);
            }
        }
        
        // Check for unusual ports (potential scanning)
        if (portCounts.size() > 20) { // Arbitrary threshold for port diversity
            double score = Math.min(1.0, portCounts.size() / 100.0);
            
            Metrics sample = metrics.get(0);
            
            Anomaly anomaly = new Anomaly(host, "PORT_SCAN_DETECTED", score,
                    String.format("Possible port scanning detected (%d unique ports)", portCounts.size()),
                    sample);
            
            anomaly.addData("unique_ports", portCounts.size());
            anomalies.add(anomaly);
        }
        
        return anomalies;
    }

    /**
     * Detect pattern-based anomalies (repeated behaviors, specific sequences)
     */
    private List<Anomaly> detectPatternAnomalies(String host, List<Metrics> metrics) {
        List<Anomaly> anomalies = new ArrayList<>();
        
        // Count connection attempts by source
        Map<String, Integer> sourceConnections = new HashMap<>();
        
        for (Metrics m : metrics) {
            if (m.getSourceIp() != null && !m.getSourceIp().equals(host)) {
                sourceConnections.put(m.getSourceIp(), 
                                     sourceConnections.getOrDefault(m.getSourceIp(), 0) + 1);
            }
        }
        
        // Detect excessive connection attempts (potential DoS)
        for (Map.Entry<String, Integer> entry : sourceConnections.entrySet()) {
            if (entry.getValue() > 50) { // Arbitrary threshold
                double score = Math.min(1.0, entry.getValue() / 100.0);
                
                // Find a sample metric for this source
                Optional<Metrics> sample = metrics.stream()
                        .filter(m -> entry.getKey().equals(m.getSourceIp()))
                        .findFirst();
                
                if (sample.isPresent()) {
                    Anomaly anomaly = new Anomaly(host, "CONNECTION_FLOOD", score,
                            String.format("High number of connections from %s: %d", 
                                         entry.getKey(), entry.getValue()),
                            sample.get());
                    
                    anomaly.addData("source_ip", entry.getKey());
                    anomaly.addData("connection_count", entry.getValue());
                    anomalies.add(anomaly);
                }
            }
        }
        
        return anomalies;
    }

    /**
     * Detect anomalies using machine learning (stub)
     */
    private List<Anomaly> detectMLAnomalies(String host, List<Metrics> metrics) {
        // This is a stub for ML detection
        // In a real implementation, you would:
        // 1. Extract features from metrics
        // 2. Apply a trained model
        // 3. Return anomalies based on model output
        
        return new ArrayList<>();
    }
}