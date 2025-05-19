package agents;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

public class Anomaly {
    private static final Logger logger = Logger.getLogger(Anomaly.class.getName());
    
    private String id;
    private String host;
    private String type;
    private double score;
    private long timestamp;
    private String description;
    private Metrics triggerMetrics;
    private String severity;
    private Map<String, Object> additionalData;

    public Anomaly() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = Instant.now().toEpochMilli();
        this.additionalData = new HashMap<>();
    }

    public Anomaly(String host, String type, double score) {
        this();
        this.host = host;
        this.type = type;
        this.score = score;
        this.severity = determineSeverity(score);
    }

    public Anomaly(String host, String type, double score, String description) {
        this(host, type, score);
        this.description = description;
    }

    public Anomaly(String host, String type, double score, String description, Metrics triggerMetrics) {
        this(host, type, score, description);
        this.triggerMetrics = triggerMetrics;
    }

    /**
     * Determine severity level based on score
     */
    private String determineSeverity(double score) {
        if (score >= 0.9) return "CRITICAL";
        else if (score >= 0.7) return "HIGH";
        else if (score >= 0.5) return "MEDIUM";
        else return "LOW";
    }

    /**
     * Add any additional data related to the anomaly
     */
    public void addData(String key, Object value) {
        additionalData.put(key, value);
    }

    /**
     * Get additional data
     */
    public Object getData(String key) {
        return additionalData.get(key);
    }

    // Getters and setters
    public String getId() { return id; }
    
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public double getScore() { return score; }
    public void setScore(double score) { 
        this.score = score;
        this.severity = determineSeverity(score);
    }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public Metrics getTriggerMetrics() { return triggerMetrics; }
    public void setTriggerMetrics(Metrics triggerMetrics) { this.triggerMetrics = triggerMetrics; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public Map<String, Object> getAdditionalData() { return additionalData; }
    public void setAdditionalData(Map<String, Object> additionalData) { this.additionalData = additionalData; }

    @Override
    public String toString() {
        return String.format("Anomaly{id='%s', host='%s', type='%s', score=%.2f, severity='%s', timestamp=%d}",
                id, host, type, score, severity, timestamp);
    }

    /**
     * Generate a detailed report of the anomaly
     */
    public String toDetailedString() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault());
        
        StringBuilder sb = new StringBuilder();
        sb.append("=== SECURITY ANOMALY DETECTED ===\n");
        sb.append("ID: ").append(id).append("\n");
        sb.append("Host: ").append(host).append("\n");
        sb.append("Type: ").append(type).append("\n");
        sb.append("Severity: ").append(severity).append("\n");
        sb.append("Score: ").append(String.format("%.2f", score)).append("\n");
        sb.append("Timestamp: ").append(formatter.format(Instant.ofEpochMilli(timestamp))).append("\n");
        
        if (description != null) {
            sb.append("Description: ").append(description).append("\n");
        }
        
        if (triggerMetrics != null) {
            sb.append("\nTrigger Metrics:\n");
            sb.append("  ").append(triggerMetrics.toString()).append("\n");
        }
        
        if (!additionalData.isEmpty()) {
            sb.append("\nAdditional Information:\n");
            for (Map.Entry<String, Object> entry : additionalData.entrySet()) {
                sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        }
        
        sb.append("=====================================");
        return sb.toString();
    }

    /**
     * Generate JSON representation for SIEM systems
     */
    public String toJson() {
        return Utils.toJson(this);
    }
}