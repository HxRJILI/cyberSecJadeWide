package agents;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SiemLogger {
    private static final Logger logger = Logger.getLogger(SiemLogger.class.getName());
    
    private final String endpoint;
    private final String apiKey;
    private final String type;
    private final boolean enabled;
    private final CloseableHttpClient httpClient;
    private final SimpleDateFormat isoDateFormat;

    /**
     * Create a SIEM logger with configuration
     */
    public SiemLogger(Utils.Config.ResponseConfig.SiemConfig config) {
        this.endpoint = config.endpoint;
        this.apiKey = config.apiKey;
        this.type = config.type;
        this.enabled = config.enabled;
        
        this.httpClient = HttpClients.createDefault();
        
        this.isoDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        this.isoDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    /**
     * Log an anomaly to the SIEM system
     */
    public boolean logAnomaly(Anomaly anomaly) {
        if (!enabled) {
            logger.info("SIEM logging is disabled in configuration");
            return false;
        }
        
        try {
            logger.info("Logging anomaly to SIEM: " + anomaly.getId());
            
            // Create the payload
            String payload = createPayload(anomaly);
            
            // Send to the appropriate SIEM system
            boolean success = false;
            
            switch (type.toLowerCase()) {
                case "elasticsearch":
                    success = sendToElasticsearch(payload);
                    break;
                case "splunk":
                    success = sendToSplunk(payload);
                    break;
                default:
                    success = sendToCustomEndpoint(payload);
                    break;
            }
            
            return success;
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to log to SIEM: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Create a standardized payload for SIEM systems
     */
 // In SiemLogger.java, update the createPayload method
    private String createPayload(Anomaly anomaly) {
        Map<String, Object> payload = new HashMap<>();
        
        // Basic information
        payload.put("@timestamp", isoDateFormat.format(new Date(anomaly.getTimestamp())));
        payload.put("id", anomaly.getId());
        payload.put("host", anomaly.getHost());
        payload.put("type", anomaly.getType());
        payload.put("severity", anomaly.getSeverity());
        payload.put("score", anomaly.getScore());
        payload.put("description", anomaly.getDescription());
        
        // Add all additional data
        payload.put("additional_data", anomaly.getAdditionalData());
        
        // Add trigger metrics if available
        if (anomaly.getTriggerMetrics() != null) {
            Metrics m = anomaly.getTriggerMetrics();
            
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("metric_type", m.getMetricType());
            metrics.put("timestamp", m.getTimestamp());
            
            // Network metrics
            if ("NETWORK".equals(m.getMetricType()) || "COMBINED".equals(m.getMetricType())) {
                metrics.put("bytes", m.getBytes());
                metrics.put("packets", m.getPackets());
                metrics.put("errors", m.getErrors());
                metrics.put("protocol", m.getProtocol());
                metrics.put("source_ip", m.getSourceIp());
                metrics.put("dest_ip", m.getDestIp());
                metrics.put("source_port", m.getSourcePort());
                metrics.put("dest_port", m.getDestPort());
            }
            
            // System metrics
            if ("SYSTEM".equals(m.getMetricType()) || "COMBINED".equals(m.getMetricType())) {
                metrics.put("cpu_usage", m.getCpuUsage());
                metrics.put("memory_used", m.getMemoryUsed());
                metrics.put("memory_total", m.getMemoryTotal());
                metrics.put("disk_used", m.getDiskUsed());
                metrics.put("disk_total", m.getDiskTotal());
                metrics.put("network_rx", m.getNetworkRx());
                metrics.put("network_tx", m.getNetworkTx());
            }
            
            payload.put("metrics", metrics);
        }
        
        // Print payload for debugging
        logger.info("SIEM payload: " + Utils.toJson(payload));
        
        // Convert to JSON
        return Utils.toJson(payload);
    }

    /**
     * Send payload to Elasticsearch
     */
    private boolean sendToElasticsearch(String payload) throws Exception {
        HttpPost httpPost = new HttpPost(endpoint);
        
        // Add headers
        httpPost.setHeader("Content-Type", "application/json");
        
        // Add payload
        httpPost.setEntity(new StringEntity(payload, "UTF-8"));
        
        // Log the payload for debugging
        System.out.println("Sending to Elasticsearch: " + payload);
        
        // Execute and get response
        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());
            
            System.out.println("Elasticsearch response: " + statusCode + " - " + responseBody);
            
            // 2xx codes are success
            return statusCode >= 200 && statusCode < 300;
        }
    }

    /**
     * Send payload to Splunk
     */
    private boolean sendToSplunk(String payload) throws Exception {
        HttpPost httpPost = new HttpPost(endpoint);
        
        // Add headers
        httpPost.setHeader("Content-Type", "application/json");
        if (apiKey != null && !apiKey.isEmpty()) {
            httpPost.setHeader("Authorization", "Splunk " + apiKey);
        }
        
        // Add payload
        httpPost.setEntity(new StringEntity(payload));
        
        // Execute and get response
        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());
            
            // 2xx codes are success
            boolean success = statusCode >= 200 && statusCode < 300;
            
            if (!success) {
                logger.warning("Splunk returned status " + statusCode + ": " + responseBody);
            }
            
            return success;
        }
    }

    /**
     * Send payload to custom endpoint
     */
    private boolean sendToCustomEndpoint(String payload) throws Exception {
        HttpPost httpPost = new HttpPost(endpoint);
        
        // Add headers
        httpPost.setHeader("Content-Type", "application/json");
        if (apiKey != null && !apiKey.isEmpty()) {
            httpPost.setHeader("X-API-Key", apiKey);
        }
        
        // Add payload
        httpPost.setEntity(new StringEntity(payload));
        
        // Execute and get response
        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());
            
            // 2xx codes are success
            boolean success = statusCode >= 200 && statusCode < 300;
            
            if (!success) {
                logger.warning("Custom endpoint returned status " + statusCode + ": " + responseBody);
            }
            
            return success;
        }
    }

    /**
     * Close resources when done
     */
    public void close() {
        try {
            if (httpClient != null) {
                httpClient.close();
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error closing HTTP client", e);
        }
    }
}