package agents;

import java.time.Instant;
import java.lang.management.ManagementFactory;

import java.util.Map;
import java.util.HashMap;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.NetworkIF;
import oshi.software.os.OperatingSystem;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Metrics {
    private static final Logger logger = Logger.getLogger(Metrics.class.getName());
    
    // Basic information
    private String host;
    private long timestamp;
    private String metricType; // "NETWORK", "SYSTEM", "COMBINED"
    
    // Network metrics
    private long bytes;
    private long packets;
    private int errors;
    private String protocol;
    private String sourceIp;
    private String destIp;
    private int sourcePort;
    private int destPort;
    
    // System metrics
    private double cpuUsage;
    private long memoryTotal;
    private long memoryUsed;
    private long diskTotal;
    private long diskUsed;
    private long networkRx;
    private long networkTx;
    
    // Additional metrics for advanced analysis
    private Map<String, Object> extendedMetrics;

    public Metrics() {
        this.timestamp = Instant.now().toEpochMilli();
        this.extendedMetrics = new HashMap<>();
    }

    /**
     * Create metrics from a captured packet
     */
    public static Metrics fromPacket(Packet packet) {
        Metrics metrics = new Metrics();
        metrics.metricType = "NETWORK";
        
        try {
            // Set hostname
            metrics.host = java.net.InetAddress.getLocalHost().getHostName();
            
            // Extract basic packet info
            metrics.bytes = packet.length();
            metrics.packets = 1;
            
            // Extract IP information if available
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                metrics.sourceIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                metrics.destIp = ipPacket.getHeader().getDstAddr().getHostAddress();
                metrics.protocol = ipPacket.getHeader().getProtocol().name();
                
                // Add extended metrics
                metrics.extendedMetrics.put("ttl", ipPacket.getHeader().getTtl());
                metrics.extendedMetrics.put("id", ipPacket.getHeader().getIdentification());
                metrics.extendedMetrics.put("tos", ipPacket.getHeader().getTos());
                
                // Extract TCP/UDP port information
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    metrics.sourcePort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                    metrics.destPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                    
                    // Add TCP flags as extended metrics
                    metrics.extendedMetrics.put("tcp_fin", tcpPacket.getHeader().getFin());
                    metrics.extendedMetrics.put("tcp_syn", tcpPacket.getHeader().getSyn());
                    metrics.extendedMetrics.put("tcp_rst", tcpPacket.getHeader().getRst());
                    metrics.extendedMetrics.put("tcp_psh", tcpPacket.getHeader().getPsh());
                    metrics.extendedMetrics.put("tcp_ack", tcpPacket.getHeader().getAck());
                    metrics.extendedMetrics.put("tcp_urg", tcpPacket.getHeader().getUrg());
                    metrics.extendedMetrics.put("window_size", tcpPacket.getHeader().getWindow());
                    
                } else if (packet.contains(UdpPacket.class)) {
                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    metrics.sourcePort = udpPacket.getHeader().getSrcPort().valueAsInt();
                    metrics.destPort = udpPacket.getHeader().getDstPort().valueAsInt();
                    metrics.extendedMetrics.put("udp_length", udpPacket.getHeader().getLength());
                }
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error processing packet: " + e.getMessage(), e);
        }
        
        return metrics;
    }

    /**
     * Create metrics from system information
     */
    public static Metrics fromSystem() {
        Metrics metrics = new Metrics();
        metrics.metricType = "SYSTEM";
        
        try {
            // Set hostname
            metrics.host = java.net.InetAddress.getLocalHost().getHostName();
            
            // CPU usage with proper fallbacks
            try {
                // Get proper CPU usage with OperatingSystemMXBean
                com.sun.management.OperatingSystemMXBean osBean = 
                    (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
                
                metrics.cpuUsage = osBean.getCpuLoad() * 100.0; // Note: getCpuLoad() for newer JDK versions
                
                // If the above doesn't work, try alternatives
                if (metrics.cpuUsage < 0 || Double.isNaN(metrics.cpuUsage)) {
                    try {
                        // Try process CPU load
                        metrics.cpuUsage = osBean.getProcessCpuLoad() * 100.0;
                    } catch (Exception e) {
                        logger.fine("Process CPU load not available, trying system load average");
                    }
                }
                
                // Last resort fallback
                if (metrics.cpuUsage < 0 || Double.isNaN(metrics.cpuUsage)) {
                    double loadAvg = osBean.getSystemLoadAverage();
                    if (loadAvg >= 0) {
                        // Normalize load average to percentage based on core count
                        int cores = Runtime.getRuntime().availableProcessors();
                        metrics.cpuUsage = (loadAvg / cores) * 100.0;
                    } else {
                        metrics.cpuUsage = 50.0; // Default fallback value
                    }
                }
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error getting CPU metrics with MXBean: " + e.getMessage(), e);
                
                // Fallback to OSHI if available
                try {
                    SystemInfo si = new SystemInfo();
                    CentralProcessor processor = si.getHardware().getProcessor();
                    
                    // Get processor ticks
                    long[] prevTicks = processor.getSystemCpuLoadTicks();
                    // Wait a bit
                    Thread.sleep(500);
                    // Get processor ticks again
                    long[] ticks = processor.getSystemCpuLoadTicks();
                    // Calculate CPU usage
                    metrics.cpuUsage = processor.getSystemCpuLoadBetweenTicks(prevTicks) * 100.0;
                } catch (Exception e2) {
                    logger.log(Level.WARNING, "Error getting CPU metrics with OSHI: " + e2.getMessage(), e2);
                    metrics.cpuUsage = 50.0; // Default fallback value
                }
            }
            
            // Memory metrics
            try {
                // Try with MXBean first
                com.sun.management.OperatingSystemMXBean osBean = 
                    (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
                
                long totalMemorySize = osBean.getTotalMemorySize();
                long freeMemorySize = osBean.getFreeMemorySize();
                
                if (totalMemorySize > 0) {
                    metrics.memoryTotal = totalMemorySize;
                    metrics.memoryUsed = totalMemorySize - freeMemorySize;
                } else {
                    // Fallback to Runtime memory
                    Runtime runtime = Runtime.getRuntime();
                    metrics.memoryTotal = runtime.totalMemory();
                    metrics.memoryUsed = metrics.memoryTotal - runtime.freeMemory();
                }
            } catch (Exception e) {
                // Fallback to OSHI
                try {
                    SystemInfo si = new SystemInfo();
                    GlobalMemory memory = si.getHardware().getMemory();
                    metrics.memoryTotal = memory.getTotal();
                    metrics.memoryUsed = metrics.memoryTotal - memory.getAvailable();
                } catch (Exception e2) {
                    logger.log(Level.WARNING, "Error getting memory metrics: " + e2.getMessage(), e2);
                    // Use JVM memory as last resort
                    Runtime runtime = Runtime.getRuntime();
                    metrics.memoryTotal = runtime.maxMemory();
                    metrics.memoryUsed = runtime.totalMemory() - runtime.freeMemory();
                }
            }
            
            // Disk metrics
            try {
                java.io.File root = new java.io.File("/");
                metrics.diskTotal = root.getTotalSpace();
                metrics.diskUsed = metrics.diskTotal - root.getFreeSpace();
                
                // Add system root on Windows
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    java.io.File cDrive = new java.io.File("C:\\");
                    if (cDrive.exists()) {
                        metrics.diskTotal = cDrive.getTotalSpace();
                        metrics.diskUsed = metrics.diskTotal - cDrive.getFreeSpace();
                    }
                }
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error getting disk metrics: " + e.getMessage(), e);
            }
            
            // Network metrics using OSHI
            try {
                SystemInfo si = new SystemInfo();
                for (NetworkIF net : si.getHardware().getNetworkIFs()) {
                    if (net.getBytesRecv() > 0) {
                        metrics.networkRx += net.getBytesRecv();
                        metrics.networkTx += net.getBytesSent();
                        metrics.packets += net.getPacketsRecv() + net.getPacketsSent();
                        metrics.errors += net.getInErrors() + net.getOutErrors();
                    }
                }
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error getting network metrics: " + e.getMessage(), e);
            }
            
            // Add extended metrics - System information
            try {
                metrics.extendedMetrics.put("os_name", System.getProperty("os.name"));
                metrics.extendedMetrics.put("os_version", System.getProperty("os.version"));
                metrics.extendedMetrics.put("java_version", System.getProperty("java.version"));
                metrics.extendedMetrics.put("cpu_cores", Runtime.getRuntime().availableProcessors());
                metrics.extendedMetrics.put("uptime_ms", ManagementFactory.getRuntimeMXBean().getUptime());
            } catch (Exception e) {
                logger.log(Level.FINE, "Error getting extended system metrics: " + e.getMessage(), e);
            }
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error collecting system metrics: " + e.getMessage(), e);
        }
        
        return metrics;
    }

    /**
     * Create combined metrics for unified analysis
     */
    public static Metrics combineMetrics(Metrics systemMetrics, Metrics networkMetrics) {
        Metrics combined = new Metrics();
        combined.metricType = "COMBINED";
        
        try {
            // Copy system metrics
            combined.host = systemMetrics.host;
            combined.cpuUsage = systemMetrics.cpuUsage;
            combined.memoryTotal = systemMetrics.memoryTotal;
            combined.memoryUsed = systemMetrics.memoryUsed;
            combined.diskTotal = systemMetrics.diskTotal;
            combined.diskUsed = systemMetrics.diskUsed;
            
            // Copy network metrics
            combined.networkRx = networkMetrics.networkRx;
            combined.networkTx = networkMetrics.networkTx;
            combined.bytes = networkMetrics.bytes;
            combined.packets = networkMetrics.packets;
            combined.errors = networkMetrics.errors;
            
            // Merge extended metrics
            combined.extendedMetrics.putAll(systemMetrics.extendedMetrics);
            combined.extendedMetrics.putAll(networkMetrics.extendedMetrics);
            
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error combining metrics: " + e.getMessage(), e);
        }
        
        return combined;
    }

    // Getters and setters
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    public String getMetricType() { return metricType; }
    public void setMetricType(String metricType) { this.metricType = metricType; }
    
    public long getBytes() { return bytes; }
    public void setBytes(long bytes) { this.bytes = bytes; }
    
    public long getPackets() { return packets; }
    public void setPackets(long packets) { this.packets = packets; }
    
    public int getErrors() { return errors; }
    public void setErrors(int errors) { this.errors = errors; }
    
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    
    public String getDestIp() { return destIp; }
    public void setDestIp(String destIp) { this.destIp = destIp; }
    
    public int getSourcePort() { return sourcePort; }
    public void setSourcePort(int sourcePort) { this.sourcePort = sourcePort; }
    
    public int getDestPort() { return destPort; }
    public void setDestPort(int destPort) { this.destPort = destPort; }
    
    public double getCpuUsage() { return cpuUsage; }
    public void setCpuUsage(double cpuUsage) { this.cpuUsage = cpuUsage; }
    
    public long getMemoryTotal() { return memoryTotal; }
    public void setMemoryTotal(long memoryTotal) { this.memoryTotal = memoryTotal; }
    
    public long getMemoryUsed() { return memoryUsed; }
    public void setMemoryUsed(long memoryUsed) { this.memoryUsed = memoryUsed; }
    
    public long getDiskTotal() { return diskTotal; }
    public void setDiskTotal(long diskTotal) { this.diskTotal = diskTotal; }
    
    public long getDiskUsed() { return diskUsed; }
    public void setDiskUsed(long diskUsed) { this.diskUsed = diskUsed; }
    
    public long getNetworkRx() { return networkRx; }
    public void setNetworkRx(long networkRx) { this.networkRx = networkRx; }
    
    public long getNetworkTx() { return networkTx; }
    public void setNetworkTx(long networkTx) { this.networkTx = networkTx; }
    
    public Map<String, Object> getExtendedMetrics() { return extendedMetrics; }
    public void setExtendedMetrics(Map<String, Object> extendedMetrics) { this.extendedMetrics = extendedMetrics; }
    
    public void addExtendedMetric(String key, Object value) {
        this.extendedMetrics.put(key, value);
    }
    
    public Object getExtendedMetric(String key) {
        return this.extendedMetrics.get(key);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Metrics{");
        sb.append("host='").append(host).append('\'');
        sb.append(", type='").append(metricType).append('\'');
        sb.append(", timestamp=").append(timestamp);
        
        if ("NETWORK".equals(metricType) || "COMBINED".equals(metricType)) {
            sb.append(", bytes=").append(bytes);
            sb.append(", packets=").append(packets);
            sb.append(", errors=").append(errors);
            if (protocol != null) {
                sb.append(", protocol='").append(protocol).append('\'');
                sb.append(", srcIP='").append(sourceIp).append('\'');
                sb.append(", dstIP='").append(destIp).append('\'');
            }
        }
        
        if ("SYSTEM".equals(metricType) || "COMBINED".equals(metricType)) {
            sb.append(", cpu=").append(String.format("%.2f%%", cpuUsage));
            sb.append(", memory=").append(memoryUsed / (1024 * 1024)).append("MB");
            sb.append(", disk=").append(diskUsed * 100 / (diskTotal > 0 ? diskTotal : 1)).append("%");
        }
        
        sb.append('}');
        return sb.toString();
    }
}