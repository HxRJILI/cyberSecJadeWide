package agents;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class FirewallManager {
    private static final Logger logger = Logger.getLogger(FirewallManager.class.getName());
    
    private final String platform;
    private final String blockScript;
    private final boolean enabled;
    private final Map<String, Long> blockedIPs;

    /**
     * Create a firewall manager with configuration
     */
    public FirewallManager(Utils.Config.ResponseConfig.FirewallConfig config) {
        this.platform = config.platform;
        this.blockScript = config.blockScript;
        this.enabled = config.enabled;
        this.blockedIPs = new HashMap<>();
    }

    /**
     * Block an IP address using appropriate firewall commands
     */
    public boolean blockIP(String ipAddress) {
        if (!enabled) {
            logger.info("Firewall blocking is disabled in configuration");
            return false;
        }
        
        // Check if this IP is already blocked
        if (blockedIPs.containsKey(ipAddress)) {
            logger.info("IP " + ipAddress + " is already blocked");
            return true;
        }
        
        try {
            logger.info("Blocking IP address: " + ipAddress);
            
            // Use the appropriate blocking method based on platform
            boolean success = false;
            
            switch (platform.toLowerCase()) {
                case "windows":
                    success = blockIPWindows(ipAddress);
                    break;
                case "linux":
                    success = blockIPLinux(ipAddress);
                    break;
                case "macos":
                    success = blockIPMacOS(ipAddress);
                    break;
                default:
                    // Use script if platform specific is not available
                    success = blockIPUsingScript(ipAddress);
                    break;
            }
            
            // If successful, add to blocked IPs
            if (success) {
                blockedIPs.put(ipAddress, System.currentTimeMillis());
                logger.info("Successfully blocked IP: " + ipAddress);
            }
            
            return success;
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to block IP: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Block IP on Windows using netsh
     */
    private boolean blockIPWindows(String ipAddress) throws Exception {
        // Create a Windows Firewall rule
        String command = "netsh advfirewall firewall add rule name=\"CYBERSECJADE_BLOCK_" 
                + ipAddress.replace(".", "_") 
                + "\" dir=in action=block remoteip=" + ipAddress;
        
        Process process = Runtime.getRuntime().exec(command);
        boolean completed = process.waitFor(30, TimeUnit.SECONDS);
        int exitCode = completed ? process.exitValue() : -1;
        
        return exitCode == 0;
    }

    /**
     * Block IP on Linux using iptables
     */
    private boolean blockIPLinux(String ipAddress) throws Exception {
        // Use iptables to block the IP
        String command = "iptables -A INPUT -s " + ipAddress + " -j DROP";
        
        Process process = Runtime.getRuntime().exec(command);
        int exitCode = process.waitFor();
        
        return exitCode == 0;
    }

    /**
     * Block IP on macOS using pfctl
     */
    private boolean blockIPMacOS(String ipAddress) throws Exception {
        // Add IP to pf table and block
        String command = "echo 'block in from " + ipAddress + " to any' | sudo pfctl -ef -";
        
        Process process = Runtime.getRuntime().exec(command);
        int exitCode = process.waitFor();
        
        return exitCode == 0;
    }

    /**
     * Block IP using provided script
     */
    private boolean blockIPUsingScript(String ipAddress) throws Exception {
        if (blockScript == null || blockScript.isEmpty()) {
            logger.warning("No block script specified in configuration");
            return false;
        }
        
        // Execute the block script with IP as parameter
        String command = blockScript + " " + ipAddress;
        
        Process process = Runtime.getRuntime().exec(command);
        
        // Wait with timeout
        boolean completed = process.waitFor(30, TimeUnit.SECONDS);
        int exitCode;
        
        if (completed) {
            exitCode = process.exitValue();
        } else {
            // Process timed out
            process.destroyForcibly();
            exitCode = -1;
            logger.warning("Process timed out after 30 seconds");
        }
        
        if (exitCode != 0) {
            // Read error output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            StringBuilder errorOutput = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                errorOutput.append(line).append("\n");
            }
            
            logger.warning("Block script exit code: " + exitCode + ", Error: " + errorOutput.toString());
        }
        
        return exitCode == 0;
    }

    /**
     * Check if an IP is currently blocked
     */
    public boolean isBlocked(String ipAddress) {
        return blockedIPs.containsKey(ipAddress);
    }

    /**
     * Get all currently blocked IPs
     */
    public Map<String, Long> getBlockedIPs() {
        return new HashMap<>(blockedIPs);
    }
}