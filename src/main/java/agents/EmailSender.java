package agents;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EmailSender {
    private static final Logger logger = Logger.getLogger(EmailSender.class.getName());
    
    private final String smtpHost;
    private final int smtpPort;
    private final String username;
    private final String password;
    private final String recipient;
    private final boolean enabled;

    /**
     * Create an email sender with configuration
     */
    public EmailSender(Utils.Config.ResponseConfig.EmailConfig config) {
        this.smtpHost = config.smtpHost;
        this.smtpPort = config.smtpPort;
        this.username = config.username;
        this.password = config.password;
        this.recipient = config.to;
        this.enabled = config.enabled;
    }

    /**
     * Send an email alert for an anomaly
     */
    public boolean sendAnomalyAlert(Anomaly anomaly) {
        if (!enabled) {
            logger.info("Email alerts are disabled in configuration");
            return false;
        }
        
        try {
            logger.info("Sending email alert for anomaly: " + anomaly.getId());
            
            // Set up mail server properties
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", smtpHost);
            props.put("mail.smtp.port", smtpPort);
            
            // Create session with authentication
            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            // Create message
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
            
            // Set message subject based on severity
            String subject = String.format("SECURITY ALERT: %s - %s", anomaly.getType(), anomaly.getSeverity());
            message.setSubject(subject);
            
            // Set message body
            message.setText(anomaly.toDetailedString());
            
            // Send message
            Transport.send(message);
            logger.info("Email alert sent successfully");
            
            return true;
            
        } catch (MessagingException e) {
            logger.log(Level.SEVERE, "Failed to send email alert: " + e.getMessage(), e);
            return false;
        }
    }
}