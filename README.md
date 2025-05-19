# CyberSecJadeWide - Real-Time Security Monitoring System

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)
![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)

CyberSecJadeWide is a comprehensive real-time cybersecurity monitoring and response system built on the JADE multi-agent framework. It provides continuous monitoring of system resources and network traffic, intelligent anomaly detection, and automated response capabilities.

## 🚀 Features

- **Real-time Monitoring**: Continuous monitoring of system metrics (CPU, memory, disk) and network traffic
- **Intelligent Analysis**: Statistical and threshold-based anomaly detection with configurable sensitivity
- **Automated Response**: Email alerts, SIEM logging, and firewall integration
- **Modular Architecture**: Multi-agent system for distributed processing and scalability
- **Dockerized Deployment**: Easy deployment with Docker and integration with ELK stack
- **Extensible Design**: Easily add new detection algorithms or response actions

## 📋 System Architecture

The system consists of three main agents:

1. **MonitorAgent**: Collects system metrics and network packet data
2. **AnalyzerAgent**: Processes metrics, detects anomalies using statistical analysis
3. **ResponseAgent**: Takes action on detected anomalies (email, SIEM logging, firewall)

![Architecture Diagram](https://via.placeholder.com/800x400?text=CyberSecJadeWide+Architecture)

## 🛠️ Installation

### Prerequisites

- Java JDK 11+ (JDK 17 recommended)
- Docker and Docker Compose
- Maven
- JADE Framework 4.6.0
- Eclipse IDE (for development)

### Method 1: Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/cyberSecJadeWide.git
cd cyberSecJadeWide

# Configure the application
# Edit src/main/resources/application.yml with your settings

# Build the project
mvn clean package

# Start with Docker Compose
docker-compose up -d
```

### Method 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cyberSecJadeWide.git
cd cyberSecJadeWide

# Build the project
mvn clean package

# Start Elasticsearch for SIEM logging
docker-compose up -d elasticsearch kibana

# Run the application
java -Doshi.windows.hideMSAcpiThermalZoneTemp=true -jar target/cyberSecJadeWide-0.0.1-SNAPSHOT.jar
```

## ⚙️ Configuration

Configuration is done through `src/main/resources/application.yml`:

```yaml
jade:
  main-container:
    host: localhost
    port: 7890
  services:
    monitor: monitoring-service
    analyze: analysis-service
    respond: response-service

metrics:
  sample-interval-ms: 5000  # 5 seconds between metrics collection
  packet-buffer-size: 65536  # Packet capture buffer size
  network-interface: auto    # 'auto' or specific interface name

detection:
  window-size: 100  # How many metrics to keep in sliding window
  threshold-score: 0.7  # Anomaly score threshold (0.0-1.0)
  algorithms:
    - type: statistical
      enabled: true
    - type: threshold
      enabled: true
    - type: ml
      enabled: false
      model-path: "models/anomaly_model.pmml"

response:
  email:
    enabled: true
    smtp-host: smtp.gmail.com
    smtp-port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    to: "admin@company.com"
  firewall:
    enabled: true
    platform: linux  # 'windows', 'linux', or 'macos'
    block-script: "scripts/block_ip.sh"
  siem:
    enabled: true
    type: elasticsearch  # 'elasticsearch', 'splunk', or 'custom'
    endpoint: "http://localhost:9200/security/_doc"
    api-key: ""  # Optional API key
```

## 📊 Monitoring and Visualization

### JADE GUI

The JADE GUI provides real-time monitoring of agent activity:
- Start the application with the `-gui` parameter
- View agent communication and status
- Use Sniffer Agent to monitor message exchange

### Kibana Dashboard

Access the Kibana dashboard to visualize security events:
1. Open http://localhost:5601
2. Go to Discover to see detected anomalies
3. Create visualizations for security metrics

## 🔧 Usage

### Running the System

```bash
# Start Docker services (if using Docker)
docker-compose up -d

# Or run manually
java -Doshi.windows.hideMSAcpiThermalZoneTemp=true -cp target/classes:lib/jade.jar:target/dependency/* jade.Boot -gui -port 7890 -agents "mon:agents.MonitorAgent;ana:agents.AnalyzerAgent;resp:agents.ResponseAgent"
```

### Viewing Alerts

1. **Email Alerts**: Check the configured email account for security alerts
2. **SIEM Logs**: View in Kibana or query Elasticsearch directly:
   ```bash
   curl http://localhost:9200/security*/_search?pretty
   ```
3. **Console Logs**: Monitor the application console for real-time updates

## 🔍 Testing

The system includes various test classes to verify functionality:

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=agents.DetectorTest
```

### Triggering Anomalies for Testing

- **CPU Stress**: Run CPU-intensive tasks 
- **Memory Stress**: Run memory-intensive applications
- **Disk Space**: Create large temporary files
- **Network Traffic**: Use network bandwidth testing tools

## 🧩 Extending the System

### Adding New Detection Algorithms

1. Modify the `Detector.java` class
2. Add your algorithm in a new method:
   ```java
   private List<Anomaly> detectCustomAnomalies(String host, List<Metrics> metrics) {
       // Your custom detection logic here
   }
   ```
3. Call your method from the `check()` method

### Adding New Response Actions

1. Create a new handler class similar to `EmailSender.java`
2. Implement your response logic
3. Integrate it into `ResponseAgent.java`

## 📝 Logging

Logging uses Java's standard logging framework (java.util.logging):

- **INFO level**: Normal operation logs
- **WARNING level**: Non-critical issues
- **SEVERE level**: Critical errors

Logs are available in the console and in the Docker container logs if using Docker.

## 🛡️ Security Considerations

- **Email Credentials**: Use app-specific passwords for Gmail
- **API Keys**: Store API keys securely, not in version control
- **Firewalls**: Requires appropriate permissions for firewall rule management
- **Admin Rights**: May require admin/root privileges for packet capture

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Authors

- **RJILI HOUSSAM** - *Initial work* - [RJILI HOUSSAM](https://github.com/HxRJILI)

## 🙏 Acknowledgments

- [JADE Framework](https://jade.tilab.com/) for the multi-agent platform
- [Elasticsearch and Kibana](https://www.elastic.co/) for SIEM capabilities
- [OSHI](https://github.com/oshi/oshi) for system metrics collection

## 📞 Support

For support, please open an issue on the GitHub repository or contact the maintainer directly.

---

Made with ❤️ for cybersecurity enthusiasts
