FROM openjdk:17-jdk-slim

WORKDIR /app

# Copy JAR and resources
COPY target/cyberSecJadeWide-0.0.1-SNAPSHOT.jar /app/cyberSecJadeWide.jar
COPY src/main/resources/application.yml /app/application.yml
COPY lib/jade.jar /app/lib/jade.jar

# Create scripts directory
RUN mkdir -p /app/scripts

# Copy firewall scripts
COPY scripts/block_ip.sh /app/scripts/
RUN chmod +x /app/scripts/block_ip.sh

# Expose ports
EXPOSE 7890 1099

# Set environment variables
ENV JAVA_OPTS="-Xms512m -Xmx1024m -Doshi.windows.hideMSAcpiThermalZoneTemp=true"

# Run JADE with agents
CMD ["sh", "-c", "java $JAVA_OPTS -cp cyberSecJadeWide.jar:lib/jade.jar jade.Boot -gui -port 7890 -agents \"mon:agents.MonitorAgent;ana:agents.AnalyzerAgent;resp:agents.ResponseAgent\""]