package agents;

import jade.core.Agent;
import jade.core.behaviours.OneShotBehaviour;

public class TestAgent extends Agent {
    @Override
    protected void setup() {
        System.out.println("=== TestAgent is running! ===");
        System.out.println("JADE is working correctly on your system.");
        
        addBehaviour(new OneShotBehaviour() {
            @Override
            public void action() {
                System.out.println("System information:");
                System.out.println("  Java version: " + System.getProperty("java.version"));
                System.out.println("  OS: " + System.getProperty("os.name"));
                System.out.println("  User: " + System.getProperty("user.name"));
                System.out.println("Agent name: " + getLocalName());
                System.out.println("=== Test completed successfully ===");
            }
        });
    }
}