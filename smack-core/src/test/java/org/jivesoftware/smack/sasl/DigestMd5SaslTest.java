package org.jivesoftware.smack.sasl;

public class DigestMd5SaslTest extends AbstractSaslTest {

    protected DigestMd5SaslTest(SASLMechanism saslMechanism) {
        super(saslMechanism);
    }

    protected void runTest() {
        saslMechanism.authenticate("chris", "irrelevant", serviceName, password);
    }
}
