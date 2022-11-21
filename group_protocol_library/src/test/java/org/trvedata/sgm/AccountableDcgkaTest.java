package org.trvedata.sgm;
import org.junit.Test;
import static org.assertj.core.api.Assertions.assertThat;
import org.trvedata.sgm.communication.Network;
import org.trvedata.sgm.communication.TotalOrderSimpleNetwork;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;
import org.trvedata.sgm.testhelper.PrintingDsgmListener;
import java.util.Arrays;


public class AccountableDcgkaTest {

    private void testGeneral(final DsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        Network network = new TotalOrderSimpleNetwork(); // default Network with instant delivery
        DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(network,
                new InMemoryPreKeySource(), implementationConfiguration, "alice", "bob");
        DsgmClient alice = factoryResult.clients[0];
        DsgmClient bob = factoryResult.clients[1];
        alice.addListener(new PrintingDsgmListener("alice", factoryResult.identityKeyToName));
        bob.addListener(new PrintingDsgmListener("bob", factoryResult.identityKeyToName));

        alice.create(Arrays.asList(alice.getIdentifier(), bob.getIdentifier()));
        alice.send("Msg1 plain".getBytes());
        bob.send("Msg2 plain".getBytes());
        alice.update();
        bob.send("Msg3 plain".getBytes());
        alice.send("Msg4 plain".getBytes());
    }

    @Test
    public void simpleTest() {
        testGeneral(
                new DsgmClient.DgmClientImplementationConfiguration(
                    DsgmClient.DcgkaChoice.ACCOUNTABLE, true, true, true));
    }

    
    
}