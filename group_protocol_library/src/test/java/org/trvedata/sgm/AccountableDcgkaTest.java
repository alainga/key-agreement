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

        //System.out.println("type of state: " +alice.mDgmProtocolState.dcgkaProtocol.getClass());
        alice.create(Arrays.asList(alice.getIdentifier(), bob.getIdentifier()));
        alice.send("Msg1 plain".getBytes());
        bob.send("Msg2 plain".getBytes());
        alice.update();
        bob.send("Msg3 plain".getBytes());
        alice.send("Msg4 plain".getBytes());
    }

    private void testMalicious(final DsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        Network network = new TotalOrderSimpleNetwork(); // default Network with instant delivery
        DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(network,
                new InMemoryPreKeySource(), implementationConfiguration, "alice", "bob", "mallet");
        DsgmClient alice = factoryResult.clients[0];
        DsgmClient bob = factoryResult.clients[1];
        DsgmClient mallet = factoryResult.clients[2];
        alice.addListener(new PrintingDsgmListener("alice", factoryResult.identityKeyToName));
        bob.addListener(new PrintingDsgmListener("poorBob", factoryResult.identityKeyToName));
        mallet.addListener(new PrintingDsgmListener("mallet", factoryResult.identityKeyToName));

        alice.create(Arrays.asList(alice.getIdentifier(), bob.getIdentifier(), mallet.getIdentifier()));
        alice.send("Msg1 plain".getBytes());
        bob.send("Msg2 plain".getBytes());
        
        //todo: either implement new methods and stuff or do everything manually...
        
        //mallet.maliciousUpdate();
        mallet.update();
        //callstack of update:
        /* mallelt.update();
        
            Pair<? extends DsgmProtocol.State, byte[]> result = mDsgmProtocol.update(mDgmProtocolState);

                Pair<DcgkaState, DcgkaProtocol.ControlMessage> dcgkaUpdate = dcgkaProtocol.update(state.dcgkaState);

                    Triple<State, UpdateMessage, byte[]> internal = updateInternal(state); // byte[] is the hash of the seed secret
                    AccountableDcgkaMessage message = new AccountableDcgkaMessage(AccountableDcgkaMessageType.UPDATE,ByteBuffer.wrap(Utils.serialize(internal.getMiddle())), ByteBuffer.wrap(internal.getRight()));
                    return Pair.of(internal.getLeft(), ControlMessage.of(Utils.serialize(message)));

                state = state.setDcgkaState(dcgkaUpdate.getLeft());
                return wrapAndProcess(state, dcgkaUpdate.getRight().getBytes(), true, true);
                
            //mDgmProtocolState = result.getLeft();
            sendMessageToGroupMembers(result.getRight());

                broadcast(message);

                    Client.mNetwork.broadcast(this, message);

                        public void broadcast(final Client sender, final byte[] message) {
                            for (Client client : mIdentifierToClient.values()) {
                                if (client != sender) queuedMessages.add(Triple.of(sender, client, message));
                            }
                            if (!isActive) {
                                // Prevent recursive calls from reaching this block
                                isActive = true;
                                while (!queuedMessages.isEmpty()) {
                                    Triple<Client, Client, byte[]> toSend = queuedMessages.pop();
                                    toSend.getMiddle().handleMessageFromNetwork(toSend.getLeft().getIdentifier(), toSend.getRight());
                                }
                                isActive = false;
                            }
                        } */
        
    }

    @Test
    public void simpleTest() {
        testGeneral(
                new DsgmClient.DgmClientImplementationConfiguration(
                    DsgmClient.DcgkaChoice.ACCOUNTABLE, true, true, true));
    }

    @Test
    public void maliciousTest() {
        testMalicious(
                new DsgmClient.DgmClientImplementationConfiguration(
                    DsgmClient.DcgkaChoice.ACCOUNTABLE, true, true, true));
    }

    
    
}