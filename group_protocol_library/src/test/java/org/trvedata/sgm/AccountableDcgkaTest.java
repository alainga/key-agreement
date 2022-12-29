package org.trvedata.sgm;
import org.junit.Test;
import static org.assertj.core.api.Assertions.assertThat;
import org.trvedata.sgm.communication.Network;
import org.trvedata.sgm.communication.TotalOrderSimpleNetwork;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;
import org.trvedata.sgm.testhelper.AccountablePrintingDsgmListener;
import java.util.Arrays;


public class AccountableDcgkaTest {

    private void testGeneral(final AccountableDsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        Network network = new TotalOrderSimpleNetwork(); // default Network with instant delivery
        AccountableDsgmClientFactory.DgmClientFactoryResult factoryResult = AccountableDsgmClientFactory.createClients(network,
                new InMemoryPreKeySource(), implementationConfiguration, "alice", "bob");
        AccountableDsgmClient alice = factoryResult.clients[0];
        AccountableDsgmClient bob = factoryResult.clients[1];
        alice.addListener(new AccountablePrintingDsgmListener("alice", factoryResult.identityKeyToName));
        bob.addListener(new AccountablePrintingDsgmListener("bob", factoryResult.identityKeyToName));

        //System.out.println("type of state: " +alice.mDgmProtocolState.dcgkaProtocol.getClass());
        alice.create(Arrays.asList(alice.getIdentifier(), bob.getIdentifier()));
        alice.send("Msg1 plain".getBytes());
        bob.send("Msg2 plain".getBytes());
        alice.update();
        bob.send("Msg3 plain".getBytes());
        alice.send("Msg4 plain".getBytes());
    }

    /* the actual malicious stuff is happening in TotalOrderSimpleNetwork when there is a message from "mallet" to "poorBob" with type update */
    private void testMalicious(final AccountableDsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        Network network = new TotalOrderSimpleNetwork(); // default Network with instant delivery
        AccountableDsgmClientFactory.DgmClientFactoryResult factoryResult = AccountableDsgmClientFactory.createClients(network,
                new InMemoryPreKeySource(), implementationConfiguration, "alice", "poorBob", "mallet");
        AccountableDsgmClient alice = factoryResult.clients[0];
        AccountableDsgmClient poorBob = factoryResult.clients[1];
        AccountableDsgmClient mallet = factoryResult.clients[2];
        alice.addListener(new AccountablePrintingDsgmListener("alice", factoryResult.identityKeyToName));
        poorBob.addListener(new AccountablePrintingDsgmListener("poorBob", factoryResult.identityKeyToName));
        mallet.addListener(new AccountablePrintingDsgmListener("mallet", factoryResult.identityKeyToName));

        alice.create(Arrays.asList(alice.getIdentifier(), poorBob.getIdentifier(), mallet.getIdentifier()));
        //alice.send("Msg1 plain".getBytes());
        //poorBob.send("Msg2 plain".getBytes());
        
        //malicious stuff is actually happening in TotalOrderSimpleNetwork
        
        //mallet.maliciousUpdate();
        System.out.println("mallet calls maliciousUpdate()");
        mallet.maliciousUpdate(poorBob.mIdentityKeyPair.publicKey);
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
                new AccountableDsgmClient.DgmClientImplementationConfiguration(
                    AccountableDsgmClient.DcgkaChoice.ACCOUNTABLE, true, true, true));
    }

    @Test
    public void maliciousTest() {
        testMalicious(
                new AccountableDsgmClient.DgmClientImplementationConfiguration(
                    AccountableDsgmClient.DcgkaChoice.ACCOUNTABLE, true, true, true));
    } 
}