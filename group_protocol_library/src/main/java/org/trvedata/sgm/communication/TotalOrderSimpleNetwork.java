package org.trvedata.sgm.communication;

import org.apache.commons.lang3.tuple.Triple;

import java.util.ArrayDeque;

import org.trvedata.sgm.misc.Utils;
import org.apache.thrift.TException;

public class TotalOrderSimpleNetwork extends SimpleNetwork {
    private boolean isActive = false;
    private ArrayDeque<Triple<Client, Client, byte[]>> queuedMessages = new ArrayDeque<>(); // (sender, recipient, message)

    /**
     * Overrides broadcast to use a message queue and detect recursive calls, so that
     * message is sent to everyone before any response messages are sent.
     */
    @Override
    public void broadcast(final Client sender, final byte[] message) {
        for (Client client : mIdentifierToClient.values()) {

            //ALG: for testing accountability
            if(sender.name == "mallet" && client.name == "poorBob"){
                try {
                    System.out.println("message = "+message); //todo find place of hash in it to modify
                    AccountableDcgkaMessage maliciousMessage = new AccountableDcgkaMessage();
                    Utils.deserialize(maliciousMessage, message);
                    if(maliciousMessage.getType().getValue() == 1){ //do it only if its an update
                        maliciousMessage.setHash(new byte[16]);
                        byte[] mm = Utils.serialize(maliciousMessage);
                        queuedMessages.add(Triple.of(sender, client, mm));
                    } else {
                        queuedMessages.add(Triple.of(sender, client, message));
                    }
                    
                } catch (TException exc) {
                    throw new IllegalArgumentException("Failed to deserialize in process", exc);
                }
            } else{
                if (client != sender) queuedMessages.add(Triple.of(sender, client, message));

            }
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
    }
}
