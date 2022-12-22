package org.trvedata.sgm.communication;

import org.apache.commons.lang3.tuple.Triple;

import java.util.ArrayDeque;

import org.trvedata.sgm.misc.Utils;
import org.apache.thrift.TException;
import org.trvedata.sgm.message.ModularMessage;
import org.trvedata.sgm.DcgkaProtocol.ControlMessage;
import org.trvedata.sgm.message.SignedMessage;

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
            /* if(sender.name == "mallet" && client.name == "poorBob"){
                SignedMessage signed;
                signed = new SignedMessage(message);
                ModularMessage modular;
                modular = new ModularMessage(signed.content);
                if(modular.isDcgka){
                    ControlMessage control = ControlMessage.of(message.content);
                    AccountableDcgkaMessage accountableDcgkaMessage = new AccountableDcgkaMessage();
                    Utils.deserialize(accountableDcgkaMessage, control.getBytes());
                    byte[] hash = accountableDcgkaMessage.getHash();
                    if(accountableDcgkaMessage.getType().getValue() == 1){ //do it only if its an update
                        System.out.println("Preparing malicious message");
                        //todo
                        AccountableDcgkaMessage maliciousMessage = new AccountableDcgkaMessage(accountableDcgkaMessage);
                        maliciousMessage.setHash(new byte[16]);
                        ControlMessage control2 = ControlMessage.of(Utils.serialize(maliciousMessage));
                        modular.content = control2;
                        //modular.signatureUpdate = signatureUpdate.getRight(); //maybe todo 
                        ModularMessage.Serialized toSign = modular.serialize();
                        signed.content = toSign;
                        queuedMessages.add(Triple.of(sender, client, signed.serialize()));
                        return;
                    } 
                } 
            }  */
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
    }
}
