package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.thrift.TException;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.crypto.*;
import org.trvedata.sgm.message.*;
import org.trvedata.sgm.misc.Constants;
import org.trvedata.sgm.misc.Logger;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

/* Extend protocol with accountability
 * 
 * 
 * 
 */

public class AccountableDcgkaProtocol extends FullDcgkaProtocol {

    
    public ProcessReturn<AState> process(AState state, ControlMessage message, IdentityKey sender,
                                        AckOrderer.Timestamp causalInfo) {
        try {
            AccountableDcgkaMessage accountableDcgkaMessage = new AccountableDcgkaMessage();
            Utils.deserialize(accountableDcgkaMessage, message.getBytes());
            byte[] hash = accountableDcgkaMessage.getHash();
            switch (accountableDcgkaMessage.getType()) {
                case CREATE:
                    CreateMessage create = new CreateMessage();
                    Utils.deserialize(create, accountableDcgkaMessage.getMessage());
                    return processCreate(state, create, sender, causalInfo, hash);
                case UPDATE:
                    UpdateMessage update = new UpdateMessage();
                    Utils.deserialize(update, accountableDcgkaMessage.getMessage());
                    return processUpdate(state, update, sender, causalInfo, hash);
                case REMOVE:
                    RemoveMessage remove = new RemoveMessage();
                    Utils.deserialize(remove, accountableDcgkaMessage.getMessage());
                    return processRemove(state, remove, sender, causalInfo, hash);
                case ADD:
                    AddMessage add = new AddMessage();
                    Utils.deserialize(add, accountableDcgkaMessage.getMessage());
                    return processAdd(state, add, sender, causalInfo);
                case WELCOME:
                    WelcomeMessage welcome = new WelcomeMessage();
                    Utils.deserialize(welcome, accountableDcgkaMessage.getMessage());
                    return processWelcome(state, welcome, sender, causalInfo);
                case ACK:
                    AckMessage ack = new AckMessage();
                    Utils.deserialize(ack, accountableDcgkaMessage.getMessage());
                    return processAck(state, ack, sender, causalInfo);
                case ACK_WITH_UPDATE:
                    AckWithUpdateMessage ackWithUpdate = new AckWithUpdateMessage();
                    Utils.deserialize(ackWithUpdate, accountableDcgkaMessage.getMessage());
                    return processAckWithUpdate(state, ackWithUpdate, sender, causalInfo, hash);
                case ADD_ACK:
                    AccAddAckMessage addAck = new AccAddAckMessage();
                    Utils.deserialize(addAck, accountableDcgkaMessage.getMessage());
                    return processAddAck(state, addAck, sender, causalInfo);
                /* case REVEAL:
                    RevealMessage reveal = new RevealMessage();
                    Utils.deserialize(reveal, accountableDcgkaMessage.getMessage());
                    return processReveal(state, reveal, sender, causalInfo); */
                default:
                    throw new IllegalArgumentException("Unrecognized AccountableDcgkaMessageType: " + accountableDcgkaMessage.getType());
            }
        } catch (TException | IllegalArgumentException exc) {
            throw new IllegalArgumentException("Failed to deserialize in process", exc);
        }
    }

    
    public Pair<AState, ControlMessage> create(AState state, Collection<IdentityKey> members) {
        CreateMessage create = new CreateMessage();
        Triple<AState, ? extends List<ByteBuffer>, byte[]> generateResult = generateSeedSecret(state, members);
        state = generateResult.getLeft();
        create.setCiphertexts(generateResult.getMiddle());
        for (IdentityKey member : members) {
            create.addToIdsExcludingSender(ByteBuffer.wrap(member.serialize()));
        }
        byte[] hash = generateResult.getRight();
        AccountableDcgkaMessage message = new AccountableDcgkaMessage(AccountableDcgkaMessageType.CREATE,
                ByteBuffer.wrap(Utils.serialize(create)), ByteBuffer.wrap(hash));
        return Pair.of(state, ControlMessage.of(Utils.serialize(message)));
    }

    private ProcessReturn<AState> processCreate(AState state, CreateMessage create, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo, byte[] hash) {
        ArrayList<IdentityKey> members = deserializeIdList(create.getIdsExcludingSender());
        members.add(sender);
        if (!members.contains(state.id)) {
            // Throw an exception, to fulfill the condition stated in the Javadoc for DcgkaProtocol.process.
            throw new IllegalArgumentException("Welcome is not for us: " + causalInfo.messageId);
        }
        state = state.setStrongRemoveDGM(new StrongRemoveDgm(members, state.id));
        Triple<AState, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecretReturn =
                processSeedSecret(state, sender, causalInfo.messageId, create.getCiphertexts(), hash);
        state = processSeedSecretReturn.getLeft();
        state = state.setCreateMessageId(causalInfo.messageId);
        ControlMessage response;
        if (processSeedSecretReturn.getMiddle() == null) response = ControlMessage.of(null);
        else {
            AccountableDcgkaMessage ackWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.ACK,
                    ByteBuffer.wrap(Utils.serialize(processSeedSecretReturn.getMiddle())), null);
            response = ControlMessage.of(Utils.serialize(ackWrapped));
        }
        return new ProcessReturn<>(state, DcgkaMessageType.WELCOME, response,
                processSeedSecretReturn.getRight(), null, members, Collections.emptyList(),
                causalInfo.messageId, Collections.emptyList());
    }

    private ProcessReturn<AState> processAck(AState state, AckMessage ack, IdentityKey sender,
                                            AckOrderer.Timestamp causalInfo) {
        if (causalInfo.ackedMessageId == null) {
            throw new IllegalArgumentException("ackedMessageId is null for ack message");
        }
        // Note acking the message will fail if it's an ack of the user's own removal.
        // Thus we will refuse to process messages from a user that depend on their own removal.
        Collection<MessageId> ackedMessageIds;
        if (!sender.equals(state.id)) {
            if (state.strongRemoveDGM.isAdd(causalInfo.ackedMessageId) ||
                    state.strongRemoveDGM.isRemove(causalInfo.ackedMessageId)) {
                // This condition will fail for acks of the creation and of updates
                state.strongRemoveDGM.ack(sender, causalInfo.ackedMessageId);
            }
            ackedMessageIds = Collections.singletonList(causalInfo.ackedMessageId);
        } else ackedMessageIds = Collections.emptyList();

        ForwardSecureEncryptionProtocol.Key updateSecret;
        PuncturablePseudorandomFunction pprf = state.pprfs.get(causalInfo.ackedMessageId);
        if (pprf == null) {
            throw new IllegalArgumentException("No PPRF for acked message");
        }
        Pair<PuncturablePseudorandomFunction, byte[]> chainUpdatePair = pprf.popValue(sender.serialize());
        if (chainUpdatePair.getRight() != null) {
            // Derive the sender's perMemberSecret from pprf.
            state = state.putPprf(causalInfo.messageId, chainUpdatePair.getLeft());
            Pair<AState, ForwardSecureEncryptionProtocol.Key> keyUpdatePair =
                    prng(state, sender, chainUpdatePair.getRight());
            state = keyUpdatePair.getLeft();
            updateSecret = keyUpdatePair.getRight();
        } else {
            // See if we got forwarded the perMemberSecret.
            ByteBuffer myForward = ack.getForwards().get(ByteBuffer.wrap(state.id.serialize()));
            if (myForward == null) {
                updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);
                Logger.i("FullDcgkaProtocol", "No derived secret for member " + sender.hashCode() +
                        " when acking message " + causalInfo.ackedMessageId + ".  This should only " +
                        "happen if the sender was added concurrently to that message and the ack.");
            } else {
                // We did get forwarded the perMemberSecret.
                Pair<AState, byte[]> decryptionResult = decryptFrom(state, sender,
                        Utils.asArray(myForward));
                state = decryptionResult.getLeft();
                Pair<AState, ForwardSecureEncryptionProtocol.Key> keyUpdatePair =
                        prng(state, sender, decryptionResult.getRight());
                state = keyUpdatePair.getLeft();
                updateSecret = keyUpdatePair.getRight();
            }
        }

        //alain: if ack.isSetHash(): compare this to adders ratchet state, if no match -> reveal :) welll maybe not

        return new ProcessReturn<>(state, DcgkaMessageType.OTHER, ControlMessage.of(null),
                updateSecret, null, Collections.emptyList(),
                Collections.emptyList(), causalInfo.messageId, ackedMessageIds);
    }

    
    public Pair<AState, ControlMessage> update(AState state) {
        Triple<AState, UpdateMessage, byte[]> internal = updateInternal(state);
        AccountableDcgkaMessage message = new AccountableDcgkaMessage(AccountableDcgkaMessageType.UPDATE,
                ByteBuffer.wrap(Utils.serialize(internal.getMiddle())), ByteBuffer.wrap(internal.getRight()));
        return Pair.of(internal.getLeft(), ControlMessage.of(Utils.serialize(message)));
    }

    private Triple<AState, UpdateMessage, byte[]> updateInternal(AState state) {
        UpdateMessage update = new UpdateMessage();
        Triple<AState, ? extends List<ByteBuffer>, byte[]> generateResult = generateSeedSecret(state,
                state.strongRemoveDGM.queryWholeWithoutMe());
        state = generateResult.getLeft();
        update.setCiphertexts(generateResult.getMiddle());
        return Triple.of(state, update, generateResult.getRight());
    }

    private ProcessReturn<AState> processUpdate(AState state, UpdateMessage update, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo, byte[] hash) {
        Triple<AState, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecretReturn =
                processSeedSecret(state, sender, causalInfo.messageId, update.getCiphertexts(), hash);
        state = processSeedSecretReturn.getLeft();
        ControlMessage response;
        if (processSeedSecretReturn.getMiddle() == null) response = ControlMessage.of(null);
        else {
            AccountableDcgkaMessage ackWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.ACK,
                    ByteBuffer.wrap(Utils.serialize(processSeedSecretReturn.getMiddle())), null);
            response = ControlMessage.of(Utils.serialize(ackWrapped));
        }
        return new ProcessReturn<>(state, DcgkaMessageType.UPDATE, response,
                processSeedSecretReturn.getRight(), null, Collections.emptyList(), Collections.emptyList(),
                causalInfo.messageId, Collections.emptyList());
    }

    
    public Pair<AState, ControlMessage> remove(AState state, IdentityKey removed) {
        RemoveMessage remove = new RemoveMessage();
        HashSet<IdentityKey> recipients = state.strongRemoveDGM.queryWholeWithoutMe();
        recipients.remove(removed);
        Triple<AState, ? extends List<ByteBuffer>, byte[]> generateResult = generateSeedSecret(state,
                recipients);
        state = generateResult.getLeft();
        remove.setCiphertexts(generateResult.getMiddle());
        remove.setRemoved(removed.serialize());
        byte[] hash = generateResult.getRight();

        AccountableDcgkaMessage message = new AccountableDcgkaMessage(AccountableDcgkaMessageType.REMOVE,
                ByteBuffer.wrap(Utils.serialize(remove)), ByteBuffer.wrap(hash));
        return Pair.of(state, ControlMessage.of(Utils.serialize(message)));
    }

    private ProcessReturn<AState> processRemove(AState state, RemoveMessage remove, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo, byte[] hash) {
        IdentityKey removed = new IdentityKey(remove.getRemoved());
        Collection<IdentityKey> removedCollection = state.strongRemoveDGM.remove(sender,
                Collections.singleton(removed), causalInfo.messageId);
        if (removedCollection.contains(state.id)) {
            // TODO: need to revert the MembershipSet.  Will be fixed once it's persistent.
            // Return the result without processing the seed secret, since we can't.
            return new ProcessReturn<>(state, DcgkaMessageType.REMOVE, ControlMessage.of(null),
                    ForwardSecureEncryptionProtocol.Key.of(null), removed, Collections.emptyList(), removedCollection,
                    causalInfo.messageId, Collections.emptyList());
        }

        Triple<AState, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecretReturn =
                processSeedSecret(state, sender, causalInfo.messageId, remove.getCiphertexts(), hash);
        state = processSeedSecretReturn.getLeft();

        // Do ack-with-update if needed
        ControlMessage response;
        HashSet<IdentityKey> diffSet = state.strongRemoveDGM.queryView(sender);
        diffSet.removeAll(state.strongRemoveDGM.queryWhole());
        if (!diffSet.isEmpty()) {
            Triple<AState, UpdateMessage, byte[]> updateResult = updateInternal(state);
            state = updateResult.getLeft();
            byte[] ackhash = updateResult.getRight(); //todo
            AckWithUpdateMessage ackWithUpdate = new AckWithUpdateMessage(processSeedSecretReturn.getMiddle(),
                    updateResult.getMiddle());
            AccountableDcgkaMessage ackWithUpdateWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.ACK_WITH_UPDATE,
                    ByteBuffer.wrap(Utils.serialize(ackWithUpdate)), ByteBuffer.wrap(ackhash));
            response = ControlMessage.of(Utils.serialize(ackWithUpdateWrapped));
        } else {
            if (processSeedSecretReturn.getMiddle() == null) response = ControlMessage.of(null);
            else {
                AccountableDcgkaMessage ackWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.ACK,
                        ByteBuffer.wrap(Utils.serialize(processSeedSecretReturn.getMiddle())), null);
                response = ControlMessage.of(Utils.serialize(ackWrapped));
            }
        }

        return new ProcessReturn<>(state, DcgkaMessageType.REMOVE, response,
                processSeedSecretReturn.getRight(), removed, Collections.emptyList(), removedCollection,
                causalInfo.messageId, Collections.emptyList());
    }

    private ProcessReturn<AState> processAckWithUpdate(AState state, AckWithUpdateMessage ackWithUpdate,
                                                      IdentityKey sender, AckOrderer.Timestamp causalInfo, byte[] hash) {
        ProcessReturn<AState> ackResult = processAck(state, ackWithUpdate.getAck(), sender, causalInfo);
        ProcessReturn<AState> updateResult = processUpdate(ackResult.state, ackWithUpdate.getUpdate(),
                sender, causalInfo, hash);
        return new ProcessReturn<>(updateResult.state, DcgkaMessageType.UPDATE, updateResult.responseMessage,
                updateResult.updateSecret, null, Collections.emptyList(), Collections.emptyList(),
                causalInfo.messageId, ackResult.ackedMessageIds);
    }

    
    public Triple<AState, ControlMessage, ControlMessage> add(AState state, IdentityKey added) {
        // TODO: new user should add themselves after deserializing
        // TODO: once MembershipSet is immutable, instead of doing that, serialize the MembershipSet
        // with the new user added?  Change in process as well.
        Pair<AState, byte[]> myPrfForAdded = encryptTo(state, added, state.prfPrngs.get(state.id));
        state = myPrfForAdded.getLeft();
        WelcomeMessage welcome = new WelcomeMessage(ByteBuffer.wrap(state.strongRemoveDGM.serialize().getLeft()),
                ByteBuffer.wrap(myPrfForAdded.getRight()));
        AccountableDcgkaMessage welcomeWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.WELCOME,
                ByteBuffer.wrap(Utils.serialize(welcome)), null);
        AddMessage add = new AddMessage(ByteBuffer.wrap(added.serialize()));
        AccountableDcgkaMessage addWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.ADD,
                ByteBuffer.wrap(Utils.serialize(add)), null);
        return Triple.of(state, ControlMessage.of(Utils.serialize(welcomeWrapped)),
                ControlMessage.of(Utils.serialize(addWrapped)));
    }

    private ProcessReturn<AState> processAdd(AState state, AddMessage add,
                                            IdentityKey sender, AckOrderer.Timestamp causalInfo) {
        IdentityKey added = new IdentityKey(add.getAdded());
        Collection<IdentityKey> addedCollection;
        if (!state.strongRemoveDGM.add(sender, added, causalInfo.messageId)) {
            addedCollection = Collections.singletonList(added);
        } else addedCollection = Collections.emptyList();

        ForwardSecureEncryptionProtocol.Key updateSecret;
        if (state.strongRemoveDGM.queryView(sender).contains(state.id)) {
            Pair<AState, ForwardSecureEncryptionProtocol.Key> prngWelcome = prng(state,
                    sender, "welcome".getBytes());
            state = prngWelcome.getLeft();
            PuncturablePseudorandomFunction pprf = new PuncturablePseudorandomFunction(prngWelcome.getRight().getBytes(),
                    Collections.singletonList(add.getAdded()));
            state = state.putPprf(causalInfo.messageId, pprf);
            Pair<AState, ForwardSecureEncryptionProtocol.Key> prngAdd = prng(state,
                    sender, "add".getBytes());
            state = prngAdd.getLeft();
            updateSecret = prngAdd.getRight();
        } else updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);

        ControlMessage response;
        if (sender.equals(state.id)) response = ControlMessage.of(null);
        else {
            Pair<AState, byte[]> myPrfForAdded = encryptTo(state, added, state.prfPrngs.get(state.id));
            state = myPrfForAdded.getLeft();

            //alain: include adders ratchet state here for newly added
            byte[] hash = Utils.hash(state.prfPrngs.get(sender));
            AccAddAckMessage addAck = new AccAddAckMessage(ByteBuffer.wrap(myPrfForAdded.getRight()), ByteBuffer.wrap(hash));
            AccountableDcgkaMessage addAckWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.ADD_ACK,
                    ByteBuffer.wrap(Utils.serialize(addAck)), null);
            response = ControlMessage.of(Utils.serialize(addAckWrapped));
            state = state.setLastAcked(causalInfo.messageId);
        }

        return new ProcessReturn<>(state, DcgkaMessageType.ADD, response,
                updateSecret, added, addedCollection, Collections.emptyList(),
                causalInfo.messageId, Collections.emptyList());
    }

    private ProcessReturn<AState> processAddAck(AState state, AccAddAckMessage ack, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo) {
        if (causalInfo.ackedMessageId == null) {
            throw new IllegalArgumentException("ackedMessageId is null for add-ack message");
        }

        Collection<MessageId> ackedMessageIds;
        if (!sender.equals(state.id)) {
            state.strongRemoveDGM.ack(sender, causalInfo.ackedMessageId);
            ackedMessageIds = Collections.singletonList(causalInfo.ackedMessageId);
        } else ackedMessageIds = Collections.emptyList();

        if (causalInfo.ackedMessageId.equals(state.addMessageId)) {
            // The acked message added us
            Pair<AState, byte[]> decryptionResult = decryptFrom(state, sender, ack.getPrfForAdded());
            state = decryptionResult.getLeft();
            state = state.putChainKey(sender, decryptionResult.getRight());
            //alain: compare ratchets
            if (!Arrays.equals(state.initialSeed, ack.getHash())){
                reveal();
            }
        }

        ForwardSecureEncryptionProtocol.Key updateSecret;
        if (state.strongRemoveDGM.queryView(sender).contains(state.id)) {
            Pair<AState, ForwardSecureEncryptionProtocol.Key> prngAdd = prng(state,
                    sender, "add".getBytes());
            state = prngAdd.getLeft();
            updateSecret = prngAdd.getRight();
        } else updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);

        return new ProcessReturn<>(state, DcgkaMessageType.OTHER, ControlMessage.of(null),
                updateSecret, null, Collections.emptyList(),
                Collections.emptyList(), causalInfo.messageId, ackedMessageIds);
    }

    private ProcessReturn<AState> processWelcome(AState state, WelcomeMessage welcome, IdentityKey sender,
                                                AckOrderer.Timestamp causalInfo) {
        StrongRemoveDgm strongRemoveDGM = StrongRemoveDgm.deserialize(welcome.getStrongRemoveDgm(), state.id)
                .getLeft();
        strongRemoveDGM.add(sender, state.id, causalInfo.messageId);
        state = state.setStrongRemoveDGM(strongRemoveDGM);
        state = state.setAddMessageId(causalInfo.messageId);
        // If the Welcome is not for us, two-party decryption will fail, so decrypt will throw an
        // IllegalArgumentException.  Thus we fulfill the condition stated in the Javadoc for
        // DcgkaProtocol.process.
        Pair<AState, byte[]> decryptReturn = decryptFrom(state, sender, welcome.getPrfForAdded());
        state = decryptReturn.getLeft();
        state = state.putChainKey(sender, decryptReturn.getRight());
        
        //alain: store received ratchet in state
        byte[] hash = Utils.hash(decryptReturn.getRight());
        state = state.putInitialSeed(hash);

        Pair<AState, ForwardSecureEncryptionProtocol.Key> prngWelcome = prng(state,
                sender, "welcome".getBytes());
        state = prngWelcome.getLeft();
        PuncturablePseudorandomFunction pprf = new PuncturablePseudorandomFunction(prngWelcome.getRight().getBytes(),
                Collections.singletonList(state.id.serialize()));
        state = state.putPprf(causalInfo.messageId, pprf);
        Pair<AState, ForwardSecureEncryptionProtocol.Key> prngAdd = prng(state,
                sender, "add".getBytes());
        state = prngAdd.getLeft();
        ForwardSecureEncryptionProtocol.Key updateSecret = prngAdd.getRight();

        AckMessage ack = new AckMessage(Collections.emptyMap());//alain: could include ratchet state received for others to check, better not, as it is used elsewehere
        AccountableDcgkaMessage ackWrapped = new AccountableDcgkaMessage(AccountableDcgkaMessageType.ACK,
                ByteBuffer.wrap(Utils.serialize(ack)), null);
        state = state.setLastAcked(causalInfo.messageId);

    
        return new ProcessReturn<>(state, DcgkaMessageType.WELCOME, ControlMessage.of(Utils.serialize(ackWrapped)),
                updateSecret, null, state.strongRemoveDGM.queryWhole(), Collections.emptyList(),
                causalInfo.messageId, Collections.emptySet());
    }

    /**
     * Generates a random secret, encrypts it for recipients in sorted order (skipping over state.id),
     * adds those encryptions to message (mutably), and stores the secret in an updated state,
     * which is returned.
     */
    private Triple<AState, ? extends List<ByteBuffer>, byte[]> generateSeedSecret(AState state, Collection<IdentityKey> recipients) {
        ArrayList<ByteBuffer> result = new ArrayList<>();
        byte[] secret = Utils.getSecureRandomBytes(Constants.KEY_SIZE_BYTES);
        byte[] hash = Utils.hash(secret);
        //todo: expose singature protocol in here: Signature signature = state.id.sign(secret);
        List<IdentityKey> sortedRecipients =
                recipients.stream().sorted().collect(Collectors.toList());
        for (IdentityKey recipient : sortedRecipients) {
            if (!recipient.equals(state.id)) {// skip me
                Pair<AState, byte[]> encryptReturn = encryptTo(state, recipient, secret);
                state = encryptReturn.getLeft();
                result.add(ByteBuffer.wrap(encryptReturn.getRight()));
            }
        }
        return Triple.of(state.setNextSeed(secret), result, hash);
    }

    private Pair<AState, byte[]> encryptTo(AState state, IdentityKey recipient, byte[] plaintext) {
        TwoPartyProtocol twoPartyProtocol = state.twoPartyProtocols.get(recipient);
        if (twoPartyProtocol == null) {
            twoPartyProtocol = new TwoPartyProtocol(state.preKeySecret, state.preKeySource, recipient);
        }
        Pair<TwoPartyProtocol, byte[]> encrypted = twoPartyProtocol.encrypt(plaintext);
        state = state.putTwoPartyProtocol(recipient, encrypted.getLeft());
        return Pair.of(state, encrypted.getRight());
    }

    /**
     * Here sendersView should be the same view of the group members that sender passed
     * to addSecret as recipients.  If sender is us, this will instead use sender.nextMessageSecret.
     */
    private Triple<AState, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecret(
            AState state, IdentityKey sender, MessageId messageId, List<ByteBuffer> ciphertexts, byte[] bcHash) {
        HashSet<IdentityKey> recipients = state.strongRemoveDGM.queryView(sender);
        recipients.remove(sender);

        byte[] seed;
        if (sender.equals(state.id)) {
            seed = state.nextSeed;
            state = state.setNextSeed(null);
        } else if (recipients.contains(state.id)) {
            // Count how many members are before me; that's my index
            int myIndex = 0;
            for (IdentityKey member : recipients) {
                if (!member.equals(sender) && member.compareTo(state.id) < 0) myIndex++;
            }
            Pair<AState, byte[]> decryptResult = decryptFrom(state, sender, Utils.asArray(ciphertexts.get(myIndex)));
            state = decryptResult.getLeft();
            seed = decryptResult.getRight();
        } else seed = null;

        ForwardSecureEncryptionProtocol.Key updateSecret;
        if (seed == null) updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);
        else {
            //compare seed received via DM with (hash of) seed broadcast
            byte[] dmHash = Utils.hash(seed);
            if (!Arrays.equals(bcHash, dmHash)) {
                reveal();
            }
            PuncturablePseudorandomFunction pprf = new PuncturablePseudorandomFunction(seed,
                    state.strongRemoveDGM.queryView(sender).stream().map(IdentityKey::serialize).collect(Collectors.toList()));
            Pair<PuncturablePseudorandomFunction, byte[]> chainUpdatePair = pprf.popValue(sender.serialize());
            state = state.putPprf(messageId, chainUpdatePair.getLeft());
            Pair<AState, ForwardSecureEncryptionProtocol.Key> prngResult = prng(state, sender, chainUpdatePair.getRight());
            state = prngResult.getLeft();
            updateSecret = prngResult.getRight();
        }

        AckMessage ack;
        if (sender.equals(state.id)) ack = null;
        else {
            Map<ByteBuffer, ByteBuffer> forwards;
            if (recipients.contains(state.id)) {
                // Forward my per-member secret to concurrently added users
                forwards = new HashMap<>();
                HashSet<IdentityKey> needsForwarding = state.strongRemoveDGM.queryWhole();
                needsForwarding.removeAll(recipients);
                needsForwarding.remove(sender);
                for (IdentityKey toForward : needsForwarding) {
                    // Note the pop doesn't do anything because we ignore the returned pprf
                    Pair<AState, byte[]> encryptionResult = encryptTo(state, toForward,
                            state.pprfs.get(messageId).popValue(state.id.serialize()).getRight());
                    state = encryptionResult.getLeft();
                    forwards.put(ByteBuffer.wrap(toForward.serialize()),
                            ByteBuffer.wrap(encryptionResult.getRight()));
                }
            } else forwards = Collections.emptyMap();
            ack = new AckMessage(forwards);
            state = state.setLastAcked(messageId);
        }

        return Triple.of(state, ack, updateSecret);
    }

    private void reveal() {
        System.err.println("Someone cheated!");
    }

    /* private ProcessReturn<AState> processReveal(AState state, RevealMessage reveal, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo) {
        return new ProcessReturn<AState>(todo);
    } */

    private Pair<AState, byte[]> decryptFrom(AState state, IdentityKey sender, byte[] ciphertext) {
        TwoPartyProtocol twoPartyProtocol = state.twoPartyProtocols.get(sender);
        if (twoPartyProtocol == null) {
            twoPartyProtocol = new TwoPartyProtocol(state.preKeySecret, state.preKeySource, sender);
        }
        Pair<TwoPartyProtocol, byte[]> decrypted = twoPartyProtocol.decrypt(ciphertext);
        if (decrypted == null) {
            throw new IllegalArgumentException("Failed to decrypt TwoPartyProtocol message from " + sender.hashCode());
        }
        state = state.putTwoPartyProtocol(sender, decrypted.getLeft());
        return Pair.of(state, decrypted.getRight());
    }

    private Pair<AState, ForwardSecureEncryptionProtocol.Key> prng(AState state, IdentityKey sender, byte[] chainUpdate) {
        // Combine chainUpdate.getRight() with current chain key to get keyUpdate and new chain key
        byte[] chainKey = state.prfPrngs.get(sender);
        byte[] keyUpdate;
        if (chainKey == null) {
            keyUpdate = Utils.hash("update", chainUpdate);
            chainKey = Utils.hash("chain", chainUpdate);
        } else {
            keyUpdate = Utils.hash("update", chainKey, chainUpdate);
            chainKey = Utils.hash("chain", chainKey, chainUpdate);
        }
        return Pair.of(state.putChainKey(sender, chainKey), ForwardSecureEncryptionProtocol.Key.of(keyUpdate));
    }

    private ArrayList<IdentityKey> deserializeIdList(List<ByteBuffer> ids) {
        ArrayList<IdentityKey> result = new ArrayList<>();
        for (ByteBuffer id : ids) {
            result.add(new IdentityKey(Utils.asArray(id)));
        }
        return result;
    }

    public Pair<AState, MessageId> getOrdererInput(AState state) {
        AState newAState = state;
        if (state.lastAcked != null) {
            // Set lackAcked to null so we only send each ack once.
            newAState = state.setLastAcked(null);
        }
        return Pair.of(newAState, state.lastAcked);
    }

    
    public Collection<IdentityKey> getMembers(AState state) {
        return state.strongRemoveDGM.queryWhole();
    }

    
    public Collection<IdentityKey> getMembersAndRemovedMembers(AState state) {
        return state.strongRemoveDGM.getMembersAndRemovedMembers();
    }

    public static class AState implements DcgkaProtocol.State {
        private final IdentityKey id;
        private final PreKeySecret preKeySecret;
        private final PreKeySource preKeySource;
        private final HashPMap<IdentityKey, TwoPartyProtocol> twoPartyProtocols;
        private final StrongRemoveDgm strongRemoveDGM; // TODO: make immutable
        private final HashPMap<MessageId, PuncturablePseudorandomFunction> pprfs;
        private final HashPMap<IdentityKey, byte[]> prfPrngs;
        private final MessageId addMessageId; // MessageId of our add message.  Null if we were added at group creation.
        private final MessageId createMessageId; // MessageId of the group creation message.  Null if we weren't an
        // initial member.
        private final MessageId lastAcked; // last message that was acked
        private final byte[] nextSeed; // the secret in a message we just generated
        // which should be processed next
        private final byte[] initialSeed; //our initial seed/the adders ratchet state when added

        public AState(IdentityKey id, PreKeySecret preKeySecret, PreKeySource preKeySource) {
            // membershipSet is initialized on welcome
            this.id = id;
            this.preKeySecret = preKeySecret;
            this.preKeySource = preKeySource;
            this.twoPartyProtocols = HashTreePMap.empty();
            this.strongRemoveDGM = StrongRemoveDgm.empty(id);
            this.pprfs = HashTreePMap.empty();
            this.prfPrngs = HashTreePMap.empty();
            this.addMessageId = null;
            this.createMessageId = null;
            this.lastAcked = null;
            this.nextSeed = null;
            this.initialSeed = null;
        }

        private AState(AState old,
                      HashPMap<IdentityKey, TwoPartyProtocol> twoPartyProtocols, StrongRemoveDgm strongRemoveDGM,
                      HashPMap<MessageId, PuncturablePseudorandomFunction> pprfs, HashPMap<IdentityKey, byte[]> prfPrngs,
                      MessageId addMessageId, MessageId createMessageId, MessageId lastAcked, byte[] nextSeed, byte[] initialSeed) {
            this.id = old.id;
            this.preKeySecret = old.preKeySecret;
            this.preKeySource = old.preKeySource;
            this.twoPartyProtocols = twoPartyProtocols;
            this.strongRemoveDGM = strongRemoveDGM;
            this.pprfs = pprfs;
            this.prfPrngs = prfPrngs;
            this.addMessageId = addMessageId;
            this.createMessageId = createMessageId;
            this.lastAcked = lastAcked;
            this.nextSeed = nextSeed;
            this.initialSeed = initialSeed;
        }

        private AState setStrongRemoveDGM(StrongRemoveDgm newStrongRemoveDgm) {
            return new AState(this, this.twoPartyProtocols, newStrongRemoveDgm,
                    this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId, this.lastAcked, this.nextSeed, this.initialSeed);
        }

        private AState setNextSeed(byte[] newNextMessageSecret) {
            return new AState(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId, this.lastAcked, newNextMessageSecret, this.initialSeed);
        }

        private AState setLastAcked(MessageId newLastAcked) {
            return new AState(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId, newLastAcked, this.nextSeed, this.initialSeed);
        }

        private AState setAddMessageId(MessageId newAddMessageId) {
            return new AState(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, newAddMessageId, this.createMessageId, this.lastAcked, this.nextSeed, this.initialSeed);
        }

        private AState setCreateMessageId(MessageId newCreateMessageId) {
            return new AState(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, this.addMessageId, newCreateMessageId, this.lastAcked, this.nextSeed, this.initialSeed);
        }

        private AState putPprf(MessageId messageId, PuncturablePseudorandomFunction newPprf) {
            return new AState(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs.plus(messageId, newPprf), this.prfPrngs, this.addMessageId, this.createMessageId,
                    this.lastAcked, this.nextSeed, this.initialSeed);
        }

        private AState putChainKey(IdentityKey member, byte[] newChainKey) {
            return new AState(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs.plus(member, newChainKey), this.addMessageId, this.createMessageId,
                    this.lastAcked, this.nextSeed, this.initialSeed);
        }

        private AState putTwoPartyProtocol(IdentityKey member, TwoPartyProtocol twoPartyProtocol) {
            return new AState(this, this.twoPartyProtocols.plus(member, twoPartyProtocol),
                    this.strongRemoveDGM, this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId,
                    this.lastAcked, this.nextSeed, this.initialSeed);
        }

        private AState putInitialSeed(byte[] hash) {
            return new AState(this, this.twoPartyProtocols,
                    this.strongRemoveDGM, this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId,
                    this.lastAcked, this.nextSeed, hash);
        }
    }
}
