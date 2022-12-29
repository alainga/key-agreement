package org.trvedata.sgm;

import org.trvedata.sgm.communication.Network;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.crypto.IdentityKeyPair;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;
import org.trvedata.sgm.crypto.PreKeySecret;

import java.util.HashMap;

public class AccountableDsgmClientFactory {

    private AccountableDsgmClientFactory() {
    }

    public static AccountableDsgmClient createClient(final Network network, final InMemoryPreKeySource inMemoryPreKeySource,
                                          final String name) {
        return createClients(network, inMemoryPreKeySource, name).clients[0];
    }

    public static AccountableDsgmClient createClient(final Network network, final InMemoryPreKeySource inMemoryPreKeySource,
    AccountableDsgmClient.DgmClientImplementationConfiguration implementationConfiguration,
                                          final String name) {
        return createClients(network, inMemoryPreKeySource, implementationConfiguration, name).clients[0];
    }

    /**
     * Creates the given number of {@link DsgmClient} for the provided network. They will be completely initialized
     * including the {@link InMemoryPreKeySource}.
     * The second part of the return value maps the created client's
     * {@link IdentityKey}'s to their names.
     */
    public static DgmClientFactoryResult createClients(final Network network,
                                                       final InMemoryPreKeySource inMemoryPreKeySource,
                                                       final int numberClients) {
        return createClients(network, inMemoryPreKeySource, numberClients, AccountableDsgmClient.DgmClientImplementationConfiguration.full()
        );
    }

    /**
     * Generalized version for testing with partially trivial protocol components.
     */
    public static DgmClientFactoryResult createClients(final Network network,
                                                       final InMemoryPreKeySource inMemoryPreKeySource, final int numberClients,
                                                       final AccountableDsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        final String[] names = new String[numberClients];
        for (int i = 0; i < numberClients; i++) {
            names[i] = "Client_" + i;
        }
        return createClients(network, inMemoryPreKeySource, implementationConfiguration, names);
    }

    /**
     * Creates {@link DsgmClient} with the given names for the provided network. They will be completely initialized
     * including the {@link InMemoryPreKeySource}.
     */
    public static DgmClientFactoryResult createClients(final Network network,
                                                       final InMemoryPreKeySource inMemoryPreKeySource,
                                                       final String... names) {
        return createClients(network, inMemoryPreKeySource, AccountableDsgmClient.DgmClientImplementationConfiguration.full(), names);
    }

    /**
     * Generalized version for testing with partially trivial protocol components.
     */
    public static DgmClientFactoryResult createClients(final Network network,
                                                       final InMemoryPreKeySource inMemoryPreKeySource,
                                                       final AccountableDsgmClient.DgmClientImplementationConfiguration implementationConfiguration,
                                                       final String... names) {
        HashMap<IdentityKey, String> namesMap = new HashMap<>();
        final AccountableDsgmClient[] clients = new AccountableDsgmClient[names.length];
        for (int i = 0; i < names.length; i++) {
            final IdentityKeyPair identityKeyPair = IdentityKey.generateKeyPair();
            PreKeySecret preKeySecret = inMemoryPreKeySource.registerUser(identityKeyPair, names.length + 1);
            clients[i] = new AccountableDsgmClient(network, preKeySecret, inMemoryPreKeySource, names[i], identityKeyPair, implementationConfiguration);
            namesMap.put(identityKeyPair.getPublicKey(), names[i]);
        }
        return new DgmClientFactoryResult(clients, namesMap);
    }

    public static class DgmClientFactoryResult {
        public final AccountableDsgmClient[] clients;
        public final HashMap<IdentityKey, String> identityKeyToName;

        public DgmClientFactoryResult(final AccountableDsgmClient[] clients, final HashMap<IdentityKey, String> identityKeyToName) {
            this.clients = clients;
            this.identityKeyToName = identityKeyToName;
        }
    }
}
