package org.trvedata.sgm;

import org.trvedata.sgm.AccountableDsgmClient.DcgkaChoice;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.crypto.IdentityKeyPair;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;
import org.trvedata.sgm.crypto.PreKeySecret;
import org.trvedata.sgm.misc.Logger;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

import static org.trvedata.sgm.AccountableMetricsCapturer.MetricCaptureResult;

public class AccountableEvaluationSimulation {

    private final CliEvaluation mArgs;

    public AccountableEvaluationSimulation(final CliEvaluation args) {
        mArgs = args;
        Logger.setLoggingLevel(Logger.Level.WARN);
    }

    public void run() throws InterruptedException {
        // test parameters
        final ArrayList<Integer> groupSizes = groupSizes(8, 128);
        final Operation[] operations = new Operation[]{Operation.MESSAGE, Operation.REMOVE, Operation.ADD, Operation.UPDATE};
        final int iterations = mArgs.iterations;

        // results parameters and collection
        final ArrayList<TestRunParameters> parameters = new ArrayList<>();
        final TestRunResults results = TestRunResults.empty();

        for (int i = 0; i < iterations; i++) {
            for (final int gs : groupSizes) {
                for (final Operation operation : operations) {
                    parameters.add(new TestRunParameters(gs, operation, DcgkaChoice.FULL));
                }
            }
        }
        Collections.shuffle(parameters, new Random(0));

        // warming up the JVM and JIT
        for (int i = 0; i < iterations; i++) {
            runTestCase(new TestRunParameters(10, Operation.UPDATE, DcgkaChoice.FULL));
        }
        System.out.println("warm-up finished");

        // actual execution
        for (int i = 0; i < parameters.size(); i++) {
            // add some time for the GC to run
            System.gc();
            Thread.sleep(1000);

            final TestRunResults result = runTestCase(parameters.get(i));
            results.add(result);

            final int threadCnt = Thread.getAllStackTraces().keySet().size();
            System.out.println((i) + "/" + parameters.size() + ": " + result.toString() + " #threads=" + threadCnt);

        }

        // output CSV
        if (mArgs.csvOutputFolder != null) {
            mArgs.csvOutputFolder.mkdirs();
            writeCsv(results.trafficMetrics, new File(mArgs.csvOutputFolder, "traffic.csv"));
            writeCsv(results.timeMetrics, new File(mArgs.csvOutputFolder, "time.csv"));
        }
    }

    private void writeCsv(final ArrayList<MetricCaptureResult> results, final File csvOutput) {
        try (final BufferedWriter outputWriter = new BufferedWriter(new FileWriter(csvOutput))) {
            outputWriter.write(results.get(0).getCsvHeader());
            outputWriter.newLine();

            for (final MetricCaptureResult result : results) {
                outputWriter.write(result.toCsvRow());
                outputWriter.newLine();
            }
        } catch (final IOException e) {
            throw new RuntimeException("Failed to write CSV output file", e);
        }
    }

    private ArrayList<Integer> groupSizes(final int fromIncl, final int toIncl) {
        final ArrayList<Integer> groupSizes = new ArrayList<>();
        final double multiplier = Math.sqrt(2);
        for (double gs = fromIncl; gs <= toIncl + 1; gs *= multiplier) {
            groupSizes.add((int) gs);
        }
        return groupSizes;
    }

    private TestRunResults runTestCase(final TestRunParameters params) throws InterruptedException {
        final ThreadSafeNetwork network = new ThreadSafeNetwork();
        final InMemoryPreKeySource preKeySource = new InMemoryPreKeySource();
        final ArrayList<AccountableThreadedClient> clients = createThreadedClients(network, preKeySource, params.groupsize, params.dcgkaChoice);

        final AccountableMetricsCapturer metrics = new AccountableMetricsCapturer(network, clients);

        // START
        for (AccountableThreadedClient client : clients) client.start();

        final ArrayList<IdentityKey> memberKeys = new ArrayList<>();
        for (final AccountableThreadedClient client : clients) memberKeys.add((IdentityKey) client.getIdentifier());

        final AccountableThreadedClient sender = clients.get(0);
        final ArrayList<AccountableThreadedClient> receivers = new ArrayList<>(clients.subList(1, clients.size())); // copy necessary

        // Make prekeys for a potential future added member now, since they should not count against the add time
        final IdentityKeyPair toAddKeyPair = IdentityKey.generateKeyPair();
        final PreKeySecret toAddPreKeySecret = preKeySource.registerUser(toAddKeyPair, params.groupsize + 1);

        // SETUP
        metrics.setupBegin();

        sender.createGroup(memberKeys);
        for (AccountableThreadedClient client : clients) client.waitUntilSetupFinished();

        // clients need to be stopped and restarted as the thread cpu time can only be read in "finished" thread state
        for (final AccountableThreadedClient client : clients) client.stop();
        for (final AccountableThreadedClient client : clients) client.join();
        metrics.setupEnd();
        for (final AccountableThreadedClient client : clients) client.start();

        // OPERATION
        for (final AccountableThreadedClient client : clients) client.clearNextOperation();
        metrics.operationBegin();

        switch (params.operation) {
            case MESSAGE:
                for (final AccountableThreadedClient client : receivers) client.expectNextOperation(1);// sender excluded
                sender.expectNextOperation(0);
                sender.sendMessage("0123456789ABCDEF0123456789ABCDEF"); // 32 byte e.g. AES key
                break;

            case ADD:
                for (final AccountableThreadedClient client : clients) client.expectNextOperation(params.groupsize);
                // Create added client ourselves instead of using DsgmClientFactory, so we can give it the
                // pre-made prekeys.
                final AccountableDsgmClient dsgmClient = new AccountableDsgmClient(network, toAddPreKeySecret, preKeySource, "NewMember",
                        toAddKeyPair, createClientImplementation(params.dcgkaChoice));
                final AccountableThreadedClient toBeAdded = new AccountableThreadedClient(dsgmClient, network, AccountableThreadedClient.ClientRole.RECIPIENT);

                toBeAdded.expectNextOperation(params.groupsize);
                toBeAdded.start();
                clients.add(toBeAdded);

                sender.addMember(toBeAdded);
                receivers.add(toBeAdded);
                break;

            case REMOVE:
                final AccountableThreadedClient toBeRemoved = receivers.get(0);
                for (final AccountableThreadedClient client : clients) {
                    if (client != toBeRemoved) client.expectNextOperation(params.groupsize - 2);
                }
                toBeRemoved.expectNextOperation(1);

                sender.removeMember(toBeRemoved);
                receivers.remove(toBeRemoved); // important as the removed client does not call `onRemove()`
                break;

            case UPDATE:
                for (final AccountableThreadedClient client : clients) client.expectNextOperation(params.groupsize - 1);
                sender.update();
                break;
        }

        for (final AccountableThreadedClient client : receivers) client.waitUntilNextOperationFinished(params.operation);// sender excluded
        sender.waitUntilNextOperationFinishedSender();

        // CLEAN-UP
        for (final AccountableThreadedClient client : clients) client.stop();
        for (final AccountableThreadedClient client : clients) client.join();
        metrics.operationEnd();

        return TestRunResults.fromMetricsCapturer(metrics, params);
    }


    private ArrayList<AccountableThreadedClient> createThreadedClients(final ThreadSafeNetwork network,
                                                            final InMemoryPreKeySource inMemoryPreKeySource,
                                                            final int gs,
                                                            final DcgkaChoice dcgkaChoice) {
        final AccountableDsgmClientFactory.DgmClientFactoryResult factoryResult = AccountableDsgmClientFactory.createClients(network,
                inMemoryPreKeySource, gs, createClientImplementation(dcgkaChoice));
        final ArrayList<AccountableThreadedClient> clients = new ArrayList<>(gs);
        for (int i = 0; i < gs; i++) {
            clients.add(new AccountableThreadedClient(factoryResult.clients[i], network, gs, i == 0 ? AccountableThreadedClient.ClientRole.SENDER : AccountableThreadedClient.ClientRole.RECIPIENT));
        }
        return clients;
    }

    private AccountableDsgmClient.DgmClientImplementationConfiguration createClientImplementation(final DcgkaChoice dcgkaChoice) {
        return new AccountableDsgmClient.DgmClientImplementationConfiguration(dcgkaChoice, true, true, true);
    }

    public static class TestRunParameters {
        public final int groupsize;
        public final Operation operation;
        public final DcgkaChoice dcgkaChoice;

        public TestRunParameters(final int groupsize, final Operation operation, final DcgkaChoice dcgkaChoice) {
            this.groupsize = groupsize;
            this.operation = operation;
            this.dcgkaChoice = dcgkaChoice;
        }
    }

    private static class TestRunResults {
        public final ArrayList<MetricCaptureResult> trafficMetrics = new ArrayList<>();
        public final ArrayList<MetricCaptureResult> timeMetrics = new ArrayList<>();

        private TestRunResults() {
        }

        public static TestRunResults empty() {
            return new TestRunResults();
        }


        public static TestRunResults fromMetricsCapturer(final AccountableMetricsCapturer metricsCapturer, final TestRunParameters params) {
            final TestRunResults instance = new TestRunResults();
            instance.trafficMetrics.add(metricsCapturer.getTrafficResults(params));
            instance.timeMetrics.addAll(metricsCapturer.getTimeResultsForClients(params));
            return instance;
        }

        public void add(final TestRunResults other) {
            this.trafficMetrics.addAll(other.trafficMetrics);
            this.timeMetrics.addAll(other.timeMetrics);
        }

        @Override
        public String toString() {
            return "TestRunResults{" + "trafficMetrics=" + trafficMetrics + ", #timeMetrics=" + timeMetrics.size() + '}';
        }
    }
}
