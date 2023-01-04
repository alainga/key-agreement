package org.trvedata.sgm;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

class AccountableMetricsCapturer {

    private final Metric setupSentBytes = new TrafficMetric("setupsentbytes");
    private final Metric operationSentBytes = new TrafficMetric("operationsentbytes");

    private final Map<AccountableThreadedClient, TimeMetric> setupTimes = new HashMap<>();
    private final Map<AccountableThreadedClient, TimeMetric> operationTimes = new HashMap<>();

    private final ThreadSafeNetwork mNetwork;
    private final Collection<AccountableThreadedClient> mClients;

    public AccountableMetricsCapturer(final ThreadSafeNetwork network, final Collection<AccountableThreadedClient> clients) {
        mNetwork = network;
        mClients = clients;
        for (final AccountableThreadedClient client : mClients) {
            setupTimes.put(client, new TimeMetric("setuptime"));
            operationTimes.put(client, new TimeMetric("operationtime"));
        }
    }

    public void setupBegin() {
        for (final AccountableThreadedClient client : mClients) setupTimes.get(client).startValue = 0L;
        setupSentBytes.startValue = mNetwork.getSentBytes();
    }

    public void setupEnd() {
        for (final AccountableThreadedClient client : mClients) setupTimes.get(client).endValue = client.getCpuTime();
        setupSentBytes.endValue = mNetwork.getSentBytes();
    }

    public void operationBegin() {
        for (final AccountableThreadedClient client : mClients) operationTimes.get(client).startValue = 0L;
        operationSentBytes.startValue = mNetwork.getSentBytes();
    }

    public void operationEnd() {
        for (final AccountableThreadedClient client : mClients) {
            if (operationTimes.get(client) != null) operationTimes.get(client).endValue = client.getCpuTime();
        }
        operationSentBytes.endValue = mNetwork.getSentBytes();
    }

    public MetricCaptureResult getTrafficResults(final AccountableEvaluationSimulation.TestRunParameters params) {
        return new MetricCaptureResult(params, null, setupSentBytes, operationSentBytes);
    }

    public ArrayList<MetricCaptureResult> getTimeResultsForClients(final AccountableEvaluationSimulation.TestRunParameters params) {
        final ArrayList<MetricCaptureResult> results = new ArrayList<>();
        for (final AccountableThreadedClient client : mClients) {
            if (setupTimes.get(client) != null && operationTimes.get(client) != null) {
                results.add(new MetricCaptureResult(params, client.getRole(), setupTimes.get(client), operationTimes.get(client)));
            }
        }
        return results;
    }

    public abstract static class Metric {
        public final String name;
        public long startValue = -1L;
        public long endValue = -1L;

        private Metric(final String name) {
            this.name = name;
        }

        public abstract double getValue();
    }

    /**
     * Captures in nano seconds, returns in milliseconds
     */
    public static class TimeMetric extends Metric {
        public static final double NS_IN_MS = 1_000_000.0;

        private TimeMetric(String name) {
            super(name);
        }

        public double getValue() {
            if (startValue < 0 || endValue < 0) throw new IllegalStateException();
            return (endValue - startValue) / NS_IN_MS;
        }
    }

    public static class TrafficMetric extends Metric {

        private TrafficMetric(String name) {
            super(name);
        }

        public double getValue() {
            if (startValue < 0 || endValue < 0) throw new IllegalStateException();
            return endValue - startValue;
        }
    }

    public static class MetricCaptureResult {
        public final AccountableEvaluationSimulation.TestRunParameters params;
        private final AccountableThreadedClient.ClientRole clientRole;
        private final Metric[] metrics;

        private MetricCaptureResult(
                final AccountableEvaluationSimulation.TestRunParameters params,
                final AccountableThreadedClient.ClientRole clientRole,
                final Metric... metrics) {
            this.params = params;
            this.clientRole = clientRole;
            this.metrics = metrics;
        }

        public String getCsvHeader() {
            final StringBuilder sb = new StringBuilder();
            sb.append("groupsize,protocol,operation");
            if (clientRole != null) sb.append(",clientrole");
            for (final Metric metric : metrics) sb.append(',').append(metric.name);
            return sb.toString();
        }

        @Override
        public String toString() {
            return getCsvHeader() + " -> " + toCsvRow();
        }

        public String toCsvRow() {
            final StringBuilder sb = new StringBuilder();
            sb.append(params.groupsize).append(',').append(params.dcgkaChoice).append(',').append(params.operation.opcode);
            if (clientRole != null) sb.append(',').append(clientRole);
            for (final Metric metric : metrics) sb.append(',').append(metric.getValue());
            return sb.toString();
        }
    }

}
