using System.Diagnostics.Metrics;

using b17s.Porta.Telemetry;

namespace b17s.Porta.Tests.Telemetry;

/// <summary>
/// Shared test harness that builds a <see cref="PortaMetrics"/> over an isolated meter and captures
/// every measurement emitted to it, so wiring tests across the suite can assert that production code
/// actually records the expected instruments. Matches the harness's own meter by reference (not by
/// name) so emissions from other <see cref="PortaMetrics"/> instances running in parallel tests are
/// not captured.
/// </summary>
internal sealed class RecordingMetricsHarness : IDisposable
{
    public PortaMetrics Metrics { get; }

    private readonly MeterListener _listener;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Concurrent.ConcurrentQueue<Measurement>> _measurements = new();

    private RecordingMetricsHarness(PortaMetrics metrics, MeterListener listener)
    {
        Metrics = metrics;
        _listener = listener;
    }

    public static RecordingMetricsHarness Create()
    {
        var factory = new HarnessMeterFactory();
        var metrics = new PortaMetrics(factory);

        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (factory.Created.Contains(instrument.Meter))
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };

        var harness = new RecordingMetricsHarness(metrics, listener);
        listener.SetMeasurementEventCallback<long>(harness.OnLong);
        listener.SetMeasurementEventCallback<double>(harness.OnDouble);
        listener.Start();
        return harness;
    }

    private void OnLong(Instrument instrument, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
        => Record(instrument.Name, value, tags);

    private void OnDouble(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
        => Record(instrument.Name, value, tags);

    private void Record(string name, object value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var dict = new Dictionary<string, object?>(tags.Length);
        foreach (var t in tags)
        {
            dict[t.Key] = t.Value;
        }
        _measurements.GetOrAdd(name, _ => new()).Enqueue(new Measurement(value, dict));
    }

    /// <summary>Drains (removes and returns) all measurements captured for the named instrument.</summary>
    public IReadOnlyList<Measurement> Drain(string instrumentName)
    {
        if (!_measurements.TryGetValue(instrumentName, out var queue))
        {
            return Array.Empty<Measurement>();
        }
        var snapshot = new List<Measurement>();
        while (queue.TryDequeue(out var m))
        {
            snapshot.Add(m);
        }
        return snapshot;
    }

    /// <summary>Net sum of long measurements for an UpDownCounter (e.g. <c>bff.sessions.active</c>).</summary>
    public long Net(string instrumentName) => Drain(instrumentName).Sum(m => Convert.ToInt64(m.Value));

    public void Dispose() => _listener.Dispose();

    internal sealed record Measurement(object Value, IReadOnlyDictionary<string, object?> Tags);

    private sealed class HarnessMeterFactory : IMeterFactory
    {
        public List<Meter> Created { get; } = [];

        public Meter Create(MeterOptions options)
        {
            var meter = new Meter(options);
            Created.Add(meter);
            return meter;
        }

        public void Dispose()
        {
            foreach (var m in Created)
            {
                m.Dispose();
            }
        }
    }
}
