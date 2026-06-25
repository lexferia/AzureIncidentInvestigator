using Azure.Monitor.Query.Models;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Infrastructure.AzureMonitor;

internal static class MetricsHelpers
{
    public static TimeSpan PickGrain(TimeWindow w)
    {
        var hours = w.Duration.TotalHours;
        return hours <= 6 ? TimeSpan.FromMinutes(1)
             : hours <= 24 ? TimeSpan.FromMinutes(5)
             : TimeSpan.FromMinutes(15);
    }

    public static MetricSeries ToSeries(MetricResult metric, MetricAggregationType agg)
    {
        var points = metric.TimeSeries
            .SelectMany(ts => ts.Values)
            .Select(v => new MetricPoint(
                v.TimeStamp,
                agg switch
                {
                    MetricAggregationType.Average => v.Average ?? 0,
                    MetricAggregationType.Maximum => v.Maximum ?? 0,
                    MetricAggregationType.Minimum => v.Minimum ?? 0,
                    MetricAggregationType.Total => v.Total ?? 0,
                    MetricAggregationType.Count => v.Count ?? 0,
                    _ => 0
                }))
            .OrderBy(p => p.AtUtc)
            .ToList();
        return new MetricSeries(metric.Name, metric.Unit.ToString(), points);
    }

    public static MetricSummary Summarize(MetricSeries series, double threshold)
    {
        if (series.Points.Count == 0)
        {
            return new MetricSummary(0, 0, 0, 0, null);
        }
        var values = series.Points.Select(p => p.Value).OrderBy(v => v).ToList();
        var avg = values.Average();
        var max = values.Max();
        var p95Idx = (int)Math.Floor(values.Count * 0.95);
        var p95 = values[Math.Min(p95Idx, values.Count - 1)];
        var minutesOver = series.Points.Count(p => p.Value > threshold);
        var hottest = series.Points.OrderByDescending(p => p.Value).First().AtUtc;
        return new MetricSummary(avg, p95, max, minutesOver, hottest);
    }

    public static InstanceCountAnalysis AnalyzeInstanceCount(MetricSeries series)
    {
        if (series.Points.Count == 0)
        {
            return new InstanceCountAnalysis(0, 0, Array.Empty<ScaleEvent>());
        }

        var pts = series.Points.OrderBy(p => p.AtUtc).ToList();
        var events = new List<ScaleEvent>();
        for (int i = 1; i < pts.Count; i++)
        {
            var from = (int)Math.Round(pts[i - 1].Value);
            var to = (int)Math.Round(pts[i].Value);
            if (from != to)
            {
                events.Add(new ScaleEvent(pts[i].AtUtc, from, to,
                    to > from ? ScaleDirection.Up : ScaleDirection.Down));
            }
        }
        return new InstanceCountAnalysis(
            (int)Math.Round(pts[0].Value),
            (int)Math.Round(pts[^1].Value),
            events);
    }

    public static Verdict ComputeVerdict(MetricSummary cpu, MetricSummary memory, double cpuWarn, double memoryWarn)
    {
        if (cpu.Max >= 95 || memory.Max >= 95)
        {
            return Verdict.Saturated;
        }
        if (cpu.Avg >= cpuWarn || memory.Avg >= memoryWarn)
        {
            return Verdict.Degraded;
        }
        return Verdict.Healthy;
    }
}
