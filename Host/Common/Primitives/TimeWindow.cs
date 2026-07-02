namespace AzureIncidentInvestigator;

public readonly struct TimeWindow : IEquatable<TimeWindow>
{
    public DateTimeOffset StartUtc { get; }
    public DateTimeOffset EndUtc { get; }

    public TimeWindow(DateTimeOffset startUtc, DateTimeOffset endUtc)
    {
        if (endUtc <= startUtc)
        {
            throw new ArgumentException("End must be after start.", nameof(endUtc));
        }
        StartUtc = startUtc;
        EndUtc = endUtc;
    }

    public TimeSpan Duration => EndUtc - StartUtc;

    public bool Equals(TimeWindow other) => StartUtc == other.StartUtc && EndUtc == other.EndUtc;
    public override bool Equals(object? obj) => obj is TimeWindow other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(StartUtc, EndUtc);
    public static bool operator ==(TimeWindow left, TimeWindow right) => left.Equals(right);
    public static bool operator !=(TimeWindow left, TimeWindow right) => !left.Equals(right);
}
