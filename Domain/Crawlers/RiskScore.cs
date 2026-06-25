namespace AzureIncidentInvestigator.Domain.Crawlers;

public enum RiskBucket { Benign, Noisy, Suspicious }

public sealed record RiskScore(int Value, RiskBucket Bucket)
{
    public static RiskScore From(int rawScore)
    {
        var clamped = Math.Clamp(rawScore, 0, 100);
        var bucket = clamped switch
        {
            < 30 => RiskBucket.Benign,
            < 60 => RiskBucket.Noisy,
            _ => RiskBucket.Suspicious
        };
        return new RiskScore(clamped, bucket);
    }
}
