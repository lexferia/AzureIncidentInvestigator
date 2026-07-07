namespace AzureIncidentInvestigator;

public sealed record UserAgentRollup(string UserAgent, long RequestCount, long NotFoundCount);

public sealed record IpRollup(string IpBucket, long RequestCount);
