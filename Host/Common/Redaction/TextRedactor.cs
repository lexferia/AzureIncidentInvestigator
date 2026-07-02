using System.Text.RegularExpressions;

namespace AzureIncidentInvestigator;

public sealed partial class TextRedactor : ITextRedactor
{
    private const int MaxLength = 2048;
    private int _count;

    public int LastRedactionCount => _count;
    public void ResetCount() => _count = 0;

    [GeneratedRegex(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.Compiled)]
    private static partial Regex EmailRegex();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", RegexOptions.Compiled)]
    private static partial Regex JwtRegex();

    [GeneratedRegex(@"Bearer\s+[A-Za-z0-9_\-\.=]+", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex BearerRegex();

    [GeneratedRegex(@"\b(AccountKey|Password|SharedAccessKey|SharedAccessSignature|ApiKey)=([^;&\s]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex ConnStringRegex();

    [GeneratedRegex(@"\b((?:\d{1,3}\.){3})\d{1,3}\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"([?&](?:key|token|password|secret|sig|signature|code)=)([^&\s]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex UrlQueryRegex();

    [GeneratedRegex(@"\b[A-Fa-f0-9]{32,}\b|\b[A-Za-z0-9+/]{32,}={0,2}\b", RegexOptions.Compiled)]
    private static partial Regex SecretRegex();

    [GeneratedRegex(@"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", RegexOptions.Compiled)]
    private static partial Regex ControlCharsRegex();

    public string Redact(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input ?? string.Empty;
        }

        var s = input;
        s = ReplaceAndCount(EmailRegex(), s, "<email>");
        s = ReplaceAndCount(JwtRegex(), s, "<jwt>");
        s = ReplaceAndCount(BearerRegex(), s, "Bearer <token>");
        s = ReplaceAndCount(ConnStringRegex(), s, m => $"{m.Groups[1].Value}=<redacted>");
        s = ReplaceAndCount(UrlQueryRegex(), s, m => $"{m.Groups[1].Value}<redacted>");
        s = ReplaceAndCount(Ipv4Regex(), s, m => $"{m.Groups[1].Value}x");
        s = ReplaceAndCount(SecretRegex(), s, "<secret>");
        return s;
    }

    public SanitizedString Wrap(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return SanitizedString.Empty;
        }
        var stripped = ControlCharsRegex().Replace(input, string.Empty);
        var redacted = Redact(stripped);
        if (redacted.Length > MaxLength)
        {
            redacted = redacted[..MaxLength];
        }
        return new SanitizedString(redacted);
    }

    private string ReplaceAndCount(Regex regex, string input, string replacement)
    {
        var matches = regex.Matches(input);
        if (matches.Count == 0)
        {
            return input;
        }
        _count += matches.Count;
        return regex.Replace(input, replacement);
    }

    private string ReplaceAndCount(Regex regex, string input, MatchEvaluator evaluator)
    {
        var matches = regex.Matches(input);
        if (matches.Count == 0)
        {
            return input;
        }
        _count += matches.Count;
        return regex.Replace(input, evaluator);
    }
}
