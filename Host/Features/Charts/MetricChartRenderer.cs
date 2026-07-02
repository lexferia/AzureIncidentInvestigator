using ScottPlot;
using ScottPlot.TickGenerators;
using Color = ScottPlot.Color;

namespace AzureIncidentInvestigator;

/// <summary>
/// Renders multi-series time-line charts in an Azure-portal-style dark theme,
/// adapted from the original ServerHealthCheckStatusReportJob.Generators.GraphGenerator.
/// Producer of bytes only — no I/O, no validation, no Azure calls.
/// </summary>
internal static class MetricChartRenderer
{
    public readonly record struct RenderSeries(string Label, DateTime[] XValues, double[] YValues, Color LineColor);

    private const string DarkBackgroundColorHex = "#111111";
    private const string ForegroundColorHex = "#f6f6f6";
    private const string GridLineColorHex = "#525252";
    private const string AxesColorHex = "#eeeeee";
    private const string XAxisLabel = "UTC";
    private const int Width = 1800;
    private const int Height = 500;

    // Distinct, accessible palette — kept short on purpose; rotated when series exceed length.
    private static readonly Color[] Palette =
    {
        Color.FromHex("#3aa0ff"),
        Color.FromHex("#ff8a3d"),
        Color.FromHex("#21d07a"),
        Color.FromHex("#c977ff"),
        Color.FromHex("#ffd166"),
        Color.FromHex("#ef476f")
    };

    public static Color PaletteColor(int index) => Palette[index % Palette.Length];

    public static byte[] RenderPng(string title, ChartValueType valueType, IReadOnlyList<RenderSeries> series)
    {
        using var plot = new Plot();

        foreach (var s in series)
        {
            var scatter = plot.Add.Scatter(s.XValues, s.YValues, s.LineColor);
            scatter.MarkerShape = MarkerShape.None;
            scatter.LineWidth = 1.5f;
            scatter.LegendText = s.Label;
        }

        ApplyTheme(plot, title);
        ConfigureYAxis(plot, valueType);
        ConfigureXAxis(plot, series);

        return plot.GetImageBytes(Width, Height, ImageFormat.Png);
    }

    private static void ApplyTheme(Plot plot, string title)
    {
        plot.Title(title, 18);
        plot.DataBackground.Color = Color.FromHex(DarkBackgroundColorHex);
        plot.FigureBackground.Color = Color.FromHex(DarkBackgroundColorHex);
        plot.XLabel(XAxisLabel, 12);
        plot.Axes.FrameColor(Color.FromHex(AxesColorHex));
        plot.Axes.Frame(false);
        plot.Axes.Margins(horizontal: 0.05);

        var style = new PlotStyle
        {
            FigureBackgroundColor = Color.FromHex(DarkBackgroundColorHex),
            DataBackgroundColor = Color.FromHex(DarkBackgroundColorHex),
            AxisColor = Color.FromHex(ForegroundColorHex)
        };
        plot.SetStyle(style);

        plot.Grid.LineColor = Color.FromHex(GridLineColorHex);
        plot.Grid.IsVisible = true;
        plot.Grid.MajorLinePattern = LinePattern.Solid;
        plot.Grid.XAxisStyle.MajorLineStyle = LineStyle.None;

        plot.Legend.IsVisible = true;
        plot.Legend.Orientation = Orientation.Horizontal;
        plot.Legend.BackgroundColor = Color.FromHex(DarkBackgroundColorHex);
        plot.Legend.OutlineColor = Color.FromHex(DarkBackgroundColorHex);
        plot.Legend.ShadowColor = Color.FromHex(DarkBackgroundColorHex);
        plot.Legend.FontColor = Color.FromHex(ForegroundColorHex);
        plot.Legend.Alignment = Alignment.MiddleLeft;
        plot.Legend.FontSize = 14;
        plot.Legend.OutlinePattern = LinePattern.DenselyDashed;
        plot.ShowLegend(Edge.Bottom);
    }

    private static void ConfigureYAxis(Plot plot, ChartValueType valueType)
    {
        var allYs = plot.GetPlottables()
            .OfType<IScatterSource>()
            .SelectMany(s => s.GetScatterPoints().Select(p => p.Y))
            .ToArray();

        if (allYs.Length > 0)
        {
            var maxY = allYs.Max();
            var paddedMax = Math.Ceiling(maxY * 1.1);
            plot.Axes.Margins(vertical: 0);
            plot.Axes.SetLimitsY(0, paddedMax);
        }

        plot.Axes.Left.TickGenerator = valueType switch
        {
            ChartValueType.Percentage => new NumericAutomatic { LabelFormatter = val => $"{val:F0}%" },
            _ => new NumericAutomatic { LabelFormatter = val => FormatCount(val) }
        };
    }

    private static void ConfigureXAxis(Plot plot, IReadOnlyList<RenderSeries> series)
    {
        plot.Axes.Bottom.TickGenerator = new DateTimeAutomatic();

        plot.RenderManager.RenderStarting += (_, _) =>
        {
            var ticks = plot.Axes.Bottom.TickGenerator.Ticks;
            var distinctDates = GetDistinctXDates(series);
            var firstTickByDate = GetFirstTickPositionByDate(distinctDates, ticks);

            for (var i = 0; i < ticks.Length; i++)
            {
                if (distinctDates.Length > 1 && i < ticks.Length - 1)
                {
                    ticks[i] = TickByDate(firstTickByDate, ticks[i]);
                    continue;
                }
                ticks[i] = TickByHour(ticks[i]);
            }
        };
    }

    private static Tick TickByDate(Dictionary<double, DateOnly> firstTickByDate, Tick current) =>
        firstTickByDate.TryGetValue(current.Position, out var date)
            ? new Tick(current.Position, date.ToString("MMM d"))
            : new Tick(current.Position, string.Empty);

    private static Tick TickByHour(Tick current) =>
        DateTime.TryParse(current.Label, out var dt)
            ? new Tick(current.Position, dt.ToString("HH:mm"))
            : current;

    private static DateOnly[] GetDistinctXDates(IReadOnlyList<RenderSeries> series) =>
        series.SelectMany(s => s.XValues)
              .Select(DateOnly.FromDateTime)
              .Distinct()
              .OrderBy(d => d)
              .ToArray();

    private static Dictionary<double, DateOnly> GetFirstTickPositionByDate(DateOnly[] distinctDates, Tick[] ticks)
    {
        var result = new Dictionary<double, DateOnly>();
        foreach (var date in distinctDates)
        {
            foreach (var tick in ticks)
            {
                if (DateTime.TryParse(tick.Label, out var dt) && DateOnly.FromDateTime(dt).Equals(date))
                {
                    result[tick.Position] = date;
                    break;
                }
            }
        }
        return result;
    }

    private static string FormatCount(double v) => v switch
    {
        >= 1_000_000 => $"{v / 1_000_000:F1}M",
        >= 1_000 => $"{v / 1_000:F1}k",
        _ => $"{v:F0}"
    };
}
