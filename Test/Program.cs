using ProcessCapture.Services;

MonitoringService monitoringService = new MonitoringService();

var dic = new Dictionary<string, string>();

monitoringService.OnCaptureCompleted += (result) =>
{
    Console.WriteLine("Capture completed. Results:");
    foreach (var kvp in result)
    {
        Console.WriteLine($"{kvp.Key}: {kvp.Value}");
        dic.Add(kvp.Key, kvp.Value);
    }
};

var result = await monitoringService.StartCaptureAsync("chrome");


Console.ReadKey();