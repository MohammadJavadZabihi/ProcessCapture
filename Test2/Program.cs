using ProcessCapture;
using ProcessCapture.Services;
using ProcessCapture.Services.Interface;

MonitoringService monitoringService = new MonitoringService();

var dic = new Dictionary<string, string>();

var result = await monitoringService.StartCaptureAsync("chrome");
foreach (var kvp in result)
{
    Console.WriteLine($"{kvp.Key}: {kvp.Value}");
    dic.Add(kvp.Key, kvp.Value);
}

Console.ReadKey();