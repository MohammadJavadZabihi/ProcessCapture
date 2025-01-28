
# MonitoringService

MonitoringService is a service for monitoring network traffic and processes related to a specific application. It uses SharpPcap to capture network packets and PacketDotNet to analyze them. It also uses system commands such as netstat and ipconfig to obtain network information.


## Deployment

You can install this package using one of the following methods:

1-Using .NET CLI

Run the following command in your terminal:
```bash
dotnet add package ProcessCapture
```
2-Using NuGet Package Manager in Visual Studio

Open Visual Studio.

Go to Tools > NuGet Package Manager > Manage NuGet Packages for Solution.

Search for ProcessCapture in the Browse tab.

Click Install to add it to your project.

After installation, you can integrate it into your application to monitor network traffic of specific processes.

## Usage/Examples

```csharp
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
```


## Output

```console
127.0.0.1: chrome
::1: chrome
```
