using PacketDotNet;
using ProcessCapture.Services.Interface;
using SharpPcap;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ProcessCapture.Services
{
    public class MonitoringService : IMonitoringService
    {
        private Dictionary<string, string> resultOfProgram = new Dictionary<string, string>();
        public event Action<Dictionary<string, string>> OnCaptureCompleted;


        /// <summary>
        /// Retrieves a list of available network capture devices.
        /// </summary>
        /// <returns>
        /// Adaptors, example : OpenVpn Adaptor, Local Area Connection, Etherenet4, ...
        /// </returns>
        
        public CaptureDeviceList GetCaptureDevices()
        {
            return CaptureDeviceList.Instance;
        }


        /// <summary>
        ///  Gets local IP addresses from ipconfig command.
        /// </summary>

        public List<string> GetLocalIpAddress()
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c ipconfig",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };

            var process = Process.Start(processInfo);
            string outpute = process.StandardOutput.ReadToEnd();

            List<string> ipAddresses = new List<string>();
            string ipPattern = @"\b(?:\d{1,3}\.){3}\d{1,3}\b";

            string[] lines = outpute.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string line in lines)
            {
                Match match = Regex.Match(line, ipPattern);
                if (match.Success)
                {
                    ipAddresses.Add(match.Value);
                }
            }

            return ipAddresses;
        }


        /// <summary>
        /// Retrieves process ID by process name.
        /// </summary>
        /// <param name="processName"></param>
        /// <param name="loop">If the loop is true, the loop will repeat until it finally finds the process. Otherwise, it will only do this once.</param>
        /// <param name="time">You can set a timeout for any loop that tries to find the process when the process is unavailable or does not exist.</param>

        public Dictionary<HashSet<int>, string> GetProcessIdByName(string processName, bool loop = false, int time = 0)
        {
            try
            {
                var pIds = new HashSet<int>();

                if (!string.IsNullOrEmpty(processName))
                {
                    var processes = Process.GetProcessesByName(processName).ToList();

                    if (loop)
                    {
                        do
                        {
                            Thread.Sleep(time);

                            processes = Process.GetProcessesByName(processName).ToList();

                            if (processes.Count <= 0)
                            {
                                return new Dictionary<HashSet<int>, string> { { new HashSet<int>(), "No processes found." } };
                            }
                        } while (processes.Count > 0);

                        foreach (var process in processes)
                        {
                            pIds.Add(process.Id);
                        }

                        return new Dictionary<HashSet<int>, string> { { pIds, "Process IDs retrieved successfully." } };
                    }

                    if (processes.Count != 0)
                    {
                        foreach (var process in processes)
                        {
                            pIds.Add(process.Id);
                        }
                        return new Dictionary<HashSet<int>, string> { { pIds, "Process IDs retrieved successfully." } };
                    }

                    return new Dictionary<HashSet<int>, string> { { pIds, "No processes found." } };
                }

                return new Dictionary<HashSet<int>, string> { { pIds, "Invalid process name." } };
            }
            catch (Exception ex)
            {
                return new Dictionary<HashSet<int>, string> { { new HashSet<int>(), $"Unknown error : {ex.Message}"} };
            }
        }

        /// <summary>
        /// Retrieves network ports used by a set of process IDs.
        /// </summary>
        /// <param name="pIds">We pass the ids we obtained from the GetProcessIdByName method to it so that we can obtain the network ports related to the process.</param>

        public HashSet<int> GetProcessPortByProcessId(HashSet<int> pIds)
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            var process = Process.Start(processInfo);
            string outePut = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            var ports = new HashSet<int>();

            foreach(var pid in pIds)
            {
                var lines = outePut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Where(line => line.Contains($"{pid}"));
                foreach(var line in lines)
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if(parts.Length >= 4)
                    {
                        var addressLocalPort = parts[1];
                        var portStringLocal = addressLocalPort.Split(':').Last();

                        var addressRemotePort = parts[2];
                        var portStringRemote = addressRemotePort.Split(":").Last();

                        if(int.TryParse(portStringLocal, out int localPort))
                        {
                            ports.Add(localPort);
                        }
                        if(int.TryParse(portStringRemote, out int remotePort))
                        {
                            ports.Add(remotePort);
                        }
                    }
                }
            }

            return ports;
        }


        /// <summary>
        /// Retrieves network ports used by a set of process IDs.
        /// </summary>
        /// <param name="pId">Instead of passing a set of process ids, we just pass an id to get the port of a process.</param>

        public HashSet<int> GetProcessPortByProcessId(int pId)
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            var process = Process.Start(processInfo);
            string outePut = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            var ports = new HashSet<int>();

            var lines = outePut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Where(line => line.Contains($"{pId}"));
            foreach (var line in lines)
            {
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4)
                {
                    var addressLocalPort = parts[1];
                    var portStringLocal = addressLocalPort.Split(':').Last();

                    var addressRemotePort = parts[2];
                    var portStringRemote = addressRemotePort.Split(":").Last();

                    if (int.TryParse(portStringLocal, out int localPort))
                    {
                        ports.Add(localPort);
                    }
                    if (int.TryParse(portStringRemote, out int remotePort))
                    {
                        ports.Add(remotePort);
                    }
                }
            }

            return ports;
        }


        /// <summary>
        /// Handles the arrival of network packets and processes them based on the specified criteria.
        /// This function extracts UDP or TCP packets, retrieves their source and destination IPs and ports,
        /// and stores the destination IPs in a dictionary if they match the given port conditions.
        /// </summary>
        /// <param name="e">The captured network packet.</param>
        /// <param name="ports">A set of ports to filter the packets.</param>
        /// <param name="pId">A set of process IDs associated with the packets.</param>
        /// <param name="processName">The name of the process associated with the packet (optional).</param>
        /// <param name="pack">The type of packet to process (UDP or TCP). If empty, both are processed.</param>

        public void OnPacketArrival(PacketCapture e, HashSet<int>? ports, HashSet<int> pId, string processName = "", string pack = "")
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            if(pack == "UDP")
            {
                var udpPacket = packet.Extract<UdpPacket>();

                if(udpPacket != null)
                {
                    var ipPack = udpPacket.ParentPacket as IPPacket;
                    if(ipPack != null)
                    {
                        var sourceIp = ipPack.SourceAddress;
                        var sourcePort = udpPacket.SourcePort;

                        var destenationIp = ipPack.DestinationAddress;
                        var destenationPort = udpPacket.DestinationPort;

                        if (ports.Contains(sourcePort) || ports.Contains(destenationPort))
                        {
                            if(sourceIp != null && destenationIp != null)
                            {
                                if (!resultOfProgram.Keys.Contains(destenationIp.ToString()))
                                {
                                    resultOfProgram.Add(destenationIp.ToString(), processName);
                                    Console.WriteLine(processName + " " + destenationIp.ToString());
                                }
                            }
                        }
                    }
                }
            }
            else if(pack == "TCP")
            {
                var tcpPacket = packet.Extract<TcpPacket>();
                if (tcpPacket != null)
                {
                    var ipPack = tcpPacket.ParentPacket as IPPacket;
                    if (ipPack != null)
                    {
                        var sourceIp = ipPack.SourceAddress;
                        var sourcePort = tcpPacket.SourcePort;

                        var destenationIp = ipPack.DestinationAddress;
                        var destenationPort = tcpPacket.DestinationPort;

                        if (ports.Contains(sourcePort) || ports.Contains(destenationPort))
                        {
                            if (sourceIp != null && destenationIp != null)
                            {
                                if (!resultOfProgram.Keys.Contains(destenationIp.ToString()))
                                {
                                    resultOfProgram.Add(destenationIp.ToString(), processName);
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                var udpPacket = packet.Extract<UdpPacket>();
                var tcpPacket = packet.Extract<TcpPacket>();
                if (udpPacket != null)
                {
                    var ipPack = udpPacket.ParentPacket as IPPacket;
                    if (ipPack != null)
                    {
                        var sourceIp = ipPack.SourceAddress;
                        var sourcePort = udpPacket.SourcePort;

                        var destenationIp = ipPack.DestinationAddress;
                        var destenationPort = udpPacket.DestinationPort;

                        if (ports.Contains(sourcePort) || ports.Contains(destenationPort))
                        {
                            if (sourceIp != null && destenationIp != null)
                            {
                                if (!resultOfProgram.Keys.Contains(destenationIp.ToString()))
                                {
                                    resultOfProgram.Add(destenationIp.ToString(), processName);
                                }
                            }
                        }
                    }
                }
                else if (tcpPacket != null)
                {
                    var ipPack = tcpPacket.ParentPacket as IPPacket;
                    if (ipPack != null)
                    {
                        var sourceIp = ipPack.SourceAddress;
                        var sourcePort = tcpPacket.SourcePort;

                        var destenationIp = ipPack.DestinationAddress;
                        var destenationPort = tcpPacket.DestinationPort;

                        if (ports.Contains(sourcePort) || ports.Contains(destenationPort))
                        {
                            if (sourceIp != null && destenationIp != null)
                            {
                                if(!resultOfProgram.Keys.Contains(destenationIp.ToString()))
                                {
                                    resultOfProgram.Add(destenationIp.ToString(), processName);
                                }
                            }
                        }
                    }
                }
            }
        }


        /// <summary>
        /// Starts capturing network packets for a specific process asynchronously.
        /// It retrieves the process ID and associated ports, then listens for incoming packets
        /// from network devices. Captured packets are analyzed and stored based on predefined criteria.
        /// </summary>
        /// <param name="processName">The name of the process to monitor.</param>
        /// <returns>A dictionary containing destination IPs and their associated process names.</returns>
        
        public async Task<Dictionary<string, string>> StartCaptureAsync(string processName)
        {
            var processInfo = GetProcessIdByName(processName);

            var processId = new HashSet<int>();

            foreach (var pId in processInfo)
            {
                processId = pId.Key;
            }

            var ports = GetProcessPortByProcessId(processId);

            var devices = GetCaptureDevices();

            var captureTaskCompletionSource = new TaskCompletionSource<Dictionary<string, string>>();

            foreach (var device in devices)
            {
                device.OnPacketArrival += (sender, e) => OnPacketArrival(e, ports, processId, processName);
                device.Open();

                device.StartCapture();
            }

            Console.CancelKeyPress += (sender, e) =>
            {
                foreach (var device in devices)
                {
                    device.StopCapture();
                    device.Close();
                }

                captureTaskCompletionSource.SetResult(resultOfProgram);
            };

            return await captureTaskCompletionSource.Task;
        }


        /// <summary>
        /// Stops the packet capturing process.
        /// It closes all active network devices and finalizes the captured results.
        /// </summary>
        
        public void StopCapture()
        {
            var captureTaskCompletionSource = new TaskCompletionSource<Dictionary<string, string>>();

            var devices = GetCaptureDevices();
            foreach (var device in devices)
            {
                device.StopCapture();
                device.Close();
            }

            captureTaskCompletionSource.SetResult(resultOfProgram);
        }
    }
}
