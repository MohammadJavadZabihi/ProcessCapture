using SharpPcap;

namespace ProcessCapture.Services.Interface
{
    public interface IMonitoringService
    {

        /*
            loop : Because if the process you selected is not available now and you want
            to wait for it to become available, you will set this loop to true. 
            time : Waiting time for next attempt
        */
        Dictionary<HashSet<int>, string> GetProcessIdByName(string processName, bool loop = false, int time = 0);

        //pId = processId
        HashSet<int> GetProcessPortByProcessId(HashSet<int> pIds);

        //because some time we don't have the pId list
        HashSet<int> GetProcessPortByProcessId(int pId);

        List<string> GetLocalIpAddress();

        CaptureDeviceList GetCaptureDevices();

        //To capture TCP and UDP packets that the process sends to the source IP address
        void OnPacketArrival(PacketCapture e, HashSet<int> ports, HashSet<int>? pId, string processName = "", string pack ="");

        Task<Dictionary<string, string>> StartCaptureAsync(string processName);
        void StopCapture();
    }
}
