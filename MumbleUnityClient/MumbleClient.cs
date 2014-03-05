using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using MumbleProto;
using NLog;
using ProtoBuf;
using Version = MumbleProto.Version;

namespace MumbleUnityClient
{
    public delegate void MumbleError(string message, bool fatal = false);

    public delegate void StartUDP();

    public class MumbleClient
    {
        Logger logger = LogManager.GetLogger("MumbleClient");

        private MumbleTCPConnection _mtc;
        private MumbleUDPConnection _muc;

        private bool _connectionSetupFinished = false;
        public bool ConnectionSetupFinished { get; set; }
        
        public Version RemoteVersion { get; set; }
        public CryptSetup CryptSetup { get; set; }
        public ChannelState ChannelState { get; set; }
        public UserState UserState { get; set; }
        public ServerSync ServerSync { get; set; }
        public CodecVersion CodecVersion { get; set; }
        public PermissionQuery PermissionQuery { get; set; }
        public ServerConfig ServerConfig { get; set; }

        public MumbleClient(String hostName, int port)
        {
            IPAddress[] addresses = Dns.GetHostAddresses(hostName);
            if (addresses.Length == 0)
            {
                throw new ArgumentException(
                    "Unable to retrieve address from specified host name.",
                    "hostName"
                    );
            }
            var host = new IPEndPoint(addresses[0], port);
            _mtc = new MumbleTCPConnection(host, hostName, ConnectUDP, DealWithError, this);
            _muc = new MumbleUDPConnection(host, DealWithError, this);

        }

        public void DealWithError(string message, bool fatal)
        {
            if (fatal)
            {
                Console.WriteLine("Fatal error: " + message);
                Console.ReadLine();
                _mtc.Close();
                _muc.Close();
                Environment.Exit(1);
            }
            else
            {
                Console.WriteLine("Recovering from: " + message);
            }
        }

        public void ConnectTCP(string username, string password)
        {
            logger.Debug("Connecting via TCP");
            _mtc.Connect(username, password);
        }

        public void ConnectUDP()
        {
            logger.Debug("Connecting via UDP");
            _muc.Connect();
        }

        public void Process()
        {
            _mtc.ProcessTcpData();    
        }

        public void SendTextMessage(string textMessage)
        {
            MumbleProto.TextMessage msg = new TextMessage()
            {
                message = textMessage
            };
            _mtc.SendMessage(MessageType.TextMessage, msg);
        }
    }
}