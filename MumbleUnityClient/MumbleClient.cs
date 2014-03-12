using System;
using System.Net;
using MumbleProto;
using NLog;
using Version = MumbleProto.Version;

namespace MumbleUnityClient
{
    public delegate void MumbleError(string message, bool fatal = false);
    public delegate void UpdateOcbServerNonce(byte[] cryptSetup);

    public class MumbleClient
    {
        Logger logger = LogManager.GetLogger("MumbleClient");

        private MumbleTcpConnection _mtc;
        private MumbleUdpConnection _muc;

        public bool ConnectionSetupFinished { get; set; }

        internal Version RemoteVersion { get; set; }
        internal CryptSetup CryptSetup { get; set; }
        internal ChannelState ChannelState { get; set; }
        internal UserState UserState { get; set; }
        internal ServerSync ServerSync { get; set; }
        internal CodecVersion CodecVersion { get; set; }
        internal PermissionQuery PermissionQuery { get; set; }
        internal ServerConfig ServerConfig { get; set; }

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
            _muc = new MumbleUdpConnection(host, DealWithError, this);
            _mtc = new MumbleTcpConnection(host, hostName, _muc.UpdateOcbServerNonce, DealWithError, this);
        }

        private void DealWithError(string message, bool fatal)
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

        public void Connect(string username, string password)
        {
            logger.Debug("Connecting via TCP");
            _mtc.Connect(username, password);
        }

        internal void ConnectUdp()
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
            var msg = new TextMessage
            {
                message = textMessage
            };
            _mtc.SendMessage(MessageType.TextMessage, msg);
        }

        public byte[] GetLatestClientNonce()
        {
            return _muc.GetLatestClientNonce();
        }
    }
}