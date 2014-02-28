using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Timers;
using MumbleProto;
using NLog;
using ProtoBuf;
using Version = MumbleProto.Version;

namespace MumbleUnityClient
{
    public class MumbleTCPConnection
    {
        private readonly IPEndPoint _host;
        private readonly string _hostname;
        private readonly Logger logger = LogManager.GetLogger("MumbleUnityConnect");

        private MumbleClient _mc;
        private readonly TcpClient _tcpClient;
        private SslStream _ssl;
        private BinaryReader _reader;
        private BinaryWriter _writer;
        private MumbleError _errorCallback;
        private bool _validConnection = false;

        public MumbleTCPConnection(IPEndPoint host, string hostname, MumbleError errorCallback, MumbleClient mc)
        {
            _host = host;
            _hostname = hostname;
            _mc = mc;
            _tcpClient = new TcpClient();
            _errorCallback = errorCallback;
        }

        public void Connect(string username, string password)
        {
            ConnectViaTCP();
            var version = new Version
            {
                release = "Immerse Mumble",
                version = (1 << 16) | (2 << 8) | (5),
                os = Environment.OSVersion.ToString(),
                os_version = Environment.OSVersion.VersionString,
            };
            SendMessage<MumbleProto.Version>(MessageType.Version, version);

            var authenticate = new Authenticate
            {
                username = username,
                password = password,
            };
            SendMessage<MumbleProto.Authenticate>(MessageType.Authenticate, authenticate);

            // Keepalive, if the Mumble server doesn't get a message 
            // for 30 seconds it will close the connection
            var tcpTimer = new System.Timers.Timer();
            tcpTimer.Elapsed += new ElapsedEventHandler(SendPing);
            tcpTimer.Interval = 2000;
            tcpTimer.Enabled = true;

        }

        public void SendMessage<T>(MessageType mt, T message)
        {
            logger.Debug("Sending " + mt.ToString() + " message");
            _writer.Write(IPAddress.HostToNetworkOrder((short)mt));
            Serializer.SerializeWithLengthPrefix<T>(_ssl, message, PrefixStyle.Fixed32BigEndian);
        }

        private void ConnectViaTCP()
        {
            _tcpClient.Connect(_host);
            NetworkStream networkStream = _tcpClient.GetStream();
            _ssl = new SslStream(networkStream, false, ValidateCertificate);
            _ssl.AuthenticateAsClient(_hostname);
            _reader = new BinaryReader(_ssl);
            _writer = new BinaryWriter(_ssl);

            DateTime startWait = DateTime.Now;
            while (!_ssl.IsAuthenticated)
            {
                if (DateTime.Now - startWait > TimeSpan.FromSeconds(2))
                {
                    logger.Error("Time out waiting for SSL authentication");
                    throw new TimeoutException("Time out waiting for SSL authentication");
                }
            }
            logger.Debug("TCP connection established");
        }

        private bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors errors)
        {
            return true;
        }

        public void ProcessTcpData()
        {
            try
            {
                var messageType = (MessageType) IPAddress.NetworkToHostOrder(_reader.ReadInt16());
                logger.Debug("Received message type: " + messageType);

                switch (messageType)
                {
                    case MessageType.Version:
                        _mc.RemoteVersion = Serializer.DeserializeWithLengthPrefix<MumbleProto.Version>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.CryptSetup:
                        _mc.CryptSetup = Serializer.DeserializeWithLengthPrefix<MumbleProto.CryptSetup>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.CodecVersion:
                        _mc.CodecVersion = Serializer.DeserializeWithLengthPrefix<MumbleProto.CodecVersion>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.ChannelState:
                        _mc.ChannelState = Serializer.DeserializeWithLengthPrefix<MumbleProto.ChannelState>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.PermissionQuery:
                        _mc.PermissionQuery = Serializer.DeserializeWithLengthPrefix<MumbleProto.PermissionQuery>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.UserState:
                        _mc.UserState = Serializer.DeserializeWithLengthPrefix<MumbleProto.UserState>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.ServerSync:
                        _mc.ServerSync = Serializer.DeserializeWithLengthPrefix<MumbleProto.ServerSync>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        _mc.ConnectionSetupFinished = true;
                        break;
                    case MessageType.ServerConfig:
                        _mc.ServerConfig = Serializer.DeserializeWithLengthPrefix<MumbleProto.ServerConfig>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        _validConnection = true; // handshake complete
                        break;
                    case MessageType.TextMessage:
                        var textMessage = Serializer.DeserializeWithLengthPrefix<MumbleProto.ServerConfig>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.UDPTunnel:
                        var udpTunnel = Serializer.DeserializeWithLengthPrefix<MumbleProto.UDPTunnel>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.Reject:
                        var reject = Serializer.DeserializeWithLengthPrefix<MumbleProto.Reject>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        _validConnection = false;
                        _errorCallback("Mumble server reject: " + reject.reason,true);
                        break;
                    default:
                        _errorCallback("Message type " + messageType.ToString() + " not implemented", true);
                        break;
                }
            }
            catch (EndOfStreamException ex)
            {
                logger.Error(ex);
            }
        }

        public void Close()
        {
            _ssl.Close();
        }

        public void SendPing(object sender, ElapsedEventArgs elapsedEventArgs)
        {
            if (_validConnection)
                SendMessage(MessageType.Ping, new Ping());
        }
    }
}