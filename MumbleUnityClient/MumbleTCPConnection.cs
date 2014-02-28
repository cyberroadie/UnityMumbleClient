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

        public MumbleTCPConnection(IPEndPoint host, string hostname, MumbleClient mc)
        {
            _host = host;
            _hostname = hostname;
            _mc = mc;
            _tcpClient = new TcpClient();
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
                        break;
                    case MessageType.TextMessage:
                        var textMessage = Serializer.DeserializeWithLengthPrefix<MumbleProto.ServerConfig>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.UDPTunnel:
                        var udpTunnel = Serializer.DeserializeWithLengthPrefix<MumbleProto.UDPTunnel>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    default:
                        throw new NotImplementedException("Message type " + messageType.ToString() + " not implemented");
                }
            }
            catch (EndOfStreamException ex)
            {
                logger.Error(ex);
            }
        }
    }
}