using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Timers;
using MumbleProto;
//using NLog;
using ProtoBuf;
using Version = MumbleProto.Version;

namespace MumbleUnityClient
{
    public class MumbleTcpConnection
    {
        private readonly UpdateOcbServerNonce _updateOcbServerNonce;
        private readonly MumbleError _errorCallback;
        private readonly IPEndPoint _host;
        private readonly string _hostname;

        private readonly MumbleClient _mc;
        private readonly TcpClient _tcpClient;
//        private readonly Logger _logger = LogManager.GetLogger("MumbleUnityConnect");
        private BinaryReader _reader;
        private SslStream _ssl;
        private bool _validConnection;
        private BinaryWriter _writer;

        internal MumbleTcpConnection(IPEndPoint host, string hostname, UpdateOcbServerNonce updateOcbServerNonce,  MumbleError errorCallback,
            MumbleClient mc)
        {
            _host = host;
            _hostname = hostname;
            _mc = mc;
            _tcpClient = new TcpClient();
            _updateOcbServerNonce = updateOcbServerNonce;
            _errorCallback = errorCallback;
        }

        internal void StartClient(string username, string password)
        {
            ConnectViaTcp();
            var version = new Version
            {
                release = "Immerse Mumble",
                version = (1 << 16) | (2 << 8) | (5),
                os = Environment.OSVersion.ToString(),
                os_version = Environment.OSVersion.VersionString,
            };
            SendMessage(MessageType.Version, version);

            var authenticate = new Authenticate
            {
                username = username,
                password = password,
            };
            SendMessage(MessageType.Authenticate, authenticate);

            // Keepalive, if the Mumble server doesn't get a message 
            // for 30 seconds it will close the connection
            var tcpTimer = new Timer();
            tcpTimer.Elapsed += SendPing;
            tcpTimer.Interval = 10000;
            tcpTimer.Enabled = true;
        }

        internal void SendMessage<T>(MessageType mt, T message)
        {
            lock (_ssl)
            {
//                _logger.Debug("Sending " + mt + " message");
                _writer.Write(IPAddress.HostToNetworkOrder((short) mt));
                Serializer.SerializeWithLengthPrefix(_ssl, message, PrefixStyle.Fixed32BigEndian);
            }
        }

        internal void ConnectViaTcp()
        {
//            _tcpClient.BeginConnect()


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
//                    _logger.Error("Time out waiting for SSL authentication");
                    throw new TimeoutException("Time out waiting for SSL authentication");
                }
            }
//            _logger.Debug("TCP connection established");
        }

        private bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors errors)
        {
            return true;
        }

        internal void ProcessTcpData()
        {
            try
            {
                var messageType = (MessageType) IPAddress.NetworkToHostOrder(_reader.ReadInt16());
//                _logger.Debug("Received message type: " + messageType);

                switch (messageType)
                {
                    case MessageType.Version:
                        _mc.RemoteVersion = Serializer.DeserializeWithLengthPrefix<Version>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
//                        _logger.Debug("Server version: " + _mc.RemoteVersion.release);
                        break;
                    case MessageType.CryptSetup:
                        var cryptSetup = Serializer.DeserializeWithLengthPrefix<CryptSetup>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        ProcessCryptSetup(cryptSetup);
                        break;
                    case MessageType.CodecVersion:
                        _mc.CodecVersion = Serializer.DeserializeWithLengthPrefix<CodecVersion>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.ChannelState:
                        _mc.ChannelState = Serializer.DeserializeWithLengthPrefix<ChannelState>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.PermissionQuery:
                        _mc.PermissionQuery = Serializer.DeserializeWithLengthPrefix<PermissionQuery>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.UserState:
                        _mc.UserState = Serializer.DeserializeWithLengthPrefix<UserState>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.ServerSync:
                        _mc.ServerSync = Serializer.DeserializeWithLengthPrefix<ServerSync>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        _mc.ConnectionSetupFinished = true;
                        break;
                    case MessageType.ServerConfig:
                        _mc.ServerConfig = Serializer.DeserializeWithLengthPrefix<ServerConfig>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        _validConnection = true; // handshake complete
                        break;
                    case MessageType.TextMessage:
                        var textMessage = Serializer.DeserializeWithLengthPrefix<TextMessage>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.UDPTunnel:
                        var udpTunnel = Serializer.DeserializeWithLengthPrefix<UDPTunnel>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        break;
                    case MessageType.Ping:
                        var ping = Serializer.DeserializeWithLengthPrefix<Ping>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
//                        _logger.Debug("Received ping: " + ping.timestamp + ", udp: " + ping.udp_packets + ", tcp:" +
//                                     ping.tcp_packets);
                        break;
                    case MessageType.Reject:
                        var reject = Serializer.DeserializeWithLengthPrefix<Reject>(_ssl,
                            PrefixStyle.Fixed32BigEndian);
                        _validConnection = false;
                        _errorCallback("Mumble server reject: " + reject.reason, true);
                        break;
                    default:
                        _errorCallback("Message type " + messageType + " not implemented", true);
                        break;
                }
            }
            catch (EndOfStreamException ex)
            {
//                _logger.Error(ex);
            }
        }

        private void ProcessCryptSetup(CryptSetup cryptSetup)
        {
            if (cryptSetup.key != null && cryptSetup.client_nonce != null && cryptSetup.server_nonce != null)
            {
                _mc.CryptSetup = cryptSetup;
                SendMessage(MessageType.CryptSetup, new CryptSetup {client_nonce = cryptSetup.client_nonce});
                _mc.ConnectUdp();
            }
            else if(cryptSetup.server_nonce != null)
            {
                _updateOcbServerNonce(cryptSetup.server_nonce);
            }
            else
            {
                SendMessage(MessageType.CryptSetup, new CryptSetup { client_nonce = _mc.GetLatestClientNonce() });

            }
        }

        internal void Close()
        {
            _ssl.Close();
        }

        internal void SendPing(object sender, ElapsedEventArgs elapsedEventArgs)
        {
            if (_validConnection)
            {
                var ping = new Ping();
                ping.timestamp = (ulong) (DateTime.UtcNow.Ticks - DateTime.Parse("01/01/1970 00:00:00").Ticks);
//                _logger.Debug("Sending TCP ping with timestamp: " + ping.timestamp);
                SendMessage(MessageType.Ping, new Ping());
            }
        }
    }
}