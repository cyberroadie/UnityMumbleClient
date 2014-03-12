using System;
using System.Net;
using System.Net.Sockets;
using System.Timers;
using NLog;

namespace MumbleUnityClient
{
    class MumbleUdpConnection
    {
        private Logger logger = LogManager.GetLogger("MumbleUnityConnection");
        private readonly IPEndPoint _host;
        private readonly UdpClient _udpClient;
        private readonly MumbleClient _mc;
        private readonly MumbleError _errorCallback;
        private CryptState _cryptState;

        internal MumbleUdpConnection(IPEndPoint host, MumbleError errorCallback, MumbleClient mc)
        {
            _host = host;
            _errorCallback = errorCallback;
            _udpClient = new UdpClient();
            _mc = mc;
        }

        public MumbleError ErrorCallback
        {
            get { return _errorCallback; }
        }

        internal void UpdateOcbServerNonce(byte[] serverNonce)
        {
            if(serverNonce != null)
                _cryptState.CryptSetup.server_nonce = serverNonce;
        }

        internal void Connect()
        {
//            ocb = new OCBEncryption(_mc.CryptSetup);
            _cryptState = new CryptState();
            _cryptState.CryptSetup = _mc.CryptSetup;
            _udpClient.Connect(_host);

            var tcpTimer = new Timer();
            tcpTimer.Elapsed += RunPing;
            tcpTimer.Interval = 5000;
            tcpTimer.Enabled = true;

        }

        private void RunPing(object sender, ElapsedEventArgs elapsedEventArgs)
        {
             SendPing();
            _udpClient.BeginReceive(ReceiveUdpMessage, null);
        }

        private void ReceiveUdpMessage(IAsyncResult res)
        {
            IPEndPoint remoteIpEndPoint = _host;
            byte[] encrypted = _udpClient.EndReceive(res, ref remoteIpEndPoint);

            byte[] message = _cryptState.Decrypt(encrypted, encrypted.Length);


            // figure out type of message
            int type = message[0] >> 5 & 0x7;
            logger.Debug("************ UDP response received: " + Convert.ToString(message[0], 2).PadLeft(8, '0'));
            logger.Debug("************ UDP response received: " + type);
         
            _udpClient.BeginReceive(ReceiveUdpMessage, null);
        }


        internal void SendPing()
        {
            ulong unixTimeStamp = (ulong) (DateTime.UtcNow.Ticks - DateTime.Parse("01/01/1970 00:00:00").Ticks);
            byte[] timeBytes = BitConverter.GetBytes(unixTimeStamp);
            var dgram = new byte[9];
            timeBytes.CopyTo(dgram, 1);
            dgram[0] = (1 << 5);
            logger.Debug("Sending UDP ping with timestamp: " + unixTimeStamp);
            var encryptedData = _cryptState.Encrypt(dgram, timeBytes.Length + 1);
//            var encryptedData = ocb.Encrypt(dgram, timeBytes.Length + 1);
            _udpClient.Send(encryptedData, encryptedData.Length);
        }

        internal void Close()
        {
            _udpClient.Close();
        }

        internal byte[] GetLatestClientNonce()
        {
            return _cryptState.CryptSetup.client_nonce;
        }
    }
}
