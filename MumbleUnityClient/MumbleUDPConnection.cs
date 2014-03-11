using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Timers;
using MumbleProto;
using NLog;

namespace MumbleUnityClient
{
    class MumbleUDPConnection
    {
        private Logger logger = LogManager.GetLogger("MumbleUnityConnection");
        private readonly IPEndPoint _host;
        private readonly UdpClient _udpClient;
        private readonly MumbleClient _mc;
        private MumbleError _errorCallback;
        private bool isValidConnection = false;
        protected OCBEncryption ocb;
        private CryptState _cryptState;
        private static int MAX_UDP_PACKET = 128;
        private byte[] response = new byte[MAX_UDP_PACKET];

        public MumbleUDPConnection(IPEndPoint host, MumbleError errorCallback, MumbleClient mc)
        {
            _host = host;
            _errorCallback = errorCallback;
            _udpClient = new UdpClient();
            _mc = mc;
        }

        public void UpdateOcbServerNonce(byte[] serverNonce)
        {
            if(serverNonce != null)
                _cryptState.CryptSetup.server_nonce = serverNonce;
        }

        public void Connect()
        {
            ocb = new OCBEncryption(_mc.CryptSetup);
            _cryptState = new CryptState();
            _cryptState.CryptSetup = _mc.CryptSetup;
            _udpClient.Connect(_host);

            var tcpTimer = new System.Timers.Timer();
            tcpTimer.Elapsed += new ElapsedEventHandler(Handshake);
            tcpTimer.Interval = 5000;
            tcpTimer.Enabled = true;

        }

        private void Handshake(object sender, ElapsedEventArgs elapsedEventArgs)
        {
             SendPing();

//            isValidConnection = response.SequenceEqual(dgram);

//            _udpClient.BeginReceive(response, 0, MAX_UDP_PACKET, SocketFlags.None, receiveCallback, null);

            _udpClient.BeginReceive(new AsyncCallback(receive), null);

//            if (!isValidConnection)
//                _errorCallback("Incorrect response from server during UDP handshake", false);

        }

        private void receive(IAsyncResult res)
        {
            IPEndPoint RemoteIpEndPoint = _host;
            byte[] response = _udpClient.EndReceive(res, ref RemoteIpEndPoint);

            logger.Debug("************ UDP response received");
            _udpClient.BeginReceive(new AsyncCallback(receive), null);
        }


        public void SendPing()
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

        public void Close()
        {
            _udpClient.Close();
        }

        public byte[] GetLatestClientNonce()
        {
            return _cryptState.CryptSetup.client_nonce;
        }
    }
}
