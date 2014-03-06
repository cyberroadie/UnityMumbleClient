﻿using System;
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
                ocb.CryptSetup.server_nonce = serverNonce;
        }

        public void Connect()
        {
            ocb = new OCBEncryption(_mc.CryptSetup);
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
//            long timestamp = DateTime.Now.Ticks;
//
//            byte[] buffer = new byte[9];
//            buffer[0] = 1 << 5;
//            buffer[1] = (byte)((timestamp >> 56) & 0xFF);
//            buffer[2] = (byte)((timestamp >> 48) & 0xFF);
//            buffer[3] = (byte)((timestamp >> 40) & 0xFF);
//            buffer[4] = (byte)((timestamp >> 32) & 0xFF);
//            buffer[5] = (byte)((timestamp >> 24) & 0xFF);
//            buffer[6] = (byte)((timestamp >> 16) & 0xFF);
//            buffer[7] = (byte)((timestamp >> 8) & 0xFF);
//            buffer[8] = (byte)((timestamp) & 0xFF);
//            _udpClient.Send(buffer, buffer.Length);

            ulong unixTimeStamp = (ulong) (DateTime.UtcNow.Ticks - DateTime.Parse("01/01/1970 00:00:00").Ticks);
            byte[] timeBytes = BitConverter.GetBytes(unixTimeStamp);
            var dgram = new byte[timeBytes.Length + 1];
//            var dgram = new byte[16];
            timeBytes.CopyTo(dgram, 1);
            dgram[0] = (1 << 5);
            logger.Debug("Sending UDP ping with timestamp: " + unixTimeStamp);
            var encryptedData = ocb.Encrypt(dgram);
            _udpClient.Send(encryptedData, encryptedData.Length);
//            _udpClient.Send(dgram, dgram.Length);


        }

        public void Close()
        {
            _udpClient.Close();
        }

        public byte[] GetLatestClientNonce()
        {
            return ocb.CryptSetup.client_nonce;
        }
    }
}
