﻿using System;
using System.Threading;
using NLog;

namespace MumbleUnityClient
{
    internal class Program
    {
        private static readonly Logger logger = LogManager.GetLogger("Program");
        private static MumbleClient _mc;

        private static void Main(string[] args)
        {
            _mc = new MumbleClient("127.0.0.1", 64738);
            _mc.Connect("olivier visual studio", "");

            Thread t = new Thread(Update);
            t.Start();

            while (true)
            {
                string msg = Console.ReadLine();
                _mc.SendTextMessage(msg);
            }
        }

        // This is the Unity Update() routine
        private static void Update()
        {
            while(true)
              _mc.Process();
        }

    }
}