using System;
using System.Threading;
using MumbleProto;
using NLog;

namespace MumbleUnityClient
{

    internal class OCBEncryption
    {
        readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion);

        private readonly OcbAes _aes;
        // TODO lock{}
        private readonly byte[] _decryptHistory = new byte[256];
        private readonly Logger logger = LogManager.GetLogger("OCBEncryption");

        public OCBEncryption(CryptSetup cryptSetup)
        {
            logger.Debug("Client nonce length: " + cryptSetup.client_nonce.Length);
            logger.Debug("Server nonce length: " + cryptSetup.server_nonce.Length);

            CryptSetup = cryptSetup;
            _aes = new OcbAes();
            _aes.Initialise(CryptSetup.key);
        }

        private CryptSetup _cryptSetup;
        public CryptSetup CryptSetup
        {
            get
            {
                try
                {
                    _lock.EnterReadLock();
                    return _cryptSetup;
                }
                finally
                {
                    _lock.ExitReadLock();
                }
            }
            set
            {
                try
                {
                    _lock.EnterWriteLock();
                    _cryptSetup = value;
                }
                finally
                {
                    _lock.ExitWriteLock();
                }
            }
        }

        public int Good { get; private set; }
        public int Late { get; private set; }
        public int Lost { get; private set; }

        public byte[] Decrypt(byte[] inBytes)
        {
            try
            {
                _lock.EnterReadLock();
                if (inBytes.Length < 4)
                    return null;

                int plainLength = inBytes.Length - 4;

                var saveiv = new byte[OcbAes.BLOCK_SIZE];
                var ivbyte = (short) (inBytes[0] & 0xFF);
                bool restore = false;
                var tag = new byte[OcbAes.BLOCK_SIZE];

                int lost = 0;
                int late = 0;

                Array.ConstrainedCopy(CryptSetup.server_nonce, 0, saveiv, 0, OcbAes.BLOCK_SIZE);

                if (((CryptSetup.server_nonce[0] + 1) & 0xFF) == ivbyte)
                {
                    // In order as expected.
                    if (ivbyte > CryptSetup.server_nonce[0])
                    {
                        CryptSetup.server_nonce[0] = (byte) ivbyte;
                    }
                    else if (ivbyte < CryptSetup.server_nonce[0])
                    {
                        CryptSetup.server_nonce[0] = (byte) ivbyte;
                        for (int i = 1; i < OcbAes.BLOCK_SIZE; i++)
                        {
                            if ((++CryptSetup.server_nonce[i]) != 0)
                            {
                                break;
                            }
                        }
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    // This is either out of order or a repeat.
                    int diff = ivbyte - CryptSetup.server_nonce[0];
                    if (diff > 128)
                    {
                        diff = diff - 256;
                    }
                    else if (diff < -128)
                    {
                        diff = diff + 256;
                    }

                    if ((ivbyte < CryptSetup.server_nonce[0]) && (diff > -30) && (diff < 0))
                    {
                        // Late packet, but no wraparound.
                        late = 1;
                        lost = -1;
                        CryptSetup.server_nonce[0] = (byte) ivbyte;
                        restore = true;
                    }
                    else if ((ivbyte > CryptSetup.server_nonce[0]) && (diff > -30) &&
                             (diff < 0))
                    {
                        // Last was 0x02, here comes 0xff from last round
                        late = 1;
                        lost = -1;
                        CryptSetup.server_nonce[0] = (byte) ivbyte;
                        for (int i = 1; i < OcbAes.BLOCK_SIZE; i++)
                        {
                            if ((CryptSetup.server_nonce[i]--) != 0)
                            {
                                break;
                            }
                        }
                        restore = true;
                    }
                    else if ((ivbyte > CryptSetup.server_nonce[0]) && (diff > 0))
                    {
                        // Lost a few packets, but beyond that we're good.
                        lost = ivbyte - CryptSetup.server_nonce[0] - 1;
                        CryptSetup.server_nonce[0] = (byte) ivbyte;
                    }
                    else if ((ivbyte < CryptSetup.server_nonce[0]) && (diff > 0))
                    {
                        // Lost a few packets, and wrapped around
                        lost = 256 - CryptSetup.server_nonce[0] + ivbyte - 1;
                        CryptSetup.server_nonce[0] = (byte) ivbyte;
                        for (int i = 1; i < OcbAes.BLOCK_SIZE; i++)
                        {
                            if ((++CryptSetup.server_nonce[i]) != 0)
                            {
                                break;
                            }
                        }
                    }
                    else
                    {
                        return null;
                    }

                    if (_decryptHistory[CryptSetup.server_nonce[0]] == CryptSetup.client_nonce[0])
                    {
                        Array.ConstrainedCopy(saveiv, 0, CryptSetup.server_nonce, 0, OcbAes.BLOCK_SIZE);
                        return null;
                    }
                }

                byte[] dst = _aes.Decrypt(inBytes, 4, plainLength, CryptSetup.server_nonce, 0, inBytes, 0);

                if (tag[0] != inBytes[1] || tag[1] != inBytes[2] || tag[2] != inBytes[3])
                {
                    Array.ConstrainedCopy(saveiv, 0, CryptSetup.server_nonce, 0, OcbAes.BLOCK_SIZE);
                    return null;
                }
                _decryptHistory[CryptSetup.server_nonce[0]] = CryptSetup.server_nonce[1];

                if (restore)
                {
                    Array.ConstrainedCopy(saveiv, 0, CryptSetup.server_nonce, 0, OcbAes.BLOCK_SIZE);
                }

                Good++;
                Late += late;
                Lost += lost;

                return dst;
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public byte[] Encrypt(byte[] inBytes)
        {
            try
            {
                _lock.EnterReadLock();
                //for (int i = 0; i < CryptSetup.client_nonce.Length; i++)
                

                for (int i = 0; i < OcbAes.BLOCK_SIZE; i++)
                {
                    if (++CryptSetup.client_nonce[i] != 0)
                        break;
                }

                logger.Debug("Encrypting " + inBytes.Length + " bytes");
                var tag = new byte[OcbAes.BLOCK_SIZE];
                byte[] dst = _aes.Encrypt(inBytes, 0, inBytes.Length, CryptSetup.client_nonce, 0, tag, 0);
                
                var fdst = new byte[dst.Length + 4];
                fdst[0] = CryptSetup.client_nonce[0];
                fdst[1] = tag[0];
                fdst[2] = tag[1];
                fdst[3] = tag[2];

                dst.CopyTo(fdst, 4);

                return fdst;
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }
    }
}