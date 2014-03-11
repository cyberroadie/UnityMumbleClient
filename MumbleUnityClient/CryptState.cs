using System;
using System.Security.Cryptography;
using MumbleProto;
using NLog;

namespace MumbleUnityClient
{
    public class CryptState
    {
        private readonly int AES_BLOCK_SIZE = 16;
//        private readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion);
        private readonly Logger logger = LogManager.GetLogger("OCBEncryption");

        private CryptSetup _cryptSetup;
        private ICryptoTransform _encryptor;


        public CryptSetup CryptSetup
        {
            get { return _cryptSetup; }
            set
            {
                _cryptSetup = value;
                var aesAlg = new AesManaged
                {
                    BlockSize = AES_BLOCK_SIZE*8,
                    Key = _cryptSetup.key,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                };
                _encryptor = aesAlg.CreateEncryptor();
            }
        }

        private void S2(byte[] block)
        {
            int carry = (block[0] >> 7) & 0x1;
            for (int i = 0; i < AES_BLOCK_SIZE - 1; i++)
            {
                block[i] = (byte) ((block[i] << 1) | ((block[i + 1] >> 7) & 0x1));
            }
            block[AES_BLOCK_SIZE - 1] = (byte) ((block[AES_BLOCK_SIZE - 1] << 1) ^ (carry*0x87));
        }

        private void S3(byte[] block)
        {
            int carry = (block[0] >> 7) & 0x1;
            for (int i = 0; i < AES_BLOCK_SIZE - 1; i++)
            {
                block[i] ^= (byte) ((block[i] << 1) | ((block[i + 1] >> 7) & 0x1));
            }
            block[AES_BLOCK_SIZE - 1] ^= (byte) ((block[AES_BLOCK_SIZE - 1] << 1) ^ (carry*0x87));
        }

        private void XOR(byte[] dst, byte[] a, byte[] b)
        {
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
            {
                dst[i] = (byte) (a[i] ^ b[i]);
            }
        }

        private void ZERO(byte[] block)
        {
            Array.Clear(block, 0, block.Length);
        }

        // buffer + amount of usefull bytes in buffer
        public byte[] Encrypt(byte[] inBytes, int length)
        {
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
            {
                if (++_cryptSetup.client_nonce[i] != 0)
                    break;
            }

            logger.Debug("Encrypting " + length + " bytes");
            var tag = new byte[AES_BLOCK_SIZE];

            var dst = new byte[length];
            OcbEncrypt(inBytes, length, dst, _cryptSetup.client_nonce, tag);

            var fdst = new byte[dst.Length + 4];
            logger.Debug("IV: " + (int)_cryptSetup.client_nonce[0]);
            fdst[0] = _cryptSetup.client_nonce[0];
            fdst[1] = tag[0];
            fdst[2] = tag[1];
            fdst[3] = tag[2];

            dst.CopyTo(fdst, 4);
            return fdst;
        }

        private void OcbEncrypt(byte[] plain, int plainLength, byte[] encrypted, byte[] nonce, byte[] tag)
        {
            var checksum = new byte[AES_BLOCK_SIZE];
            var tmp = new byte[AES_BLOCK_SIZE];

//            byte[] delta = encryptCipher.doFinal(nonce);
            var delta = new byte[AES_BLOCK_SIZE];
            _encryptor.TransformBlock(nonce, 0, AES_BLOCK_SIZE, delta, 0);

            int offset = 0;
            int len = plainLength;
            while (len > AES_BLOCK_SIZE)
            {
                var buffer = new byte[AES_BLOCK_SIZE];
                S2(delta);
                Array.Copy(plain, offset, buffer, 0, AES_BLOCK_SIZE);
                XOR(checksum, checksum, buffer);
                XOR(tmp, delta, buffer);

//                encryptCipher.doFinal(tmp, 0, AES_BLOCK_SIZE, tmp);
                _encryptor.TransformBlock(tmp, 0, AES_BLOCK_SIZE, tmp, 0);

                XOR(buffer, delta, tmp);
                Array.Copy(buffer, 0, encrypted, offset, AES_BLOCK_SIZE);
                offset += AES_BLOCK_SIZE;
                len -= AES_BLOCK_SIZE;
            }

            S2(delta);
            ZERO(tmp);
            long num = len*8;
            tmp[AES_BLOCK_SIZE - 2] = (byte) ((num >> 8) & 0xFF);
            tmp[AES_BLOCK_SIZE - 1] = (byte) (num & 0xFF);
            XOR(tmp, tmp, delta);

//            byte[] pad = encryptCipher.doFinal(tmp);
            var pad = new byte[AES_BLOCK_SIZE];
            _encryptor.TransformBlock(tmp, 0, AES_BLOCK_SIZE, pad, 0);

            Array.Copy(plain, offset, tmp, 0, len);
            Array.Copy(pad, len, tmp, len, AES_BLOCK_SIZE - len);

            XOR(checksum, checksum, tmp);
            XOR(tmp, pad, tmp);
            Array.Copy(tmp, 0, encrypted, offset, len);

            S3(delta);
            XOR(tmp, delta, checksum);

//            encryptCipher.doFinal(tmp, 0, AES_BLOCK_SIZE, tag);
            _encryptor.TransformBlock(tmp, 0, AES_BLOCK_SIZE, tag, 0);
        }
    }
}