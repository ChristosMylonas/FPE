using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace FPELibrary
{
    /// <summary>
    /// Format Preserving Encryption using the scheme FE1 from the paper
    /// "Format-Preserving Encryption" by Bellare, Rogaway, et al
    /// (http://eprint.iacr.org/2009/251)
    /// Ported from Botan Library Version 1.10.3 (http://botan.randombit.net)
    /// </summary>
    public static class FE1
    {
        // Normally FPE is for SSNs, CC#s, etc, nothing too big
        private const int MAX_N_BYTES = 128 / 8;

        /// <summary>
        /// Generic Z_n FPE decryption, FD1 scheme
        /// </summary>
        /// <param name="modulus">Use to determine the range of the numbers. Example, if the
        /// numbers range from 0 to 999, use "1000" here.</param>
        /// <param name="ciphertext">The number to decrypt.</param>
        /// <param name="key">Secret key</param>
        /// <param name="tweak">Non-secret parameter, think of it as an IV - use the same one used to encrypt</param>
        /// <returns>The decrypted number</returns>
        public static BigInteger Decrypt(BigInteger modulus, BigInteger ciphertext,
                           byte[] key,
                           byte[] tweak)
        {
            FPE_Encryptor F = new FPE_Encryptor(key, modulus, tweak);

            BigInteger a, b;
            NumberTheory.factor(modulus, out a, out b);

            int r = rounds(a, b);

            BigInteger X = ciphertext;

            for (int i = 0; i != r; ++i)
            {
                BigInteger W = X.mod(a);
                BigInteger R = X / a;

                BigInteger bigInteger = (W - F.F(r - i - 1, R));

                BigInteger L = bigInteger.mod(a);
                X = b * L + R;
            }

            return X;
        }

        /// <summary>
        /// Generic Z_n FPE encryption, FE1 scheme
        /// </summary>
        /// <param name="modulus">Use to determine the range of the numbers. Example, if the
        /// numbers range from 0 to 999, use "1000" here.</param>
        /// <param name="plaintext">The number to encrypt.</param>
        /// <param name="key">Secret key</param>
        /// <param name="tweak">Non-secret parameter, think of it as an IV</param>
        /// <returns>The encrypted number.</returns>
        public static BigInteger Encrypt(BigInteger modulus, BigInteger plaintext,
                           byte[] key,
                           byte[] tweak)
        {
            FPE_Encryptor F = new FPE_Encryptor(key, modulus, tweak);

            BigInteger a, b;
            NumberTheory.factor(modulus, out a, out b);

            int r = rounds(a, b);

            BigInteger X = plaintext;

            for (int i = 0; i != r; ++i)
            {
                BigInteger L = X / b;
                BigInteger R = X.mod(b);

                BigInteger W = (L + F.F(i, R)).mod(a);
                X = a * R + W;
            }

            return X;
        }

        /// <summary>
        /// According to a paper by Rogaway, Bellare, etc, the min safe number
        /// of rounds to use for FPE is 2+log_a(b). If a >= b then log_a(b) &lt;= 1
        /// so 3 rounds is safe. The FPE factorization routine should always
        /// return a >= b, so just confirm that and return 3.
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        private static int rounds(BigInteger a, BigInteger b)
        {
            if (a < b)
                throw new Exception("FPE rounds: a < b");
            return 3;
        }

        /// <summary>
        /// A simple round function based on HMAC(SHA-256)
        /// </summary>
        private class FPE_Encryptor
        {
            private System.Security.Cryptography.HMACSHA256 mac;

            private byte[] mac_n_t;

            internal FPE_Encryptor(byte[] key,
                             BigInteger n,
                             byte[] tweak)
            {
                mac = new System.Security.Cryptography.HMACSHA256(key);
                mac.Initialize();

                byte[] n_bin = n.encode();

                if (n_bin.Length > MAX_N_BYTES)
                    throw new Exception("N is too large for FPE encryption");

                var ms = new MemoryStream();

                ms.update_be(n_bin.Length);
                ms.update(n_bin);

                ms.update_be(tweak.Length);
                ms.update(tweak);

                mac_n_t = mac.ComputeHash(ms.ToArray());
            }

            internal BigInteger F(int round_no, BigInteger R)
            {
                byte[] r_bin = R.encode();
                var ms = new MemoryStream();
                ms.update(mac_n_t);
                ms.update_be(round_no);

                ms.update_be(r_bin.Length);
                ms.update(r_bin);

                byte[] X = mac.ComputeHash(ms.ToArray()).Reverse().ToArray();
                var X_ = new byte[X.Length + 1];
                X.CopyTo(X_, 0);
                X_[X.Length] = 0; // guarantee a positive interpretation
                BigInteger ret = new BigInteger(X_);
                return ret;
            }
        }
    }
}
