using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Numerics;
using FPELibrary;
using System.Text;

namespace TestFPE
{
    [TestClass]
    public class FPETests
    {
        static byte[] key = Encoding.Unicode.GetBytes("Here's my secret key!");
        static byte[] tweak = Encoding.Unicode.GetBytes("Here's my tweak");

        [TestMethod]
        public void TestNumericEncryption()
        {
            int range = 1000;
            BigInteger modulus = new BigInteger(range);

            BigInteger plain = new BigInteger(0);

            BigInteger enc = FE1.Encrypt(modulus, plain, key, tweak);
            BigInteger dec = FE1.Decrypt(modulus, enc, key, tweak);

            Assert.AreEqual(plain, dec);
        }


        [TestMethod]
        public void StressTestNumericEncryption()
        {
            int range = 10000;
            BigInteger modulus = new BigInteger(range);

            Random r = new Random();
            int times = 10000;   
            for (int i = 0; i < times; i++)
            {
                
                BigInteger plain = new BigInteger(r.Next(0, range));

                BigInteger enc = FE1.Encrypt(modulus, plain, key, tweak);
                BigInteger dec = FE1.Decrypt(modulus, enc, key, tweak);

                Assert.AreEqual(plain, dec);
            }
            
        }
    }
}
