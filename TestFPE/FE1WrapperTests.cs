using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Numerics;
using FPELibrary;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace TestFPE
{
    [TestClass]
    public class FPEWrapperTests
    {
        #region common keys
        static byte[] key = Encoding.Unicode.GetBytes("Here's my secret key!");
        static byte[] tweak = Encoding.Unicode.GetBytes("Here's my tweak");
        #endregion

        #region ulong
        [TestMethod]
        public void TestULongEncryptionMax()
        {
            ulong plain = ulong.MaxValue - 1;

            var enc = FPEWrapper.EncryptULong(key, tweak, plain);
            var dec = FPEWrapper.DecryptULong(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void TestULongEncryptionMin()
        {
            ulong plain = ulong.MinValue + 1;

            var enc = FPEWrapper.EncryptULong(key, tweak, plain);
            var dec = FPEWrapper.DecryptULong(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void TestULongEncryptionZero()
        {
            ulong plain = 0;

            var enc = FPEWrapper.EncryptULong(key, tweak, plain);
            var dec = FPEWrapper.DecryptULong(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void TestULongEncryptionRandom()
        {
            Random r = new Random();
            int times = 1000;
            for (int i = 0; i < times; i++)
            {

                ulong plain = (ulong)r.Next(0, int.MaxValue);

                var enc = FPEWrapper.EncryptULong(key, tweak, plain);
                var dec = FPEWrapper.DecryptULong(key, tweak, enc);

                Assert.AreEqual(plain, dec);
            }
        }
        #endregion

        #region uint
        [TestMethod]
        public void TestUIntEncryptionMax()
        {
            uint plain = uint.MaxValue - 1;

            var enc = FPEWrapper.EncryptUInt(key, tweak, plain);
            var dec = FPEWrapper.DecryptUInt(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void TestUIntEncryptionMin()
        {
            uint plain = uint.MinValue + 1;

            var enc = FPEWrapper.EncryptUInt(key, tweak, plain);
            var dec = FPEWrapper.DecryptUInt(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void TestUIntEncryptionZero()
        {
            uint plain = 0;

            var enc = FPEWrapper.EncryptUInt(key, tweak, plain);
            var dec = FPEWrapper.DecryptUInt(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void TestUIntEncryptionRandom()
        {
            Random r = new Random();
            int times = 1000;
            for (int i = 0; i < times; i++)
            {

                uint plain = (uint)r.Next(0, int.MaxValue);

                var enc = FPEWrapper.EncryptUInt(key, tweak, plain);
                var dec = FPEWrapper.DecryptUInt(key, tweak, enc);

                Assert.AreEqual(plain, dec);
            }
        }
        #endregion

        #region int ranking
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingMax()
        {
            FPEWrapper.RankInt(int.MaxValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingMin()
        {
            FPEWrapper.RankInt(int.MinValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingMaxMinusOne()
        {
            int initial = int.MaxValue - 1;
            var rankedValue = FPEWrapper.RankInt(initial);
            var unrankedValue = FPEWrapper.UnrankInt(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }

        [TestMethod]
        public void TestRankingZero()
        {
            int initial = 0;
            var rankedValue = FPEWrapper.RankInt(initial);
            var unrankedValue = FPEWrapper.UnrankInt(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingMinPlusOne()
        {
            int initial = int.MinValue + 1;
            var rankedValue = FPEWrapper.RankInt(initial);
            var unrankedValue = FPEWrapper.UnrankInt(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }
        #endregion

        #region Safe int ranking
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIntToIntRankingMax()
        {
            FPEWrapper.RankIntToSafeInt(FPEWrapper.MaxAllowedSafeInt);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIntToIntRankingMin()
        {
            FPEWrapper.RankIntToSafeInt(FPEWrapper.MinAllowedSafeInt);
        }

        [TestMethod]
        public void TestIntToIntRankingMaxMinusOne()
        {
            int initial = FPEWrapper.MaxAllowedSafeInt - 1;
            var rankedValue = FPEWrapper.RankIntToSafeInt(initial);
            var unrankedValue = FPEWrapper.UnrankSafeIntToInt(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }

        [TestMethod]
        public void TestIntToIntRankingZero()
        {
            int initial = 0;
            var rankedValue = FPEWrapper.RankIntToSafeInt(initial);
            var unrankedValue = FPEWrapper.UnrankSafeIntToInt(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }

        [TestMethod]
        public void TestIntToIntRankingMinPlusOne()
        {
            int initial = FPEWrapper.MinAllowedSafeInt + 1;
            var rankedValue = FPEWrapper.RankIntToSafeInt(initial);
            var unrankedValue = FPEWrapper.UnrankSafeIntToInt(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }
        #endregion

        #region int
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIntEncryptionMax()
        {
            FPEWrapper.EncryptInt(key, tweak, int.MaxValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIntEncryptionMaxMinusOne()
        {
            FPEWrapper.EncryptInt(key, tweak, int.MaxValue - 1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIntEncryptionMin()
        {
            FPEWrapper.EncryptInt(key, tweak, int.MinValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIntEncryptionMinPlusOne()
        {
            FPEWrapper.EncryptInt(key, tweak, int.MinValue + 1);
        }

        [TestMethod]
        public void TestIntEncryptionMaxMinusTwo()
        {
            int initial = int.MaxValue - 2;
            var encryptedValue = FPEWrapper.EncryptInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }

        [TestMethod]
        public void TestIntEncryptionZero()
        {
            int initial = 0;
            var encryptedValue = FPEWrapper.EncryptInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestIntEncryptionMinusOne()
        {
            int initial = -1;
            var encryptedValue = FPEWrapper.EncryptInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestIntEncryptionMinPlusTwo()
        {
            int initial = int.MinValue + 2;
            var encryptedValue = FPEWrapper.EncryptInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }
        #endregion

        #region Safe int
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestSafeIntEncryptionMax()
        {
            FPEWrapper.EncryptSafeInt(key, tweak, FPEWrapper.MaxAllowedSafeInt);
        }

        [TestMethod]
        public void TestSafeIntEncryptionMaxMinusOne()
        {
            int initial = FPEWrapper.MaxAllowedSafeInt - 1;
            var encryptedValue = FPEWrapper.EncryptSafeInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptSafeInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestSafeIntEncryptionMin()
        {
            FPEWrapper.EncryptSafeInt(key, tweak, FPEWrapper.MinAllowedSafeInt);
        }

        [TestMethod]
        public void TestSafeIntEncryptionMinPlusOne()
        {
            int initial = FPEWrapper.MinAllowedSafeInt + 1;
            var encryptedValue = FPEWrapper.EncryptSafeInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptSafeInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestSafeIntEncryptionMaxMinusTwo()
        {
            int initial = FPEWrapper.MaxAllowedSafeInt - 2;
            var encryptedValue = FPEWrapper.EncryptSafeInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptSafeInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }

        [TestMethod]
        public void TestSafeIntEncryptionZero()
        {
            int initial = 0;
            var encryptedValue = FPEWrapper.EncryptSafeInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptSafeInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestSafeIntEncryptionMinusOne()
        {
            int initial = -1;
            var encryptedValue = FPEWrapper.EncryptSafeInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptSafeInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestSafeIntEncryptionMinPlusTwo()
        {
            int initial = FPEWrapper.MinAllowedSafeInt + 2;
            var encryptedValue = FPEWrapper.EncryptSafeInt(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptSafeInt(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }

        [TestMethod]
        public void StressTestSafeIntEncryption()
        {
            Random r = new Random();
            int times = 10000;
            for (int i = 0; i < times; i++)
            {
                int plain = r.Next(FPEWrapper.MinAllowedSafeInt, FPEWrapper.MaxAllowedSafeInt);
                var encryptedValue = FPEWrapper.EncryptSafeInt(key, tweak, plain);
                var decryptedValue = FPEWrapper.DecryptSafeInt(key, tweak, encryptedValue);
                Console.WriteLine($"Src:{plain}, Dest:{decryptedValue}");
                Assert.AreEqual(plain, decryptedValue);
            }
        }
        #endregion

        #region long ranking
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingLongMax()
        {
            FPEWrapper.RankLong(long.MaxValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingLongMin()
        {
            FPEWrapper.RankLong(long.MinValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingLongMaxMinusOne()
        {
            long initial = long.MaxValue - 1;
            var rankedValue = FPEWrapper.RankLong(initial);
            var unrankedValue = FPEWrapper.UnrankLong(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }

        [TestMethod]
        public void TestRankingLongZero()
        {
            long initial = 0;
            var rankedValue = FPEWrapper.RankLong(initial);
            var unrankedValue = FPEWrapper.UnrankLong(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestRankingLongMinPlusOne()
        {
            long initial = long.MinValue + 1;
            var rankedValue = FPEWrapper.RankLong(initial);
            var unrankedValue = FPEWrapper.UnrankLong(rankedValue);
            Assert.AreEqual(initial, unrankedValue);

        }
        #endregion

        #region long
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestLongEncryptionMax()
        {
            FPEWrapper.EncryptLong(key, tweak, long.MaxValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestLongEncryptionMaxMinusOne()
        {
            FPEWrapper.EncryptLong(key, tweak, long.MaxValue - 1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestLongEncryptionMin()
        {
            FPEWrapper.EncryptLong(key, tweak, long.MinValue);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestLongEncryptionMinPlusOne()
        {
            FPEWrapper.EncryptLong(key, tweak, long.MinValue + 1);
        }

        [TestMethod]
        public void TestLongEncryptionMaxMinusTwo()
        {
            long initial = long.MaxValue - 2;
            var encryptedValue = FPEWrapper.EncryptLong(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptLong(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }

        [TestMethod]
        public void TestLongEncryptionZero()
        {
            long initial = 0;
            var encryptedValue = FPEWrapper.EncryptLong(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptLong(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestLongEncryptionMinusOne()
        {
            long initial = -1;
            var encryptedValue = FPEWrapper.EncryptLong(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptLong(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestLongEncryptionMinPlusTwo()
        {
            long initial = long.MinValue + 2;
            var encryptedValue = FPEWrapper.EncryptLong(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptLong(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }

        [TestMethod]
        public void StressTestLongEncryption()
        {
            Random r = new Random();
            int times = 10000;
            for (int i = 0; i < times; i++)
            {
                int plain = r.Next(int.MinValue + 2, int.MaxValue - 2);
                var enc = FPEWrapper.EncryptLong(key, tweak, plain);
                var dec = FPEWrapper.DecryptLong(key, tweak, enc);
                Console.WriteLine($"Src:{enc}, Dest:{dec}");
                Assert.AreEqual(plain, dec);
            }
        }
        #endregion

        #region DateTime
        [TestMethod]
        public void TestDateEncryption()
        {
            var plain = DateTime.Now;

            DateTime enc = FPEWrapper.EncryptDateTime(key, tweak, plain);
            DateTime dec = FPEWrapper.DecryptDateTime(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }


        [TestMethod]
        public void StressTestDateEncryption()
        {
            Random r = new Random();
            int times = 1000;
            for (int i = 0; i < times; i++)
            {
                int year = r.Next(1900, 2020);
                int month = r.Next(1, 12);
                int date = r.Next(1, 28);

                int hour = r.Next(0, 23);
                int minute = r.Next(0, 59);
                int sec = r.Next(0, 59);
                int ms = r.Next(0, 999);
                var plain = new DateTime(year, month, date, hour, minute, sec, ms);

                DateTime enc = FPEWrapper.EncryptDateTime(key, tweak, plain);
                DateTime dec = FPEWrapper.DecryptDateTime(key, tweak, enc);
                Console.WriteLine($"Src:{enc}, Dest:{dec}");
                Assert.AreEqual(plain, dec);
            }
        }
        #endregion

        #region SqlDateTime
        [TestMethod]
        public void TestSqlDateEncryption()
        {
            var plain = DateTime.Now;

            DateTime enc = FPEWrapper.EncryptSqlDateTime(key, tweak, plain);
            DateTime dec = FPEWrapper.DecryptSqlDateTime(key, tweak, enc);

            Assert.AreEqual(plain, dec);

        }

        [TestMethod]
        public void TestSqlDateEncryption2()
        {
            var plain = new DateTime(1984, 10, 1);

            DateTime enc = FPEWrapper.EncryptSqlDateTime(key, tweak, plain);
            DateTime dec = FPEWrapper.DecryptSqlDateTime(key, tweak, enc);

            Assert.AreEqual(plain, dec);

        }

        [TestMethod]
        public void TestSqlDateEncryptionMin()
        {
            var plain = FPEWrapper.MinPossibleSqlDate;

            DateTime enc = FPEWrapper.EncryptSqlDateTime(key, tweak, plain);
            DateTime dec = FPEWrapper.DecryptSqlDateTime(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void TestSqlDateEncryptionMax()
        {
            var plain = FPEWrapper.MaxPossibleSqlDate;

            DateTime enc = FPEWrapper.EncryptSqlDateTime(key, tweak, plain);
            DateTime dec = FPEWrapper.DecryptSqlDateTime(key, tweak, enc);

            Assert.AreEqual(plain, dec);
        }

        [TestMethod]
        public void StressTestSqlDateEncryption()
        {
            Random r = new Random();
            int times = 10000;
            for (int i = 0; i < times; i++)
            {
                int year = r.Next(1900, 2020);
                int month = r.Next(1, 12);
                int date = r.Next(1, 28);

                int hour = r.Next(0, 23);
                int minute = r.Next(0, 59);
                int sec = r.Next(0, 59);
                int ms = r.Next(0, 999);
                var plain = new DateTime(year, month, date, hour, minute, sec, ms);

                DateTime enc = FPEWrapper.EncryptSqlDateTime(key, tweak, plain);
                DateTime dec = FPEWrapper.DecryptSqlDateTime(key, tweak, enc);
                Console.WriteLine($"Src:{enc}, Dest:{dec}");
                Assert.AreEqual(plain, dec);
            }
        }
        #endregion

        #region Decimal
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestDecimalEncryptionMax()
        {
            FPEWrapper.EncryptDecimal(key, tweak, FPEWrapper.MaxAllowedDecimal);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestDecimalEncryptionMaxMinusOne()
        {
            FPEWrapper.EncryptDecimal(key, tweak, FPEWrapper.MaxAllowedDecimal - 0.00001M);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestDecimalEncryptionMin()
        {
            FPEWrapper.EncryptDecimal(key, tweak, FPEWrapper.MinAllowedDecimal);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestDecimalEncryptionMinPlusOne()
        {
            FPEWrapper.EncryptDecimal(key, tweak, FPEWrapper.MinAllowedDecimal + 0.00001M);
        }

        [TestMethod]
        public void TestDecimalEncryptionMaxMinusTwo()
        {
            Decimal initial = FPEWrapper.MaxAllowedDecimal - 0.00002M;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }

        [TestMethod]
        public void TestDecimalEncryptionZero()
        {
            Decimal initial = 0;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestDecimalEncryptionOneDecimalPoint()
        {
            Decimal initial = 0.1M;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestDecimalEncryptionTwoDecimalPoints()
        {
            Decimal initial = 0.01M;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestDecimalEncryptionThreeDecimalPoints()
        {
            Decimal initial = 0.001M;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestDecimalEncryptionFourDecimalPoints()
        {
            Decimal initial = 0.0001M;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestDecimalEncryptionFiveDecimalPoints()
        {
            Decimal initial = 0.00001M;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestDecimalEncryptionMinusOne()
        {
            Decimal initial = -1;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);
        }

        [TestMethod]
        public void TestDecimalEncryptionMinPlusTwo()
        {
            Decimal initial = FPEWrapper.MinAllowedDecimal + 0.00002M;
            var encryptedValue = FPEWrapper.EncryptDecimal(key, tweak, initial);
            var decryptedValue = FPEWrapper.DecryptDecimal(key, tweak, encryptedValue);

            Assert.AreEqual(initial, decryptedValue);

        }

        [TestMethod]
        public void StressTestDecimalEncryption()
        {
            Random r = new Random();
            int times = 10000;
            for (int i = 0; i < times; i++)
            {
                Decimal plain = r.Next(int.MinValue + 2, int.MaxValue - 2);
                var enc = FPEWrapper.EncryptDecimal(key, tweak, plain);
                var dec = FPEWrapper.DecryptDecimal(key, tweak, enc);
                Console.WriteLine($"Src:{enc}, Dest:{dec}");
                Assert.AreEqual(plain, dec);
            }
        }
        #endregion

        #region String using FPE 

        public static string GetRandomString(int size)
        {
            Random r = new Random(DateTime.Now.Millisecond);
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < size; i++)
            {
                var randomChar = r.Next(Char.MinValue, Char.MaxValue);
                result.Append(Convert.ToChar(randomChar));
            }

            return result.ToString();
        }

        public static string GetRandomString(int size, char min, char max)
        {
            Random r = new Random(DateTime.Now.Millisecond);
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < size; i++)
            {
                var randomChar = r.Next(min, max);
                result.Append(Convert.ToChar(randomChar));
            }

            return result.ToString();
        }

        [TestMethod]
        public void TestStringEncryption()
        {
            var plain = "hello world";

            var enc = FPEWrapper.EncryptString(key, tweak, plain);

            var dec = FPEWrapper.DecryptString(key, tweak, enc);

            Assert.AreEqual(plain, dec);
            Assert.AreEqual(plain.Length, dec.Length);
        }


        [TestMethod]
        public void StressTestStringEncryption()
        {
            Random r = new Random();
            int times = 1000;
            for (int i = 0; i < times; i++)
            {
                var plain = GetRandomString(20);

                var enc = FPEWrapper.EncryptString(key, tweak, plain);
                var dec = FPEWrapper.DecryptString(key, tweak, enc);
                Console.WriteLine($"Src:{enc}, Dest:{dec}");
                Assert.AreEqual(plain, dec);
                Assert.AreEqual(plain.Length, dec.Length);
            }
        }

        public List<string> GetRandomStrings(int size, int stringSize, char min, char max)
        {
            HashSet<string> results = new HashSet<string>();

            Random r = new Random();
            for (int i = 0; i < size; i++)
            {
                string s = GetRandomString(stringSize, min, max);
                while (results.Contains(s))
                {
                    s = GetRandomString(stringSize, min, max);
                }
                results.Add(s);
            }

            return results.ToList();
        }


        [TestMethod]
        public void StressTestStringEncryptionUniqueness()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();


            int times = 1000;
            Random r = new Random();
            List<string> randomInput = GetRandomStrings(times, 20, char.MinValue, char.MaxValue);
            for (int i = 0; i < times; i++)
            {
                var plain = randomInput[i];

                var enc = FPEWrapper.EncryptString(key, tweak, plain);
                var dec = FPEWrapper.DecryptString(key, tweak, enc);
                Console.WriteLine($"Src:{enc}, Dest:{dec}");
                Assert.AreEqual(plain, dec);
                Assert.AreEqual(plain.Length, dec.Length);

                if (results.ContainsKey(enc))
                    Assert.Fail($"results already contains Encrypted value:{enc} for Plain text:{results[enc]}");
                else
                    results.Add(enc, plain);
            }

            
        }

        [TestMethod]
        public void TestStringEncryptionUniqueness()
        {
            Dictionary<string, string> results = new Dictionary<string, string>();


            List<string> randomInput = new List<string>()
            {
                "01",
                "02",
                "03",
                "04",
                "05",
                "06",
                "07",
                "08",
                "09",
                "1",
                "10",
                "11",
                "12",
                "13",
                "14",
                "15",
                "16",
                "17",
                "18",
                "19",
                "99",
                "Demo"
            };
            for (int i = 0; i < randomInput.Count; i++)
            {
                var plain = randomInput[i];

                var enc = FPEWrapper.EncryptString(key, tweak, plain);
                var dec = FPEWrapper.DecryptString(key, tweak, enc);
                Console.WriteLine($"Src:{enc}, Dest:{dec}");
                Assert.AreEqual(plain, dec);
                Assert.AreEqual(plain.Length, dec.Length);

                if (results.ContainsKey(enc))
                    Assert.Fail($"results already contains Encrypted value:{enc} for Plain text:{results[enc]}");
                else
                    results.Add(enc, plain);
            }


        }
        #endregion
    }
}
