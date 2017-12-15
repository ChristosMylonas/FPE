using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace FPELibrary
{
    public static class FPEWrapper
    {
        #region ulong
        public static ulong EncryptULong(byte[] key, byte[] tweak, ulong source, ulong range = ulong.MaxValue)
        {
            if (source >= ulong.MaxValue)
                throw new ArgumentException($"source should be less than {uint.MaxValue}");

            if (source > range)
                throw new ArgumentException($"source should be less than range");

            BigInteger modulus = new BigInteger(range);
            BigInteger plain = new BigInteger(source);
            BigInteger result = FE1.Encrypt(modulus, plain, key, tweak);

            return (ulong)result;
        }

        public static ulong DecryptULong(byte[] key, byte[] tweak, ulong source, ulong range = ulong.MaxValue)
        {
            if (source >= ulong.MaxValue)
                throw new ArgumentException($"source should be less than {uint.MaxValue}");

            if (source > range)
                throw new ArgumentException($"source should be less than range");

            BigInteger modulus = new BigInteger(range);
            BigInteger sourceBI = new BigInteger(source);
            BigInteger result = FE1.Decrypt(modulus, sourceBI, key, tweak);

            return (ulong)result;
        }
        #endregion

        #region uint
        public static uint EncryptUInt(byte[] key, byte[] tweak, uint source, uint range = uint.MaxValue)
        {
            if (source >= uint.MaxValue)
                throw new ArgumentException($"source should be less than {uint.MaxValue}");

            if (source > range)
                throw new ArgumentException($"source should be less than range");

            BigInteger modulus = new BigInteger(range);
            BigInteger plain = new BigInteger(source);
            BigInteger result = FE1.Encrypt(modulus, plain, key, tweak);

            return (uint)result;
        }

        public static uint DecryptUInt(byte[] key, byte[] tweak, uint source, uint range = uint.MaxValue)
        {
            if (source >= uint.MaxValue)
                throw new ArgumentException($"source should be less than {uint.MaxValue}");

            if (source > range)
                throw new ArgumentException($"source should be less than range");

            BigInteger modulus = new BigInteger(range);
            BigInteger sourceBI = new BigInteger(source);
            BigInteger result = FE1.Decrypt(modulus, sourceBI, key, tweak);

            return (uint)result;
        }
        #endregion
        
        #region int ranking
        const int BASE_RANKING_VALUE = int.MinValue + 1;
        public static uint RankInt(int source)
        {
            if (source >= int.MaxValue - 1)
                throw new ArgumentException($"source should be less than {int.MaxValue} + 1");

            if (source <= int.MinValue + 1)
                throw new ArgumentException($"source should be greater than {int.MinValue} - 1");

            uint result = (uint)(source + BASE_RANKING_VALUE);
            return result;
        }

        public static int UnrankInt(uint source)
        {
            int result = (int)(source - BASE_RANKING_VALUE);
            return result;
        }
        #endregion

        #region int
        public static uint EncryptInt(byte[] key, byte[] tweak, int source)
        {
            if (source >= int.MaxValue - 1)
                throw new ArgumentException($"source should be less than {int.MaxValue} + 1");

            if (source <= int.MinValue + 1)
                throw new ArgumentException($"source should be greater than {int.MinValue} - 1");


            uint rankedValue = RankInt(source);
            uint result = EncryptUInt(key, tweak, rankedValue);

            return result;
        }

        public static int DecryptInt(byte[] key, byte[] tweak, uint source)
        {
            uint result = DecryptUInt(key, tweak, source);
            int unrankedValue = UnrankInt(result);


            return unrankedValue;
        }
        #endregion

        #region long ranking
        const long BASE_LONG_RANKING_VALUE = long.MinValue + 1;
        public static ulong RankLong(long source)
        {
            if (source >= long.MaxValue - 1)
                throw new ArgumentException($"source should be less than {long.MaxValue} + 1");

            if (source <= long.MinValue + 1)
                throw new ArgumentException($"source should be greater than {long.MinValue} - 1");

            ulong result = (ulong)(source + BASE_LONG_RANKING_VALUE);
            return result;
        }

        public static long UnrankLong(ulong source)
        {
            long result = ((long)source - BASE_LONG_RANKING_VALUE);
            return result;
        }
        #endregion

        #region long
        public static ulong EncryptLong(byte[] key, byte[] tweak, long source)
        {
            if (source >= long.MaxValue - 1)
                throw new ArgumentException($"source should be less than {long.MaxValue} + 1");

            if (source <= long.MinValue + 1)
                throw new ArgumentException($"source should be greater than {long.MinValue} - 1");


            ulong rankedValue = RankLong(source);
            ulong result = EncryptULong(key, tweak, rankedValue);

            return result;
        }

        public static long DecryptLong(byte[] key, byte[] tweak, ulong source)
        {
            ulong result = DecryptULong(key, tweak, source);
            long unrankedValue = UnrankLong(result);


            return unrankedValue;
        }
        #endregion

        #region DateTime
        static DateTime MaxPossibleDate = new DateTime(2999, 12, 31);
        public static DateTime EncryptDateTime(byte[] key, byte[] tweak, DateTime source)
        {
            if (source >= MaxPossibleDate)
                throw new ArgumentException($"source should be less than {MaxPossibleDate}");

            ulong ticks = (ulong)source.Ticks;
            ulong maxTicks = (ulong) new DateTime(2999, 12, 31).Ticks;

            var result = EncryptULong(key, tweak, ticks, maxTicks);

            return new DateTime((long)result);
        }

        public static DateTime DecryptDateTime(byte[] key, byte[] tweak, DateTime source)
        {
            ulong ticks = (ulong)source.Ticks;
            ulong maxTicks = (ulong)new DateTime(2999, 12, 31).Ticks;

            var result = DecryptULong(key, tweak, ticks, maxTicks);

            return new DateTime((long)result);
        }
        #endregion

        #region decimal
        public static Decimal EncryptDecimal(byte[] key, byte[] tweak, Decimal source)
        {
            var roundedSource = Math.Round(source, 5);
            var withoutFractions = roundedSource * 100000M;
            var asLong = Decimal.ToInt64(withoutFractions);

            var encrypted = EncryptLong(key, tweak, asLong);
            var result = new Decimal(encrypted);
            return result;
        }

        public static Decimal DecryptDecimal(byte[] key, byte[] tweak, Decimal source)
        {
            var asLong = Decimal.ToUInt64(source);
            var plain = DecryptLong(key, tweak, asLong);

            decimal withFractions = plain / 100000M;
            Decimal result = Math.Round(withFractions, 5);

            return result;
        }
        #endregion

        #region String using FPE
        static ulong maxChar = Convert.ToUInt64(Char.MaxValue);
        public static string EncryptString(byte[] key, byte[] tweak, string source)
        {
            StringBuilder result = new StringBuilder();
            foreach (var item in source)
                result.Append(Convert.ToChar(EncryptULong(key, tweak, Convert.ToUInt64(item), maxChar)));

            return result.ToString();
        }

        public static string DecryptString(byte[] key, byte[] tweak, string source)
        {
            StringBuilder result = new StringBuilder();
            foreach (var item in source)
                result.Append(Convert.ToChar(DecryptULong(key, tweak, Convert.ToUInt64(item), maxChar)));

            return result.ToString();
        }
        #endregion
    }
}
