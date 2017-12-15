using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace FPELibrary
{
    internal static class Utility
    {
        internal static byte[] encode(this BigInteger n)
        {
            if (n.IsZero) return new byte[0];
            else return n.ToByteArray().Reverse().SkipWhile(h => h == 0).ToArray();
        }

        internal static BigInteger mod(this BigInteger n, BigInteger op)
        {
            BigInteger x = n % op;
            if (x.Sign >= 0) return x;
            else return op + x;
        }

        internal static void Swap<T>(ref T a, ref T b)
        {
            T tmp = a;
            a = b;
            b = tmp;
        }

        internal static void update(this MemoryStream mac, byte[] num)
        {
            mac.Write(num, 0, num.Length);
        }

        internal static void update_be(this MemoryStream mac, int num)
        {
            var bytes = BitConverter.GetBytes(num);
            for (int i = 3; i >= 0; --i)
            {
                byte b = bytes[i];
                mac.WriteByte(b);
            }
        }
    }
}
