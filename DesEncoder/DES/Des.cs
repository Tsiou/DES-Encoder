using System;
using System.Collections.Generic;

namespace DesEncoder.DES
{
    static class Des
    {
        public static void Encrypt(string message, ulong key)
        {
            List<ulong> subkeys = Encrypter.GenerateKeys(key);

            var ciphertext = Encrypter.Encode(Convert.ToUInt64(message.ToHex()), subkeys);

            Console.WriteLine($"binary representation: { Encrypter.ToBinary(ciphertext)}");
            Console.WriteLine();
            Console.WriteLine($"base64 representation: { Convert.ToBase64String(BitConverter.GetBytes(ciphertext))}");
            Console.ReadKey();
            Console.Clear();
        }

        public static string ToHex(this string str)
        {
            char[] charValues = str.ToCharArray();
            string hexOutput = string.Empty;
            foreach (char ch in charValues)
            {
                int value = Convert.ToInt32(ch);
                hexOutput += $"{value:X}";
            }

            return hexOutput;
        }
    }
}
