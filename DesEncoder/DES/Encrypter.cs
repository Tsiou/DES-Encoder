using DesEncoder.DES.Constants;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DesEncoder.DES
{
    public static class Encrypter
    {
        private static int[] LeftShifts { get; } = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        /// <summary>
        /// Generates the 16 subkeys from the key provided.
        /// </summary>
        /// <param name="key">The key provided, must be a 64 bit unsigned long.</param>
        /// <returns>A list of subkeys to be used for the encryption.</returns>
        public static List<ulong> GenerateKeys(ulong key)
        {
            Console.WriteLine($"Creating subkeys from {key.ToBinary()}");
            ulong permutedKey = Permute(key, PermutationData.FirstPermutation);
            ulong c = Left28(permutedKey);
            ulong d = Right28(permutedKey);
            Console.WriteLine();
            Console.WriteLine($"Left  side of the key in bits: {c.ToBinary().Substring(0, 28)}.");
            Console.WriteLine($"Right side of the key in bits: {d.ToBinary().Substring(0, 28)}.");
            Console.WriteLine();
            Console.WriteLine("Starting rounds of subkey generation, press any key to continue.");
            Console.ReadKey();

            var subKeys = new List<Pair> { new Pair { Left = c, Right = d } };

            for (int i = 1; i <= LeftShifts.Count(); i++)
            {
                if (i - 1 > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine($"Clearing round {i - 1}, press any key to continue");
                    Console.ReadKey();
                }
                Console.Clear();
                Console.WriteLine($"Round {i} Initial values:");
                Console.WriteLine($"Left  subkey (C): {subKeys[i - 1].Left.ToBinary().First28Bits()}");
                Console.WriteLine($"Right subkey (D): {subKeys[i - 1].Right.ToBinary().First28Bits()}");
                var keyPair = new Pair
                {
                    Left = LeftShift56(subKeys[i - 1].Left, LeftShifts[i - 1]),
                    Right = LeftShift56(subKeys[i - 1].Right, LeftShifts[i - 1])
                };
                subKeys.Add(keyPair);
                Console.WriteLine();
                Console.WriteLine($"After shifting:");
                Console.WriteLine($"Left  subkey: {keyPair.Left.ToBinary().First28Bits()}");
                Console.WriteLine($"Right subkey: {keyPair.Right.ToBinary().First28Bits()}");
            }

            var result = new List<ulong>();

            Console.WriteLine();
            Console.WriteLine("Starting round key permutations, press any key to begin.");

            for (int i = 0; i < subKeys.Count; i++)
            {
                if (i % 3 == 0)
                {
                    if (i != 0)
                    {
                        Console.WriteLine("Press any key to continue");
                    }
                    Console.ReadKey();
                    Console.Clear();
                }
                Console.WriteLine();
                ulong joined = Concat56(subKeys[i].Left, subKeys[i].Right);
                Console.WriteLine($"Round {i.ToString("00")} subkey, before permutation: {joined.ToBinary().First56Bits()}.");
                ulong permuted = Permute(joined, PermutationData.SecondPermutation);
                Console.WriteLine($"Subkey after permutation:            {permuted.ToBinary().First56Bits()}.");
                Console.WriteLine();

                result.Add(permuted);
            }
            return result;
        }

        public static ulong Encode(ulong block, List<ulong> subKeys)
        {
            Console.WriteLine("Starting on message encryption, press any key to continue.");
            Console.ReadKey();
            Console.Clear();
            Console.WriteLine($"Processing through the initial permutation: {block.ToBinary()}");
            ulong permutedBlock = Permute(block, PermutationData.InitialPermutation);
            Console.WriteLine($"Block after the initial permutation:        {permutedBlock.ToBinary()}");
            Console.WriteLine();

            var pair = new Pair
            {
                Left = permutedBlock & 0xFFFFFFFF00000000,
                Right = (permutedBlock & 0x00000000FFFFFFFF) << 32
            };

            Console.WriteLine("The two block parts are:");
            Console.WriteLine($"Left:  {pair.Left.ToBinary().First32Bits()}");
            Console.WriteLine($"Right: {pair.Right.ToBinary().First32Bits()}");

            Console.WriteLine();
            Console.WriteLine("Starting the encryption rounds, press any key to continue.");
            Console.ReadKey();
            Console.Clear();
            for (int i = 0; i < 16; i++)
            {
                Console.WriteLine($"Round {i + 1}");
                pair = new Pair
                {
                    Left = pair.Right,
                    Right = pair.Left ^ Ffunction(pair.Right, subKeys[i + 1])
                };
                if (i != 15)
                {
                    Console.WriteLine("Starting next round, press any key to continue.");
                    Console.ReadKey();
                }
                Console.Clear();
            }

            ulong joined = pair.Right | (pair.Left >> 32);
            Console.WriteLine($"After applying F and XOR:               { joined.ToBinary()}");

            var afterInvPermutation = Permute(joined, PermutationData.InvertedInitialPermutation);
            Console.WriteLine($"After the inverted initial permutation: {afterInvPermutation.ToBinary()}");
            Console.WriteLine();
            return afterInvPermutation;
        }

        /// <summary>
        /// We use the logical AND operator to only get the bits we're interested in from the original value.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns>the value with only the first 28 bits containing the original values.</returns>
        public static ulong Left28(ulong key)
        {
            return key & 0xFFFFFFF000000000;
        }

        /// <summary>
        /// We use the logical AND operator to only get the bits we're interested in from the original value.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns>the value with only the first 28 bits containing the original values.</returns>
        public static ulong Right28(ulong key)
        {
            return (key << 28) & 0xFFFFFFF000000000;
        }

        // Join two 56 bit values
        /// <summary>
        /// Takes in the two key halves and creates a 56 bit by concatenating the left and right sides
        /// by using logical OR on the bits that are important to the key generation.
        /// </summary>
        /// <param name="leftHalf">the left half</param>
        /// <param name="rightHalf">the right half</param>
        /// <returns>the key as is used in the encryption</returns>
        public static ulong Concat56(ulong leftHalf, ulong rightHalf)
        {
            return (leftHalf & 0xFFFFFFF000000000) | ((rightHalf & 0xFFFFFFF000000000) >> 28);
        }

        // 56 bit left shift
        public static ulong LeftShift56(ulong val, int count)
        {
            for (int i = 0; i < count; i++)
            {
                ulong msb = val & 0x8000000000000000;
                val = (val << 1) & 0xFFFFFFE000000000 | msb >> 27;
            }

            return val;
        }

        // Input is left aligned 48 bit value
        // Output is 8 left aligned 6 bit values
        public static List<byte> Split(ulong val)
        {
            var result = new List<byte>();

            for (int i = 0; i < 8; i++)
            {
                result.Add((byte)((val & 0xFC00000000000000) >> 56));

                val <<= 6;
            }

            return result;
        }

        public static byte SBoxLookup(byte val, int table)
        {
            int index = ((val & 0x80) >> 2) | ((val & 0x04) << 2) | ((val & 0x78) >> 3);
            return SubstitutionBoxes.SBoxes[table, index];
        }

        public static ulong Permute(ulong val, int[] changes)
        {
            ulong result = 0;
            const int size = sizeof(ulong) * 8;

            for (int i = 0; i < changes.Length; i++)
            {
                ulong bit = val >> size - changes[i] & 1;
                result |= bit << size - i - 1;
            }

            return result;
        }

        public static ulong Ffunction(ulong right, ulong key)
        {
            Console.WriteLine($"Right key from previous round: {right.ToBinary().First32Bits()}.");
            Console.WriteLine();
            Console.WriteLine($"Key for this round:            {key.ToBinary().First48Bits()}");
            ulong expansion = Permute(right, PermutationData.ExpansionPermutation);
            Console.WriteLine($"Expanded right key:            {expansion.ToBinary().First48Bits()}");

            ulong x = expansion ^ key;
            Console.WriteLine($"After XOR with key:            {x.ToBinary().First48Bits()}");

            var bs = Split(x);

            ulong boxLookup = 0;

            for (int i = 0; i < 8; i++)
            {
                boxLookup <<= 4;
                boxLookup |= SBoxLookup(bs[i], i);
            }

            boxLookup <<= 32;

            Console.WriteLine();
            Console.WriteLine($"values after substitution box lookup: {boxLookup.ToBinary().First32Bits()}");
            var result = Permute(boxLookup, PermutationData.PPermutation);

            Console.WriteLine($"Permuted block after P permutation:   {result.ToBinary().First32Bits()}");

            return result;
        }

        #region Extensions for ease of use
        public static string ToBinary(this ulong value)
        {
            return Convert.ToString((long)value, 2);
        }

        public static string First28Bits(this string str)
        {
            return str.Substring(0, 28);
        }

        public static string First32Bits(this string str)
        {
            return str.Substring(0, 32);
        }

        public static string First56Bits(this string str)
        {
            return str.Substring(0, 56);
        }

        public static string First48Bits(this string str)
        {
            return str.Substring(0, 48);
        }
        
        #endregion
    }

    public struct Pair
    {
        public ulong Left;
        public ulong Right;
    }
}
