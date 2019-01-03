using DesEncoder.DES;

namespace DesEncoder
{
    class Program
    {
        static void Main(string[] args)
        {
            string message = "TSITSIRI";

            ulong key = 0xF46E986435465354;

            Des.Encrypt(message, key);
        }
    }
}