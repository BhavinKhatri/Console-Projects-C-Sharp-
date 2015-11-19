using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            //Rendomly generated 30 character key.
            //Create Unique key from RNGCryptoServiceProvider 
            //http://www.codeproject.com/Articles/14403/Generating-Unique-Keys-in-Net

            var guid = Guid.NewGuid().ToString();

            Aes aesEncryption = Aes.Create();
            aesEncryption.KeySize = 256;
            aesEncryption.GenerateKey();
            string base64Key = Convert.ToBase64String(aesEncryption.Key);

            //Per document generated key
            var rendom = GetUniqueKey(30);
            //1.	The Key is to contain at least 256 bits of cryptographically secure random data.
            var hiddenKey = CreateSalt(256);

            var hiddenKeyString = GetString(hiddenKey);

            var againConvertedKey = GetBytes(hiddenKeyString);

            //Created date time of file
            var dateTime = DateTime.Now;
            var dateTimeArray = new byte[8];
            var sourceBytes = BitConverter.GetBytes(dateTime.Ticks);
            Array.Copy(sourceBytes, 0, dateTimeArray, 0, 8);
            var newKey = hiddenKey.Concat(dateTimeArray).ToArray();
            var hmac512 = new HMACSHA512(newKey);
            var papper = hmac512.ComputeHash(hiddenKey, 0, 256);

            string encodedHmac = HmacBase64(rendom, papper);

            //Save in database with rendom key
            var salt = CreateSalt(128);
            var encryptionKey = CryptSharp.Utility.SCrypt.ComputeDerivedKey(Encoding.UTF8.GetBytes(encodedHmac), salt, 262144, 8, 1, null,32);
            var encodedKey1 = Convert.ToBase64String(encryptionKey);
            //Again Create encryptionKey to check for equality.
            var encryptionKey2 = CryptSharp.Utility.SCrypt.ComputeDerivedKey(Encoding.UTF8.GetBytes(encodedHmac), salt, 262144, 8, 1, 2,32);
            var encodedKey2 = Convert.ToBase64String(encryptionKey2);

            var isSame = String.Compare(encodedKey1, encodedKey2, StringComparison.Ordinal);
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private static string GetUniqueKey(int maxSize)
        {
            const string a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            var chars = a.ToCharArray();
            var data = new byte[1];
            var crypto = new RNGCryptoServiceProvider();
            crypto.GetNonZeroBytes(data);
            int size = maxSize;
            data = new byte[size];
            crypto.GetNonZeroBytes(data);
            var result = new StringBuilder(size);
            foreach (var b in data)
            {
                result.Append(chars[b % chars.Length]);
            }
            return result.ToString();
        }

        private static byte[] CreateSalt(int size)
        {
            //Generate a cryptographic random number.
            var rng = new RNGCryptoServiceProvider();
            var buff = new byte[size];
            rng.GetBytes(buff);
            // Return a Base64 string representation of the random number.
            //var str = ConvertBiteArrayToString(buff, 256);
            return buff;
        }

        private static string HmacBase64(string password, byte[] pepper)
        {
            if (pepper == null)
            {
                Console.WriteLine("Password hash not created - pepper is null.");
                return null;
            }
            var hmac = new HMACSHA256(pepper);
            hmac.Initialize();
            byte[] buffer = Encoding.UTF8.GetBytes(password);
            byte[] rawHmac = hmac.ComputeHash(buffer);
            return Convert.ToBase64String(rawHmac);
        }

        static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        static string GetString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
    }

}
