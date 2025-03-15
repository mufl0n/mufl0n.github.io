// ILSpy again

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using quark;

[AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
internal sealed class MemeAttribute : Attribute {
	public readonly int Pointzzzz;
	public readonly string Lit;
	public MemeAttribute(int pointzzzz, string lit) {
		Pointzzzz = pointzzzz;
		Lit = lit;
	}
}

[Meme(2, "ac")]
[Meme(10, "c0")]

public class MoreSpace {
	[Meme(4, "em")]
	[Meme(3, "em")]
	public static int L(bool encrypt, FileStream src, FileStream dest) {
		Console.Write("Starting..."); Thread.Sleep(2000);
		Console.Write(".");           Thread.Sleep(2000);
		Console.WriteLine();
		return 1337;
	}
	[Meme(6, "{d")]
	[Meme(5, "es")]
	public static int L([Meme(7, "0t")][Meme(8, "n3")] int doEncrypt, [Meme(14, "l1")] FileStream src, [Meme(9, "t_")] FileStream dest) {
		Console.Write("Starting..."); Thread.Sleep(2000);
		Console.Write(".");           Thread.Sleep(2000);
		Console.WriteLine();
		return 1337;
	}
}

[Meme(-100, "sp")]
public class Space {
	[Meme(15, "nu")]
	[Meme(12, "_0")]
	public static int L([Meme(13, "n_")] bool isEncrypt, [Meme(16, "x}")] FileStream src, [Meme(11, "re")] FileStream dest) {
		Thread.Sleep(2000);
		if (Debugger.IsAttached) { return 1; }
		Dictionary<int, string> dictionary = new Dictionary<int, string>();
		Type[] types = Assembly.GetAssembly(typeof(MoreSpace)).GetTypes();
		foreach (Type type in types) {
			foreach (MemeAttribute customAttribute in type.GetCustomAttributes<MemeAttribute>()) {
				dictionary.Add(customAttribute.Pointzzzz, customAttribute.Lit);
			}
			MethodInfo[] methods = type.GetMethods();
			foreach (MethodInfo methodInfo in methods) {
				foreach (MemeAttribute customAttribute2 in methodInfo.GetCustomAttributes<MemeAttribute>()) {
					dictionary.Add(customAttribute2.Pointzzzz, customAttribute2.Lit);
				}
				foreach (MemeAttribute item in methodInfo.GetParameters().SelectMany((ParameterInfo _) => _.GetCustomAttributes<MemeAttribute>())) {
					dictionary.Add(item.Pointzzzz, item.Lit);
				}
			}
		}
		byte[] realFlag = dictionary.OrderBy((KeyValuePair<int, string> _) => _.Key).SelectMany((KeyValuePair<int, string> _) => Encoding.UTF8.GetBytes(_.Value)).ToArray();
		byte[] fakeFlag = Encoding.UTF8.GetBytes("spacememes{not!A!valid!flag}");
		Rfc2898DeriveBytes randomBytes = new Rfc2898DeriveBytes(realFlag, fakeFlag, 100);
		byte[] key = randomBytes.GetBytes(32);
		Array.Fill(realFlag, (byte)0);
		randomBytes.Dispose();
		RijndaelManaged cipher = new RijndaelManaged();
		cipher.Mode = CipherMode.CBC;
		cipher.Padding = PaddingMode.PKCS7;
		cipher.KeySize = 128;
		cipher.Key = key;
		if (isEncrypt) {
			try	{
				ICryptoTransform transform = cipher.CreateEncryptor(cipher.Key, cipher.IV);
				dest.Write(BitConverter.GetBytes(cipher.IV.Length), 0, 4);
				dest.Write(cipher.IV, 0, cipher.IV.Length);
				dest.Flush();
				CryptoStream cryptoStream = new CryptoStream(dest, transform, CryptoStreamMode.Write);
				src.CopyTo(cryptoStream);
				cryptoStream.Close();
			} catch {
				Console.WriteLine("Error during encryption");
			}
		} else {
			try {
				cipher.IV = ReadIV(src);
				ICryptoTransform transform2 = cipher.CreateDecryptor(cipher.Key, cipher.IV);
				new CryptoStream(src, transform2, CryptoStreamMode.Read).CopyTo(dest);
				dest.Flush();
			} catch {
				Console.WriteLine("Error during decryption");
			}
		}
		Thread.Sleep(2000);
		return 0;
	}

	private static byte[] ReadIV(Stream s) {
		byte[] part1 = new byte[4];
		if (s.Read(part1, 0, part1.Length) != part1.Length) {
			throw new SystemException("Stream did not contain properly formatted byte array");
		}
		byte[] part2 = new byte[BitConverter.ToInt32(part1, 0)];
		if (s.Read(part2, 0, part2.Length) != part2.Length) {
			throw new SystemException("Did not read byte array properly");
		}
		return part2;
	}
}
