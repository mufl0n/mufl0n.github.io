# nucleus

[library.m0unt41n.ch/challenges/nucleus](https://library.m0unt41n.ch/challenges/nucleus) ![](../../resources/re.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a .NET binary, which dynamically loads an assembly from a resource (masked as "JPEG" internal resource).
That contains encryption / decryption routines and the whole program pretends to be an encryptor /
decryptor for files. The flag is hidden in one of the encryption keys - mingled as fields in multiple
instantiations of a static class.

# Analysis

## nucleus.cs

The original binary which we get in the challenge is a pretty big .NET executable. It does not easily work:

```bash
$ ./nucleus
No usable version of libssl was found
Aborted (core dumped)
```

... but it can be easily decompiled with [ILSpy](https://github.com/icsharpcode/ILSpy). With a bit
of annotating and trimming the boilerplate, the gist of [nucleus.cs](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/re/nucleus/nucleus.cs) is:

```csharp
internal class Program {
	private static int Main(string[] args) {
		return RealProgram.realMain(args);
	}
}

internal class RealProgram {
	public static int realMain(string[] args) {
		string[] commandNames = new string[2] { "encrypt", "decrypt" };
		bool isEncrypt = args[0] == commandNames[0];
		if (File.Exists(args[2])) {
			File.Delete(args[2]);
		}

		// Load "nucleus.res.quark.jpg" into a MemoryStream
		string name = nucleus.Decoder.decodeToString(29, 5, 87, 15, 0, 24, 64, 67, 65, 31, 0, 94, 69, 22, 4, 31, 88, 67, 89, 10, 20);
		using MemoryStream memoryStream = new MemoryStream();
		typeof(a).Assembly.GetManifestResourceStream(name).CopyTo(memoryStream);

		// Decode that stream into an assembly		
		Assembly assembly = Assembly.Load(nucleus.Decoder.decodeToBytes(memoryStream.Tokey()));

		// Get the "quark.Space" class from that assembly and "L" method from that class.
		string name2 = nucleus.Decoder.decodeToString(2, 5, 85, 17, 14, 67, 96, 29, 82, 25, 22);
		MethodInfo method = assembly.GetType(name2).GetMethod(nucleus.Decoder.decodetoString(63));

		// Call that method with args #2 / #3 as file descriptors (and isEncrypt as first arg)
		using FileStream arg2 = File.Open(args[1], FileMode.Open);
		using FileStream arg3 = File.OpenWrite(args[2]);
		return method.CreateDelegate<Func<bool, FileStream, FileStream, int>>()(isEncrypt, arg2, arg3);
	}
}

// Simple, fixed-key XOR decoder class:
internal class Decoder {
	public static string decodeToString(params int[] data) {
		byte[] key = new byte[10] { 115, 112, 52, 99, 101, 109, 51, 109, 51, 122 };
		StringBuilder stringBuilder = new StringBuilder();
		int pos = 0;
		foreach (int item in data) {
			stringBuilder.Append((char)(item ^ key[pos % key.Length]));
			pos++;
		}
		return stringBuilder.ToString();
	}

	public static byte[] decodeToBytes(byte[] data) {
		byte[] key = new byte[10] { 115, 112, 52, 99, 101, 109, 51, 109, 51, 122 };
		byte[] result = new byte[data.Length];
		for (int i = 0; i < data.Length; i++) {
			result[i] = (byte)(data[i] ^ key[i % key.Length]);
		}
		return result;
	}
}
```

## Decoding the strings

In order to decode above strings masked as byte arrays, we used a simple Python script:

```python
def decodeToString(data):
    key = [115, 112, 52, 99, 101, 109, 51, 109, 51, 122]
    res = ''
    for pos in range(len(data)):
        res+=chr(data[pos]^key[pos%len(key)])
    return res

def decodeToBytes(data):
    key = [115, 112, 52, 99, 101, 109, 51, 109, 51, 122]
    res = b''
    for pos in range(len(data)):
        res+=(data[pos]^key[pos%len(key)]).to_bytes(1)
    return res

print(decodeToString([58, 80, 88, 10, 14, 8, 19, 25, 91, 31, 83, 18, 65, 4, 22, 77, 85, 2, 65, 90, 30, 9, 71, 6, 9, 11, 29]))
print(decodeToString([29, 5, 87, 15, 0, 24, 64, 67, 65, 31, 0, 94, 69, 22, 4, 31, 88, 67, 89, 10, 20]))
print(decodeToString([2, 5, 85, 17, 14, 67, 96, 29, 82, 25, 22]))
print(decodeToString([63]))

assembly = decodeToBytes(open("nucleus.res.quark.jpg", "rb").read(65536))
open("quark", "wb").write(assembly)
```

## quark.cs

Now, decompiling the `quark` assembly we get [quark.cs](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/re/nucleus/quark.cs):

```csharp
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
```

I actually don't know C# *that* well, but what I see here is:

*   A program that encrypts / decrypts files: `progname (encrypt|decrypt) src dest`.
*   Encryption is reasonably standard AES, using random bytes derived from fixed strings (`realFlag` and `fakeFlag`) to generate PBKDF2.
    *   (OK, at this point, my variable names already reveal what's going on &#128578;)
*   Aborts when it sees `Debugger.IsAttached`
*   The program tries to not keep the `realFlag` in RAM (see `Array.Fill()`)
*   Most importantly a somewhat cryptic `Meme` class is instantiated few times, in seemingly random places across the code.

## Meme / MemeAttribute class

Again, I don't fully understand the intricacies here, but what I see about that class:

*   It is somewhat static, but, can be instantiated multiple times, with an `int` and two-character `String` every time
*   These instantiations don't change the program flow
*   As part of building the `realFlag`, all the instantiations are gathered into an `Array` and sorted by their first (`int`) field
*   These `Meme` instantiations, actually... hmm. When we manually sort them, we get:

```csharp
[Meme(-100, "sp")]
[Meme(   2, "ac")]
[Meme(   3, "em")]
[Meme(   4, "em")]
[Meme(   5, "es")]
[Meme(   6, "{d")]
[Meme(   7, "0t")]
[Meme(   8, "n3")]
[Meme(   9, "t_")]
[Meme(  10, "c0")]
[Meme(  11, "re")]
[Meme(  12, "_0")]
[Meme(  13, "n_")]
[Meme(  14, "l1")]
[Meme(  15, "nu")]
[Meme(  16, "x}")]
```

... and combining these character pairs looks like a flag. And it is a flag indeed &#128578;

---

## `spacememes{d0tn3t_c0re_0n_l1nux}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
