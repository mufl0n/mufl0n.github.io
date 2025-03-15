// ILSpy

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using nucleus;

internal class Program {
	private static int Main(string[] args) {
		return RealProgram.realMain(args);
	}
}

internal class RealProgram {
	public static int realMain(string[] args) {
		if (args.Length != 3) {
			return PrintUsage();
		}
		string[] commandNames = new string[2] { "encrypt", "decrypt" };
		if (!commandNames.Contains(args[0])) {
			Console.WriteLine("Supported operations: " + string.Join(", ", commandNames));
			return PrintUsage();
		}
		bool isEncrypt = args[0] == commandNames[0];
		if (!File.Exists(args[1])) {
			Console.WriteLine("Please make sure that the source file exists.");
			return 1;
		}
		if (File.Exists(args[2])) {
			Console.WriteLine("Are you sure that you want to overwrite '" + args[2] + "'? [y/N]");
			if (Console.ReadLine().ToLowerInvariant().Trim() != "y") {
				return 1;
			}
			File.Delete(args[2]);
		}
		if (Debugger.IsAttached) {
			// "I like the bugs for myself.""
			Console.WriteLine(nucleus.Decoder.decodeToString(58, 80, 88, 10, 14, 8, 19, 25, 91, 31, 83, 18, 65, 4, 22, 77, 85, 2, 65, 90, 30, 9, 71, 6, 9, 11, 29));
			return 2;
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

	private static int PrintUsage() {
		Console.WriteLine("Usage: ./" + AppDomain.CurrentDomain.FriendlyName + " encrypt <src_plain_file> <dst_enc_file>");
		Console.WriteLine("       ./" + AppDomain.CurrentDomain.FriendlyName + " decrypt <src_enc_file> <dst_plain_file>");
		return 1;
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

