internal class 亼
{
    internal delegate ulong 个(byte[] 丨, uint 丩);

    internal delegate ulong 土(byte[] 丨, byte[] 丨2, uint 丩);

    internal static readonly nuint 兆 = 2000u;

    internal const uint 八 = 12288u;

    internal const int 刾 = 12;

    internal const int 匜 = 16;

    internal const string 刎 = "kernel32.dll";
}

using System.Runtime.InteropServices;

internal class 乡
{
    [DllImport("kernel32.dll")]
    public static extern nint VirtualAlloc(nint 冖, nuint 凸, uint 凵, uint 匚);
}


public class Assembly
{
    public static readonly byte[] 亞;

    public static readonly byte[] 冫;

    public static readonly byte[] 亏;

    public static readonly byte[] 不;

    public static readonly byte[] 垯;

    public static readonly byte[] 仌;

    public static readonly byte[] 亘;

    public static readonly byte[] 埜;

    public static readonly byte[] 坙;

    public static readonly byte[] 夼;

    static Assembly()
    {
        亞 = new byte[24]
        {
            138, 68, 17, 255, 52, 42, 136, 68, 17, 255,
            72, 255, 202, 117, 241, 72, 137, 200, 195, 0,
            0, 0, 0, 0
        };
        冫 = new byte[26]
        {
            122, 70, 79, 75, 89, 79, 10, 79, 68, 94,
            79, 88, 10, 94, 66, 79, 10, 90, 75, 89,
            89, 93, 69, 88, 78, 16
        };
        亏 = new byte[32]
        {
            157, 171, 108, 129, 114, 34, 142, 39, 166, 52,
            210, 81, 101, 200, 204, 65, 138, 15, 194, 25,
            189, 105, 24, 64, 193, 185, 114, 78, 81, 200,
            98, 108
        };
        不 = new byte[143]
        {
            110, 68, 78, 73, 88, 80, 19, 110, 88, 94,
            72, 79, 84, 73, 68, 19, 126, 79, 68, 77,
            73, 82, 90, 79, 92, 77, 85, 68, 19, 124,
            88, 78, 122, 94, 80, 17, 29, 110, 68, 78,
            73, 88, 80, 19, 110, 88, 94, 72, 79, 84,
            73, 68, 19, 126, 79, 68, 77, 73, 82, 90,
            79, 92, 77, 85, 68, 19, 124, 81, 90, 82,
            79, 84, 73, 85, 80, 78, 17, 29, 107, 88,
            79, 78, 84, 82, 83, 0, 11, 19, 13, 19,
            13, 19, 13, 17, 29, 126, 72, 81, 73, 72,
            79, 88, 0, 83, 88, 72, 73, 79, 92, 81,
            17, 29, 109, 72, 95, 81, 84, 94, 118, 88,
            68, 105, 82, 86, 88, 83, 0, 95, 13, 14,
            91, 8, 91, 10, 91, 12, 12, 89, 8, 13,
            92, 14, 92
        };
        垯 = new byte[40]
        {
            99, 169, 210, 52, 95, 51, 104, 160, 110, 43,
            213, 30, 86, 104, 18, 110, 40, 213, 95, 33,
            99, 213, 226, 95, 199, 146, 43, 42, 42, 42,
            233, 146, 42, 42, 42, 42, 233, 42, 42, 42
        };
        仌 = new byte[7] { 120, 83, 94, 79, 68, 77, 73 };
        亘 = new byte[7] { 121, 88, 94, 79, 68, 77, 73 };
        埜 = new byte[30]
        {
            24, 76, 8, 18, 79, 8, 35, 18, 72, 8,
            77, 10, 79, 35, 12, 77, 18, 10, 76, 23,
            79, 35, 25, 78, 79, 69, 69, 30, 78, 72
        };
        坙 = new byte[46]
        {
            239, 37, 95, 53, 9, 193, 151, 245, 255, 217,
            92, 200, 15, 202, 72, 226, 242, 133, 41, 10,
            133, 184, 138, 26, 152, 247, 161, 90, 147, 198,
            137, 171, 164, 145, 226, 182, 80, 82, 253, 238,
            35, 199, 70, 23, 206, 8
        };
        夼 = new byte[46]
        {
            196, 223, 136, 93, 185, 71, 183, 100, 77, 238,
            209, 141, 11, 226, 172, 184, 113, 235, 47, 229,
            191, 255, 120, 221, 242, 16, 75, 64, 90, 176,
            176, 12, 7, 120, 164, 133, 60, 58, 124, 107,
            190, 43, 85, 177, 122, 9
        };
        乙(不);
        乙(仌);
        乙(亘);
    }

    private static 亾 仟<亾>(byte[] 伿)
    {
        nint num = 乡.VirtualAlloc(IntPtr.Zero, 亼.兆, 12288u, 64u);
        Marshal.Copy(伿, 0, num, 伿.Length);
        return Marshal.GetDelegateForFunctionPointer<亾>(num);
    }

    private static byte[] 又()
    {
        byte[] array = new byte[32];
        for (int i = 0; i < array.Length; i++)
        {
            array[i] = (byte)((uint)i ^ 0xBEu);
        }
        return array;
    }

    private static byte[] 儻(int l)
    {
        return RandomNumberGenerator.GetBytes(l);
    }

    private static byte[] 尸(byte[] 么, byte[] 了)
    {
        Type typeFromHandle = typeof(byte[]);
        Type type = Type.GetType(Encoding.ASCII.GetString(不));
        object obj = (type?.GetConstructor(new Type[1] { typeFromHandle }))?.Invoke(new object[1] { 么 });
        byte[] array = 儻(12);
        byte[] array2 = new byte[16];
        byte[] array3 = new byte[了.Length];
        (type?.GetMethod(Encoding.ASCII.GetString(仌), new Type[5] { typeFromHandle, typeFromHandle, typeFromHandle, typeFromHandle, typeFromHandle }))?.Invoke(obj, new object[5]
        {
            array,
            了,
            array3,
            array2,
            Array.Empty<byte>()
        });
        byte[] array4 = new byte[array.Length + array2.Length + array3.Length];
        array.CopyTo(array4, 0);
        array2.CopyTo(array4, array.Length);
        array3.CopyTo(array4, array.Length + array2.Length);
        return array4;
    }

    public static void Main()
    {
        仟<亼.个>(亞)(冫, (uint)冫.Length);
        Console.WriteLine(Encoding.ASCII.GetString(冫));
        仟<亼.个>(亞)(垯, (uint)垯.Length);
        byte[] bytes = Encoding.ASCII.GetBytes(Console.ReadLine().Trim());
        byte[] 么 = 又();
        byte[] 么2 = 儻(32);
        if (仟<亼.土>(垯)(bytes, 埜, (uint)bytes.Length) == 0L)
        {
            Console.WriteLine(Encoding.ASCII.GetString(屮(么2, 尸(么2, 屮(么, 夼)))));
        }
        else
        {
            Console.WriteLine(Encoding.ASCII.GetString(屮(么2, 尸(么2, 屮(么, 坙)))));
        }
        byte[] array = new byte[32];
        bytes.CopyTo(array, 0);
        try
        {
            byte[] 了 = Convert.FromHexString("30FB0E8EFFB608050C6AC1A319817BDBEC58C5E2D6C868D5FC04E37B476981456C14CCF797BE9B83DD587346DE3E0822EE020A0A4DAEB088F4C6393278CF9C6401534B789FE590A61B416A6A2B705DE1F8E10AF9597333E9E67CA22015EE8F98E7C5B189A552");
            byte[] bytes2 = 屮(array, 了);
            Console.WriteLine("--------------------------");
            Console.WriteLine(Encoding.ASCII.GetString(bytes2));
        }
        catch
        {
        }
    }

    private static byte[] 屮(byte[] 么, byte[] 了)
    {
        Type typeFromHandle = typeof(byte[]);
        Type type = Type.GetType(Encoding.ASCII.GetString(不));
        object obj = (type?.GetConstructor(new Type[1] { typeFromHandle }))?.Invoke(new object[1] { 么 });
        byte[] array = new byte[12];
        byte[] array2 = new byte[16];
        byte[] array3 = new byte[了.Length - array.Length - array2.Length];
        byte[] array4 = new byte[array3.Length];
        Array.Copy(了, 0, array, 0, array.Length);
        Array.Copy(了, array.Length, array2, 0, array2.Length);
        Array.Copy(了, array.Length + array2.Length, array3, 0, array3.Length);
        (type?.GetMethod(Encoding.ASCII.GetString(亘), new Type[5] { typeFromHandle, typeFromHandle, typeFromHandle, typeFromHandle, typeFromHandle }))?.Invoke(obj, new object[5]
        {
            array,
            array3,
            array2,
            array4,
            Array.Empty<byte>()
        });
        return array4;
    }

    private static void 乙(byte[] 不)
    {
        for (int i = 0; i < 不.Length; i++)
        {
            不[i] = (byte)(不[i] ^ 0x3Du);
        }
    }
}








