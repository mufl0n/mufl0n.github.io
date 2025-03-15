internal class Constants {
    internal delegate ulong Xor2A(byte[] buf, uint len);
    internal delegate ulong CompareXor7C(byte[] buf1, byte[] buf2, uint len);
    internal static readonly nuint size = 2000;
    internal const uint allocationType = 0x3000;  // MEM_COMMIT|MEM_RESERVE
    internal const uint protect = 0x0040;         // PAGE_EXECUTE_READWRITE
    internal const int ivLen = 12;
    internal const int tagLen = 16;
    internal const string kernel32Str = "kernel32.dll";
}

internal class AllocHelper {
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    [DllImport(Constants.kernel32Str)]
    public static extern nint VirtualAlloc(
        nint pointer, nuint size, uint allocationType, uint protect);
}

public class Krabs2 {
    public static readonly byte[] _Xor2A;
    public static readonly byte[] PasswordPrompt;
    public static readonly byte[] Unused;
    public static readonly byte[] AesGcmClassName;
    public static readonly byte[] _CompareXor7C;
    public static readonly byte[] EncryptStr;
    public static readonly byte[] DecryptStr;
    public static readonly byte[] PasswordStr;
    public static readonly byte[] SuccessStr;
    public static readonly byte[] FailureStr;

    static Krabs2() {
        _Xor2A = new byte[24] {
            138, 68, 17, 255,        // 0x0000000000000000:  8A 44 11 FF    mov al, byte ptr [rcx + rdx - 1]
            52, 42,                  // 0x0000000000000004:  34 2A          xor al, 0x2a
            136, 68, 17, 255,        // 0x0000000000000006:  88 44 11 FF    mov byte ptr [rcx + rdx - 1], al
            72, 255, 202,            // 0x000000000000000a:  48 FF CA       dec rdx
            117, 241,                // 0x000000000000000d:  75 F1          jne 0
            72, 137, 200,            // 0x000000000000000f:  48 89 C8       mov rax, rcx
            195,                     // 0x0000000000000012:  C3             ret 
            0, 0, 0, 0, 0
        };
        _CompareXor7C = new byte[40] {
            99, 169, 210, 52,        // 0x0000000000000000:  49 83 F8 1E       cmp r8, 0x1e
            95, 51,                  // 0x0000000000000004:  75 19             jne 0x1f
            104, 160, 110, 43, 213,  // 0x0000000000000006:  42 8A 44 01 FF    mov al, byte ptr [rcx + r8 - 1]
            30, 86,                  // 0x000000000000000b:  34 7C             xor al, 0x7c
            104, 18, 110, 40, 213,   // 0x000000000000000d:  42 38 44 02 FF    cmp byte ptr [rdx + r8 - 1], al
            95, 33,                  // 0x0000000000000012:  75 0B             jne 0x1f
            99, 213, 226,            // 0x0000000000000014:  49 FF C8          dec r8
            95, 199,                 // 0x0000000000000017:  75 ED             jne 6
            146, 43, 42, 42, 42,     // 0x0000000000000019:  B8 01 00 00 00    mov eax, 1
            233,                     // 0x000000000000001e:  C3                ret
            146, 42, 42, 42, 42,     // 0x000000000000001f:  B8 00 00 00 00    mov eax, 0
            233,                     // 0x0000000000000024:  C3                ret 
            42, 42, 42               
        };
        PasswordPrompt = new byte[26] {
            // "Please enter the password:" XOR'd with 0x2A
            122, 70, 79, 75, 89, 79, 10, 79, 68, 94, 79, 88, 10, 94, 66, 79, 10, 90, 75, 89, 89, 93, 69, 88, 78, 16
        };
        PasswordStr = new byte[30] {
            // "d0tn3t_n4t1v3_p1nv0k3_e2399b24" XOR'd with 0x7C
            24, 76, 8, 18, 79, 8, 35, 18, 72, 8,
            77, 10, 79, 35, 12, 77, 18, 10, 76, 23,
            79, 35, 25, 78, 79, 69, 69, 30, 78, 72
        };
        AesGcmClassName = new byte[143] {
            // "System.Security.Cryptography.AesGcm, System.Security.Cryptography.Algorithms, Version=6.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
            // XOR'd with 0x3D
            110, 68, 78, 73, 88, 80, 19, 110, 88, 94, 72, 79, 84, 73, 68, 19, 126, 79, 68, 77,
            73, 82, 90, 79, 92, 77, 85, 68, 19, 124, 88, 78, 122, 94, 80, 17, 29, 110, 68, 78,
            73, 88, 80, 19, 110, 88, 94, 72, 79, 84, 73, 68, 19, 126, 79, 68, 77, 73, 82, 90,
            79, 92, 77, 85, 68, 19, 124, 81, 90, 82, 79, 84, 73, 85, 80, 78, 17, 29, 107, 88,
            79, 78, 84, 82, 83, 0, 11, 19, 13, 19, 13, 19, 13, 17, 29, 126, 72, 81, 73, 72, 79,
            88, 0, 83, 88, 72, 73, 79, 92, 81, 17, 29, 109, 72, 95, 81, 84, 94, 118, 88, 68,
            105, 82, 86, 88, 83, 0, 95, 13, 14, 91, 8, 91, 10, 91, 12, 12, 89, 8, 13, 92, 14, 92
        };
        EncryptStr = new byte[7] { 120, 83, 94, 79, 68, 77, 73 };  // "Encrypt" XOR'd with 0x3D
        DecryptStr = new byte[7] { 121, 88, 94, 79, 68, 77, 73 };  // "Decrypt" XOR'd with 0x3D
        SuccessStr = new byte[46] {
            // "Password correct!!" encrypted with FixedBytes() key and IV/tag below
            239, 37, 95, 53, 9, 193, 151, 245, 255, 217, 92, 200,                              // IV:EF255F3509C197F5FFD95CC8
            15, 202, 72, 226, 242, 133, 41, 10, 133, 184, 138, 26, 152, 247, 161, 90,          // tag:0FCA48E2F285290A85B88A1A98F7A15A
            147, 198, 137, 171, 164, 145, 226, 182, 80, 82, 253, 238, 35, 199, 70, 23, 206, 8  // ciphertext:93C689ABA491E2B65052FDEE23C74617CE08
        };
        FailureStr = new byte[46] {
            // "Password incorrect" encrypted with FixedBytes() key and IV/tag below
            196, 223, 136, 93, 185, 71, 183, 100, 77, 238, 209, 141,                           // IV:C4DF885DB947B7644DEED18D
            11, 226, 172, 184, 113, 235, 47, 229, 191, 255, 120, 221, 242, 16, 75, 64,         // tag:0BE2ACB871EB2FE5BFFF78DDF2104B40
            90, 176, 176, 12, 7, 120, 164, 133, 60, 58, 124, 107, 190, 43, 85, 177, 122, 9     // ciphertext:5AB0B00C0778A4853C3A7C6BBE2B55B17A09
        };
        Unused = new byte[32] {
            157, 171, 108, 129, 114, 34, 142, 39, 166, 52, 210, 81, 101, 200, 204, 65,
            138, 15, 194, 25, 189, 105, 24, 64, 193, 185, 114, 78, 81, 200, 98, 108
        };
        Xor3D(AesGcmClassName);
        Xor3D(EncryptStr);
        Xor3D(DecryptStr);
    }

    private static void Xor3D(byte[] data) {
        for (int i = 0; i < data.Length; i++) {
            data[i] = (byte)(data[i] ^ 0x3D);
        }
    }

    private static byte[] FixedBytes() {
        byte[] result = new byte[32];
        for (int i = 0; i < result.Length; i++) {
            result[i] = (byte)(i ^ 0xBE);
        }
        return result;  // BEBFBCBDBABBB8B9B6B7B4B5B2B3B0B1AEAFACADAAABA8A9A6A7A4A5A2A3A0A1
    }

    private static byte[] RandomBytes(int len) {
        return RandomNumberGenerator.GetBytes(len);
    }

    private static DelegateType LoadFunction<DelegateType>(byte[] code) {
        nint num = AllocHelper.VirtualAlloc(
            IntPtr.Zero, Constants.size, Constants.allocationType, Constants.protect);
        Marshal.Copy(code, 0, num, code.Length);
        return Marshal.GetDelegateForFunctionPointer<DelegateType>(num);
    }

    private static byte[] Encrypt(byte[] key, byte[] input) {
        Type bytesType = typeof(byte[]);

        // aes = new System.Security.Cryptography.AesGcm(key)
        Type aesType = Type.GetType(Encoding.ASCII.GetString(AesGcmClassName));
        object aes = (aesType?.GetConstructor(new Type[1] { bytesType }))?.Invoke(new object[1] { key });

        byte[] iv = RandomBytes(Constants.ivLen);
        byte[] tag = new byte[Constants.tagLen];
        byte[] ciphertext = new byte[input.Length];

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.decrypt
        // aes.Encrypt(iv, input, ciphertext, tag)        
        (aesType?.GetMethod(Encoding.ASCII.GetString(EncryptStr), new Type[5] { bytesType, bytesType, bytesType, bytesType, bytesType }))?.Invoke(aes, new object[5] {
            iv, input, ciphertext, tag, Array.Empty<byte>()
        });

        // Save IV, tag and ciphertext in the output
        byte[] result = new byte[iv.Length + tag.Length + ciphertext.Length];
        iv.CopyTo(result, 0);
        tag.CopyTo(result, iv.Length);
        ciphertext.CopyTo(result, iv.Length + tag.Length);
        return result;
    }

    private static byte[] Decrypt(byte[] key, byte[] input) {
        Type bytesType = typeof(byte[]);

        // aes = new System.Security.Cryptography.AesGcm(key)
        Type aesType = Type.GetType(Encoding.ASCII.GetString(AesGcmClassName));
        object aes = (aesType?.GetConstructor(new Type[1] { bytesType }))?.Invoke(new object[1] { key });

        byte[] iv = new byte[Constants.ivLen];
        byte[] tag = new byte[Constants.tagLen];
        byte[] ciphertext = new byte[input.Length - iv.Length - tag.Length];
        byte[] result = new byte[ciphertext.Length];

        // Extract IV, tag and ciphertext from the input
        Array.Copy(input, 0, iv, 0, iv.Length);
        Array.Copy(input, iv.Length, tag, 0, tag.Length);
        Array.Copy(input, iv.Length + tag.Length, ciphertext, 0, ciphertext.Length);

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.decrypt
        // aes.Decrypt(iv, ciphertext, tag, result)        
        (aesType?.GetMethod(Encoding.ASCII.GetString(DecryptStr), new Type[5] { bytesType, bytesType, bytesType, bytesType, bytesType }))?.Invoke(aes, new object[5] {
            iv, ciphertext, tag, result, Array.Empty<byte>()
        });
        return result;
    }

    public static void Main() {
        LoadFunction<Constants.Xor2A>(_Xor2A)(PasswordPrompt, PasswordPrompt.Length);
        Console.WriteLine(Encoding.ASCII.GetString(PasswordPrompt));
        LoadFunction<Constants.Xor2A>(_Xor2A)(_CompareXor7C, _CompareXor7C.Length);

        byte[] input = Encoding.ASCII.GetBytes(Console.ReadLine().Trim());
        byte[] keyReal = FixedBytes();
        byte[] keyDummy = RandomBytes(32);
        if (LoadFunction<Constants.CompareXor7C>(_CompareXor7C)(input, PasswordStr, input.Length) == 0) {
            Console.WriteLine(Encoding.ASCII.GetString(Decrypt(keyDummy, Encrypt(keyDummy, Decrypt(keyReal, FailureStr)))));
        } else {
            Console.WriteLine(Encoding.ASCII.GetString(Decrypt(keyDummy, Encrypt(keyDummy, Decrypt(keyReal, SuccessStr)))));
        }

        byte[] inputBytes = new byte[32];
        input.CopyTo(inputBytes, 0);
        try {
            byte[] secretMessage = Convert.FromHexString("30FB0E8EFFB608050C6AC1A319817BDBEC58C5E2D6C868D5FC04E37B476981456C14CCF797BE9B83DD587346DE3E0822EE020A0A4DAEB088F4C6393278CF9C6401534B789FE590A61B416A6A2B705DE1F8E10AF9597333E9E67CA22015EE8F98E7C5B189A552");
            byte[] decryptedMessage = Decrypt(inputBytes, secretMessage);
            Console.WriteLine("--------------------------");
            Console.WriteLine(Encoding.ASCII.GetString(decryptedMessage));
        } catch {}
    }
}
