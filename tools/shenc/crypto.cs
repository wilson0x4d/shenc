﻿using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace shenc
{
    partial class Program
    {
        internal static string GetThumbprint(RSA rsa)
        {
            var result = default(string);
            using (var sha1 = SHA1.Create())
            {
                var rsaParameters = rsa.ExportParameters(false);
                var json = JsonConvert.SerializeObject(rsaParameters);
                var data = Encoding.UTF8.GetBytes(json);
                var hashed = sha1.ComputeHash(data);
                result = string.Join(":", hashed.Select(e => e.ToString("X2")).ToArray()).ToLower();
            }
            return result;
        }

        private static void Hash(string keyid)
        {
            using (var rsa = LoadKeypair(keyid, false))
            {
                var thumbprint = GetThumbprint(rsa);
                Log($"HASH: {keyid}=\"{thumbprint}\"");
            }
        }

        private static RSA GenerateKeypair(string keyid = null, int keyLength = 8192)
        {
            keyid = keyid ?? $"{Guid.NewGuid()}";
            if (keyid.EndsWith(".prikey", StringComparison.OrdinalIgnoreCase) || keyid.EndsWith(".pubkey", StringComparison.OrdinalIgnoreCase))
            {
                keyid = keyid.Remove(keyid.Length - 7);
            }
            Console.WriteLine("Generating a new key, this could take a while.. please be patient.");
            var rsa = RSA.Create();
            rsa.KeySize = keyLength;
            {
                var rsaParameters = rsa.ExportParameters(true);
                var json = JsonConvert.SerializeObject(new
                {
                    // dynamic type because `RSAParameters` does not serialize as expected
                    rsaParameters.D,
                    rsaParameters.DP,
                    rsaParameters.DQ,
                    rsaParameters.Exponent,
                    rsaParameters.InverseQ,
                    rsaParameters.Modulus,
                    rsaParameters.P,
                    rsaParameters.Q
                }, Formatting.Indented);
                var prikey = Encoding.UTF8.GetBytes(json);
                using (var file = File.Open($"{keyid}.prikey", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    file.Write(prikey, 0, prikey.Length);
                    file.Flush();
                    file.Close();
                }
                Console.WriteLine($"Generated PRIKEY file: {keyid}.prikey");
            }
            {
                var rsaParameters = rsa.ExportParameters(false);
                var json = JsonConvert.SerializeObject(new
                {
                    // dynamic type because `RSAParameters` does not serialize as expected
                    rsaParameters.D,
                    rsaParameters.DP,
                    rsaParameters.DQ,
                    rsaParameters.Exponent,
                    rsaParameters.InverseQ,
                    rsaParameters.Modulus,
                    rsaParameters.P,
                    rsaParameters.Q
                }, Formatting.Indented);
                var pubkey = Encoding.UTF8.GetBytes(json);
                using (var file = File.Open($"{keyid}.pubkey", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    file.Write(pubkey, 0, pubkey.Length);
                    file.Flush();
                    file.Close();
                }
                Console.WriteLine($"Generated PUBKEY file: {keyid}.pubkey");
            }
            return rsa;
        }

        private static RSA LoadKeypair(string keyid, bool generateIfMissing = false, int keyLength = 8192)
        {
            if (!File.Exists(keyid))
            {
                if (File.Exists($"{keyid}.prikey"))
                {
                    keyid = $"{keyid}.prikey";
                }
                else if (File.Exists($"{keyid}.pubkey"))
                {
                    keyid = $"{keyid}.pubkey";
                }
                else if (generateIfMissing)
                {
                    keyid = $"{keyid}.prikey";
                    return GenerateKeypair(keyid, keyLength);
                }
                else
                {
                    throw new FileNotFoundException(keyid);
                }
            }
            using (var file = File.Open(keyid, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var buf = new byte[file.Length];
                var offset = 0;
                while (offset < buf.Length)
                {
                    offset += file.Read(buf, offset, buf.Length);
                }
                var json = Encoding.UTF8.GetString(buf);
                var parameters = JsonConvert.DeserializeObject<dynamic>(json); // dynamic type because `RSAParameters` does not deserialize as expected
                var rsaParameters = new RSAParameters
                {
                    D = parameters.D,
                    DP = parameters.DP,
                    DQ = parameters.DQ,
                    Exponent = parameters.Exponent,
                    InverseQ = parameters.InverseQ,
                    Modulus = parameters.Modulus,
                    P = parameters.P,
                    Q = parameters.Q
                };
                var rsa = RSA.Create();
                rsa.ImportParameters(rsaParameters);
                file.Close();
                Console.WriteLine($"Loaded Key '{keyid}'");
                return rsa;
            }
        }

        private static void EncryptText(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            var data = Encoding.UTF8.GetBytes(input);
            var edata = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            var output = Convert.ToBase64String(edata, Base64FormattingOptions.None);
            Console.WriteLine(output);
        }

        private static void EncryptFile(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var data = new byte[infile.Length];
                infile.Read(data, 0, data.Length);
                var edata = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                using (var outfile = File.Open($"{input}.out", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    outfile.Write(edata, 0, edata.Length);
                    outfile.Flush();
                    outfile.Close();
                }
                infile.Close();
            }
            Console.WriteLine($"Created: {input}.out");
        }

        private static void DecryptText(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            var edata = Convert.FromBase64String(input);
            var data = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
            var output = Encoding.UTF8.GetString(data);
            Console.WriteLine(output);
        }

        private static void DecryptFile(string keyfile, string input)
        {
            var rsa = LoadKeypair(keyfile);
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (input.EndsWith(".out"))
                {
                    input = input.Substring(0, input.Length - 4);
                }
                var edata = new byte[infile.Length];
                infile.Read(edata, 0, edata.Length);
                var data = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                using (var outfile = File.Open($"{input}", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    outfile.Write(data, 0, data.Length);
                    outfile.Flush();
                    outfile.Close();
                }
                infile.Close();
            }
            Console.WriteLine($"Created: {input}");
        }

        private static void Encrypt(string keyfile, string input)
        {
            if (File.Exists(input))
            {
                EncryptFile(keyfile, input);
            }
            else
            {
                EncryptText(keyfile, input);
            }
        }

        private static void Decrypt(string keyfile, string input)
        {
            if (File.Exists(input))
            {
                DecryptFile(keyfile, input);
            }
            else
            {
                DecryptText(keyfile, input);
            }
        }

    }
}