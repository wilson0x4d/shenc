using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using X4D.Diagnostics.Logging;

namespace CQ.Crypto
{
    public sealed class Crypt
    {
        public string GetThumbprint(RSA rsa)
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

        public string Hash(string keyid)
        {
            using (var rsa = LoadKeypair(keyid, false))
            {
                var thumbprint = GetThumbprint(rsa);
                return thumbprint;
            }
        }

        public RSA GenerateKeypair(string keyid = null, int keyLength = 8192)
        {
            keyid = keyid ?? $"{Guid.NewGuid()}";
            if (keyid.EndsWith(".prikey", StringComparison.OrdinalIgnoreCase) || keyid.EndsWith(".pubkey", StringComparison.OrdinalIgnoreCase))
            {
                keyid = keyid.Remove(keyid.Length - 7);
            }
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
                $"Generated PRIKEY file: {keyid}.prikey".Log();
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
                $"Generated PUBKEY file: {keyid}.pubkey".Log();
            }
            return rsa;
        }

        public RSA LoadKeypair(string keyid, bool generateIfMissing = false, int keyLength = 8192)
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
                $"Loaded Key '{keyid}'".Log();
                return rsa;
            }
        }

        public string EncryptText(string keyid, string input)
        {
            var rsa = LoadKeypair(keyid);
            var data = Encoding.UTF8.GetBytes(input);
            var edata = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            var output = Convert.ToBase64String(edata, Base64FormattingOptions.None);
            return output;
        }

        public string EncryptFile(string keyid, string input)
        {
            var rsa = LoadKeypair(keyid);
            var rng = new RNGCryptoServiceProvider();
            var blockSize = (rsa.KeySize / 8) - 17;
            var pdata = new byte[blockSize];
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var dataLength = infile.Length;
                using (var outfile = File.Open($"{input}.out", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    outfile.Write(BitConverter.GetBytes(infile.Length), 0, 8);
                    for (int i = 0; i < dataLength; i += blockSize)
                    {
                        rng.GetNonZeroBytes(pdata);
                        infile.Read(pdata, 0, blockSize);
                        var edata = rsa.Encrypt(pdata, RSAEncryptionPadding.Pkcs1);
                        outfile.Write(edata, 0, edata.Length);
                    }
                    outfile.Flush();
                    outfile.Close();
                }
                infile.Close();
            }
            return $"Created: {input}.out";
        }

        public string DecryptText(string keyid, string input)
        {
            var rsa = LoadKeypair(keyid);
            var edata = Convert.FromBase64String(input);
            var data = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
            var output = Encoding.UTF8.GetString(data);
            return output;
        }

        public string DecryptFile(string keyid, string input)
        {
            var rsa = LoadKeypair(keyid);
            var blockSize = (rsa.KeySize / 8) - 17;
            var edata = new byte[blockSize + 17];
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var lenbuf = new byte[8];
                infile.Read(lenbuf, 0, 8);
                var pdataLength = BitConverter.ToInt64(lenbuf, 0);
                if (input.EndsWith(".out"))
                {
                    input = input.Substring(0, input.Length - 4);
                }
                using (var outfile = File.Open($"{input}", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    for (int i = 0; i < pdataLength; i += blockSize)
                    {
                        infile.Read(edata, 0, edata.Length);
                        var pdata = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                        outfile.Write(pdata, 0, blockSize);
                    }
                    outfile.Flush();
                    outfile.Close();
                }
                infile.Close();
            }
            return $"Created: {input}";
        }

        public string Encrypt(string keyid, string input)
        {
            if (File.Exists(input))
            {
                return EncryptFile(keyid, input).Log();
            }
            else
            {
                return EncryptText(keyid, input).Log();
            }
        }

        public string Decrypt(string keyid, string input)
        {
            if (File.Exists(input))
            {
                return DecryptFile(keyid, input).Log();
            }
            else
            {
                return DecryptText(keyid, input).Log();
            }
        }
    }
}
