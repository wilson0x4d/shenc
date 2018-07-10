using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace shenc
{
    /// <summary>
    /// A quick and dirty tool for encrypting/decrypting text from a shell prompt.
    /// <para>Generates a one-time keypair, used for encryption/decryption.</para>
    /// <para>PUBLIC  key stored to `.pubkey` file.</para>
    /// <para>PRIVATE key stored to `.prikey` file.</para>
    /// <para></para>
    /// </summary>
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                if (args == null || args.Length == 0)
                {
                    PrintHelp();
                    return;
                }
                var opcode = args[0].ToUpperInvariant();
                var keyfile = args.Length > 1
                    ? args[1].ToUpperInvariant()
                    : default(string);
                var input = args.Length > 2
                    ? string.Join(" ", args.Skip(2))
                    : default(string);

                switch (opcode)
                {
                    case "G":
                        GenerateKeypair(keyfile);
                        return;

                    case "E":
                        Encrypt(keyfile, input);
                        break;

                    case "D":
                        Decrypt(keyfile, input);
                        break;

                    default:
                        PrintHelp();
                        return;
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
        }

        private static void Log(Exception ex)
        {
            try
            {
                while (ex != null)
                {
                    Console.Error.WriteLine($"Exception: {ex.Message}");
                    Console.Error.WriteLine($"StackTrace: {ex.StackTrace}");
                    ex = ex.InnerException;
                }
            }
            catch (Exception L_ex)
            {
                Trace.TraceError($"{L_ex.Message}=>{L_ex.StackTrace}");
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("shenc g //generates a new keypair");
            Console.WriteLine("shenc e [keyfile] [input] // encrypts a string or file using specified keypair");
            Console.WriteLine("shenc d [keyfile] [input] // decrypts a string or file using specified keypair");
        }

        private static void GenerateKeypair(string keyid = null)
        {
            keyid = keyid ?? $"{Guid.NewGuid()}";
            var cspParameters = new CspParameters
            {
                ProviderType = 1,
                Flags = CspProviderFlags.UseArchivableKey,
                KeyNumber = (int)KeyNumber.Exchange
            };
            var rsaProvider = new RSACryptoServiceProvider(cspParameters);
            var prikey = rsaProvider.ToXmlString(true);
            var pubkey = rsaProvider.ToXmlString(false);
            using (var prikeyFile = File.CreateText($"{keyid}.prikey"))
            {
                prikeyFile.Write(prikey);
                prikeyFile.Flush();
                prikeyFile.Close();
            }
            Console.WriteLine($"Generated PRIKEY file: {keyid}.prikey");
            using (var pubkeyFile = File.CreateText($"{keyid}.pubkey"))
            {
                pubkeyFile.Write(pubkey);
                pubkeyFile.Flush();
                pubkeyFile.Close();
            }
            Console.WriteLine($"Generated PUBKEY file: {keyid}.pubkey");
        }

        private static RSA LoadKeyfile(string keyfile)
        {
            if (!File.Exists(keyfile))
            {
                if (File.Exists($"{keyfile}.prikey"))
                {
                    keyfile = $"{keyfile}.prikey";
                }
                else if (File.Exists($"{keyfile}.pubkey"))
                {
                    keyfile = $"{keyfile}.pubkey";
                }
                else
                {
                    throw new FileNotFoundException(keyfile);
                }
            }
            var csp = new RSACryptoServiceProvider(new CspParameters
            {
                ProviderType = 1
            });
            using (var file = File.OpenText(keyfile))
            {
                var xml = file.ReadToEnd();
                csp.FromXmlString(xml);
                file.Close();
            }
            return csp;
        }

        private static void EncryptText(string keyfile, string input)
        {
            var csp = LoadKeyfile(keyfile);
            var data = Encoding.UTF8.GetBytes(input);
            var edata = csp.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            var output = Convert.ToBase64String(edata, Base64FormattingOptions.None);
            Console.WriteLine(output);
        }

        private static void EncryptFile(string keyfile, string input)
        {
            var csp = LoadKeyfile(keyfile);
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
            {
                var data = new byte[infile.Length];
                infile.Read(data, 0, data.Length);
                var edata = csp.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                using (var outfile = File.Open($"{input}.out", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
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
            var csp = LoadKeyfile(keyfile);
            var edata = Convert.FromBase64String(input);
            var data = csp.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
            var output = Encoding.UTF8.GetString(data);
            Console.WriteLine(output);
        }

        private static void DecryptFile(string keyfile, string input)
        {
            var csp = LoadKeyfile(keyfile);
            using (var infile = File.Open($"{input}", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
            {
                if (input.EndsWith(".out"))
                {
                    input = input.Substring(0, input.Length - 4);
                }
                var edata = new byte[infile.Length];
                infile.Read(edata, 0, edata.Length);
                var data = csp.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                using (var outfile = File.Open($"{input}", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
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
