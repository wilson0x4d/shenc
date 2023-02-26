using CQ.Crypto;
using CQ.Network;
using CQ.Settings;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using X4D.Diagnostics.Logging;

namespace shenc
{
    /// <summary>
    /// <para>adapted from https://gist.github.com/wilson0x4d/a659723373ab2dd5ac845ba8a92ebb84</para>
    /// </summary>
    partial class Program
    {
        private static Crypt _crypt;

        private static int _processId;

        static Program()
        {
            X4D.Diagnostics.Logging.LoggingExtensions.Settings.ShouldNormalizeMessages = false;
            _crypt = new Crypt();
        }

        private static void SwitchToInteractiveMode(
            RSA rsa,
            CancellationTokenSource cancellationTokenSource)
        {
            var whitelist = new Whitelist();
            whitelist.ReloadWhitelist();

            var cqHub = new CQHub(
                _crypt,
                whitelist,
                rsa,
                OnStatusChanged);

#pragma warning disable 4014
            var ddnsUpdater = new DynamicDnsUpdater(_crypt, OnStatusChanged);
            ddnsUpdater.UpdateDynamicDnsAsync();
#pragma warning restore 4014

            var interactiveShell = new InteractiveShell(
                whitelist,
                cqHub,
                _crypt,
                _processId,
                rsa,
                OnStatusChanged,
                cancellationTokenSource);

            interactiveShell.ProcessCommand("/THUMBPRINT").Wait();

            InteractiveShell.PrintInteractiveHelp("HELP");


            while (!cancellationTokenSource.IsCancellationRequested)
            {
                var command = Console.ReadLine();
                if (!string.IsNullOrWhiteSpace(command))
                {
                    try
                    {
                        var task = interactiveShell.ProcessCommand(command);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        ex.Log();
                    }
                }
            }
        }

        private static void OnStatusChanged(string statusText)
        {
            Console.WriteLine(statusText);
        }

        private static void Main(string[] args)
        {
            Console.WriteLine($"Shell Encryption Tool ({typeof(Program).Assembly.GetName().Version})");
            _processId = Process.GetCurrentProcess().Id;
            try
            {
                if (args == null || args.Length == 0)
                {
                    PrintHelp();
                    return;
                }

                var opcode = args[0].ToUpperInvariant();

                // take specified keyid, removing any pubkey/prikey file extension
                var keyid = args.Length > 1
                    ? (args[1].EndsWith(".prikey", StringComparison.OrdinalIgnoreCase) != args[1].EndsWith(".pubkey", StringComparison.OrdinalIgnoreCase))
                        ? args[1].Remove(args[1].Length - 7)
                        : args[1]
                    : default(string);

                var input = args.Length > 2
                    ? string.Join(" ", args.Skip(2))
                    : default(string);

                switch (opcode)
                {
                    case "CHAT":
                        {
                            if (string.IsNullOrWhiteSpace(keyid))
                            {
                                keyid = "chat";
                            }
                            var rsa = _crypt.LoadKeypair(keyid, true); // ie. "My" key, the key used to decrypt incoming data
                            var cancellationTokenSource = new CancellationTokenSource();
                            Console.CancelKeyPress += (s, e) =>
                            {
                                if (!cancellationTokenSource.IsCancellationRequested)
                                {
                                    cancellationTokenSource.Cancel();
                                }
                            };
                            SwitchToInteractiveMode(rsa, cancellationTokenSource);
                        }
                        return;

                    case "GENKEYS":
                    case "G":
                        _crypt.GenerateKeypair(keyid, int.Parse(input ?? "8192"));
                        if (File.Exists($"{keyid}.prikey"))
                        {
                            Console.WriteLine($"PRIKEY file: {keyid}.prikey");
                        }
                        if (File.Exists($"{keyid}.pubkey"))
                        {
                            Console.WriteLine($"PUBKEY file: {keyid}.pubkey");
                        }
                        return;

                    case "ENCRYPT":
                    case "E":
                        _crypt.Encrypt(keyid, input);
                        break;

                    case "DECRYPT":
                    case "D":
                        _crypt.Decrypt(keyid, input);
                        break;

                    case "HASH":
                    case "H":
                        {
                            var thumbprint = _crypt.Hash(keyid);
                            $"HASH: {keyid}=\"{thumbprint}\"".Log();
                        }
                        break;

                    default:
                        PrintHelp();
                        return;
                }
            }
            catch (Exception ex)
            {
                ex.Log();
            }
        }

        #region Help

        private static void PrintHelp() =>
            Console.WriteLine(@"
shenc genkeys
    generates a new keypair

shenc hash <keyfile>
    gets a hash of the specified keypair

shenc encrypt <keyfile> <input>
    encrypts a string or file using specified keypair

shenc decrypt <keyfile> <input>
    decrypts a string or file using specified keypair

shenc chat [keyfile]
    enter `shenc` into 'chat mode', a chat-specific keypair
    is auto-generated if one is not specified (ideal.)

===
=== NO-IP Support:
===
=== In your app config, add two <appSettings/> keys:
===
<appSettings>
    <add key=""no-ip:hostname"" value=""w00tcakes.ddns.net""/>
    <add key=""no-ip:auth"" value=""UgkUnzZvIbmSX9Fp5ejRBtgpwsTHV/g+QB0=""/>
    <!-- optional keys, and their defaults
    <add key=""no-ip:key"" value=""chat""/>
    <add key=""no-ip:address"" value=""127.0.0.1""/>
    -->
</appSettings>
=== You can create an encrypted `auth` value like so:
shenc e chat noip-username:noip-password
=== Then copy-paste the base64-encoded value into your config.
=== ");

        #endregion Help
    }
}
