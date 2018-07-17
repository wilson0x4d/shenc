using CQ;
using CQ.Crypto;
using CQ.Network;
using CQ.Settings;
using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using X4D.Diagnostics.Configuration;
using X4D.Diagnostics.Logging;

namespace shenc
{
    /// <summary>
    /// <para>adapted from https://gist.github.com/wilson0x4d/a659723373ab2dd5ac845ba8a92ebb84</para>
    /// </summary>
    partial class Program
    {
        private static Whitelist _whitelist;

        private static Crypt _crypt;

        private static Netwk _netwk;

        private static int _processId;

        static Program()
        {
            //var section = SystemDiagnosticsBootstrapper.Configure()
            //    as ConfigurationSection;

            _crypt = new Crypt();
        }

        private static void SwitchToInteractiveMode(
            RSA rsa,
            CancellationTokenSource cancellationTokenSource)
        {
            _whitelist = new Whitelist();
            _whitelist.LoadWhitelist();

            _crypt = new Crypt();

            _netwk = new Netwk(_crypt, _whitelist, rsa);
            _netwk.MessageReceived += (s, e) =>
            {
                Console.WriteLine($"({DateTime.UtcNow.ToString("HH:mm:ss")}) {e.Client}> {e.Message}");
            };
            _netwk.UpdateDynamicDns()
                .ContinueWith(t =>
                {
                    Console.WriteLine(t.Result);
                });

            PrintInteractiveHelp("HELP");

            Console.WriteLine("Welcome to Interactive Mode, enter one of the commands above to get started.");

            while (!cancellationTokenSource.IsCancellationRequested)
            {
                var command = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(command))
                {
                    continue;
                }
                var commandParts = command.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (commandParts.Length > 0)
                {
                    commandParts[0] = commandParts[0].ToUpperInvariant();
                    switch (commandParts[0])
                    {
                        case "/HELP":
                        case "/?":
                            PrintInteractiveHelp(commandParts.Length > 1 ? commandParts[1] : commandParts[0]);
                            break;

                        case "/QUIT":
                            try
                            {
                                Console.WriteLine("Disconnecting..".Log());
                                _netwk.ShutdownAllClientWorkers();
                            }
                            finally
                            {
                                Console.WriteLine("Shutting down..".Log());
                                cancellationTokenSource.Cancel(false);
                            }
                            break;

                        case "/LISTEN":
                            {
                                // TODO: control accept queue length
                                var portNumber = commandParts.Length > 1 ? int.Parse(commandParts[1]) : 18593;
                                Console.WriteLine($"Listening for connections on port '{portNumber}'..");
                                _netwk
                                    .StartListening(
                                        cancellationTokenSource,
                                        portNumber)
                                    .ContinueWith(t =>
                                    {
                                        Console.WriteLine($"LISTEN: Stopped listening on {portNumber}.");
                                    });

                            }
                            break;

                        case "/DISCONNECT":
                            {
                                _netwk.DisconnectAllClients(commandParts);
                            }
                            break;

                        case "/CONNECT":
                            // TODO: similar to whitelist need a "last seen" list so we can attempt a connect by thumbnail/alias (last seen shoudl index by thumbnail)
                            // treat each command input as a 'hostport'
                            commandParts.Skip(1).Select(async hostport =>
                            {
                                try
                                {
                                    Console.WriteLine($"Establishing connection to [{hostport}]");
                                    var client = await _netwk.ConnectTo(hostport, rsa);
                                    await client.Worker;
                                    Console.WriteLine($"Disconnected from [{hostport}]");
                                }
                                catch (Exception ex)
                                {
                                    // TODO: console?
                                    ex.Log();
                                }
                            })
                            .ToArray();
                            break;

                        case "/NOLISTEN":
                        case "/NOHOST":
                            _netwk.StopListening();
                            break;

                        case "/PING":
                            _netwk.PingAllClients();
                            break;

                        case "/ACCEPT":
                            Console.WriteLine(
                                _netwk.AcceptClient(commandParts));
                            break;

                        case "/BAN":
                            Console.WriteLine(
                                _netwk.Ban(commandParts));
                            break;

                        case "/WHITELIST":
                            {
                                lock (_whitelist)
                                {
                                    foreach (var thumbprint in _whitelist)
                                    {
                                        Console.WriteLine($"WHITELIST: {thumbprint}");
                                    }
                                }
                            }
                            break;

                        default:
                            _netwk.SendChatMessage(command);
                            break;
                    }
                }
            }
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

        #region Interactive Help

        private static void PrintInteractiveHelp(string command)
        {
            switch (command.Trim('/'))
            {
                case "LISTEN":
                    Console.WriteLine(@"

Summary:
    Listen for connections on the specified port number.

Usage:
    /LISTEN [port-number]

    port-number = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

 NOTE: Listening on more than one port is not supported.

 NOTE: The port may need to be added to your firewall.

See also: /ACCEPT, /NOLISTEN
");
                    break;

                case "NOLISTEN":
                    Console.WriteLine(@"

Summary:
    Stop listening for connections.

Usage:
    /NOLISTEN

See also: /BAN, /DISCONNECT, /LISTEN
");
                    break;

                case "CONNECT":
                    Console.WriteLine(@"

Summary:
    Connect a remote system.

Usage:
    /CONNECT <host[:port]>

    host = (required) a hostname or ip address of the
        remote system to connect to.

    port = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

See also: /DISCONNECT
");
                    break;

                case "DISCONNECT":
                    Console.WriteLine(@"

Summary:
    Disconnect a remote system.

Usage:
    /DISCONNECT <alias|thumbprint|<host[:port]>|*]>

    Only 1 the 3 parameters shown are required:

    alias = (required) an alias previously assigned
        to a thumbrint associated with the remote
        system.

    -or-

    thumbprint = (required) a thumbrint associated
        with the remote system.

    -or-

    host = (required) a hostname or ip address of the
        remote system to connect to.

    port = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

    -or-

    * = a special-case literal character '*' (asterisk)
        which will disconnect all remote systems.

See also: /BAN, /CONNECT
");
                    break;

                case "ACCEPT":
                    Console.WriteLine(@"

Summary:
    Accept a thumbprint/remote/client, and optionally
    assign it an alias, by adding it to the WHITELIST.

Usage:
    /ACCEPT <thumbprint> [alias]

    thumbprint = (required) a thumbrint associated
        with the remote system.

    alias = (optional) an alias previously assigned
        to a thumbrint associated with the remote
        system.

See also: /BAN
");
                    break;

                case "BAN":
                    Console.WriteLine(@"

Summary:
    Ban a thumbprint/remote/client by removing it from
    the WHITELIST.

Usage:
    /BAN <alias|thumbprint|<host[:port]>>

    alias = (required) an alias previously assigned
        to a thumbrint associated with the remote
        system.

    -or-

    thumbprint = (required) a thumbrint associated
        with the remote system.

    -or-

    host = (required) a hostname or ip address of the
        remote system to connect to.

    port = (optional) The Port Number to listen for
        connections on, defaults to port 18593.

See also: /BAN
");
                    break;

                case "WHITELIST":
                    Console.WriteLine(@"

Summary:
    Displays the current WHITELIST entries.

Usage:
    /WHITELIST

See also: /ACCEPT, /BAN
");
                    break;

                case "QUIT":
                    Console.WriteLine(@"

Summary:
    Quit, gracefully disconnecting all remotes.

Usage:
    /QUIT
");
                    break;

                case "HELP":
                default:
                    Console.WriteLine(@"

/HELP [command]

/LISTEN [port-number]
/NOLISTEN

/CONNECT <host>:<port>
/DISCONNECT <alias|<host>:<port>>

/ACCEPT <thumbprint> [alias]
/BAN <thumbprint|alias|<host>:<port>>
/WHITELIST

/QUIT
");
                    break;
            }
        }

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

        #endregion Interactive Help
    }
}
