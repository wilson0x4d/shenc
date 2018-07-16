using Newtonsoft.Json;
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
        private static void SwitchToInteractiveMode(
    RSA rsa,
    CancellationTokenSource cancellationTokenSource)
        {
            _whitelist = LoadWhitelist()
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value);
            _clients = new Dictionary<string, ClientState>(StringComparer.OrdinalIgnoreCase);
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
                                // shutdown all client workers
                                lock (_clients)
                                {
                                    Task.WaitAll(_clients.Values.Select(StopClientWorker).ToArray());
                                }
                            }
                            finally
                            {
                                // shutdown self
                                cancellationTokenSource.Cancel(false);
                            }
                            break;

                        case "/LISTEN":
                            // TODO: control accept queue length
#pragma warning disable 4014
                            StartListening(
                                cancellationTokenSource,
                                commandParts.Length > 1 ? int.Parse(commandParts[1]) : 18593,
                                (client) => OnClientAcceptCallback(client, rsa));
#pragma warning restore 4014
                            break;

                        case "/DISCONNECT":
                            {
                                lock (_clients)
                                {
                                    var clients = _clients.Values
                                        .Where(client => commandParts.Any(e =>
                                               e == "*" // accept a wildcard for "all" clients
                                               || e.Equals(client.Alias, StringComparison.InvariantCultureIgnoreCase)
                                               || e.Equals($"{client.HostName}:{client.PortNumber}", StringComparison.OrdinalIgnoreCase)
                                               || e.Equals(client.Thumbprint, StringComparison.OrdinalIgnoreCase)));
                                    foreach (var client in clients)
                                    {
#pragma warning disable 4014
                                        StopClientWorker(client);
#pragma warning restore 4014
                                    }
                                }
                            }
                            break;

                        case "/CONNECT":
                            // treat each command input as a 'hostport'
                            commandParts.Skip(1).Select(async hostport =>
                            {
                                try
                                {
                                    var client = await ConnectTo(hostport, rsa);
                                }
                                catch (Exception ex)
                                {
                                    Log(ex);
                                }
                            })
                            .ToArray();
                            break;

                        case "/NOLISTEN":
                        case "/NOHOST":
                            StopListening();
                            break;

                        case "/PING":
                            {
                                // manual ping initiation for all hosts
                                var clients = default(IEnumerable<Task>);
                                lock (_clients)
                                {
                                    clients = _clients.Values
                                        .Select(PING)
                                        .ToArray(); // fire and forget.
                                }
                            }
                            break;

                        case "/ACCEPT":
                            {
                                if (commandParts.Length < 2)
                                {
                                    PrintInteractiveHelp(commandParts[0]);
                                }
                                else
                                {
                                    lock (_whitelist)
                                    {
                                        var thumbprint = commandParts[1];
                                        _whitelist.TryGetValue(thumbprint, out string L_alias);
                                        var alias = commandParts.Length > 2
                                            ? commandParts[2]
                                            : L_alias
                                            ?? thumbprint;
                                        _whitelist[thumbprint] = alias;
                                        lock (_clients)
                                        {
                                            foreach (var client in _clients.Values)
                                            {
                                                if (client.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    client.Alias = alias;
                                                }
                                            }
                                        }
                                        StoreWhitelist();
                                        Log($"ACCEPT: '{thumbprint}' => '{alias}'");
                                    }
                                }
                            }
                            break;

                        case "/BAN":
                            {
                                // remove from whitelist, each command part would be a new thumbprint
                                lock (_clients)
                                    lock (_whitelist)
                                    {
                                        var clients = _clients.Values
                                            .Where(client => commandParts.Any(e =>
                                                e.Equals(client.Alias, StringComparison.InvariantCultureIgnoreCase)
                                                || e.Equals($"{client.HostName}:{client.PortNumber}", StringComparison.OrdinalIgnoreCase)
                                                || e.Equals(client.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                                            .ToArray();

                                        var blacklist = _whitelist
                                            .Where(kvp => commandParts.Any(e =>
                                                kvp.Key.Equals(e, StringComparison.OrdinalIgnoreCase))
                                                || commandParts.Any(e => kvp.Value.Equals(e, StringComparison.OrdinalIgnoreCase)))
                                            .Select(kvp => kvp.Key)
                                            .ToArray();

                                        foreach (var thumbprint in blacklist)
                                        {
                                            _whitelist.Remove(thumbprint);
                                            Log($"BAN: {thumbprint}");
                                        }

                                        StoreWhitelist();

                                        foreach (var client in clients)
                                        {
#pragma warning disable 4014
                                            StopClientWorker(client);
#pragma warning restore 4014
                                        }
                                    }
                            }
                            break;

                        case "/WHITELIST":
                            {
                                lock (_whitelist)
                                {
                                    foreach (var thumbprint in _whitelist)
                                    {
                                        Log($"WHITELIST: {thumbprint}");
                                    }
                                }
                            }
                            break;

                        default:
                            {
                                // write message to all connected clients (like a chat room)
                                var tasks = default(IEnumerable<Task>);
                                var failures = new List<ClientState>();
                                lock (_clients)
                                {
                                    tasks = _clients.Values
                                        .Select(client => Task.Factory.StartNew(async () =>
                                        {
                                            try
                                            {
                                                Send(client, command);
                                            }
                                            catch (Exception ex)
                                            {
                                                Log(ex);
                                                failures.Add(client);
                                            }
                                            await Task.CompletedTask;
                                        }))
                                        .ToArray();
                                }
                                if (tasks.Any())
                                {
                                    Task.WaitAll(tasks.ToArray());
                                    tasks = failures.Select(client =>
                                    {
                                        try
                                        {
                                            lock (_clients)
                                            {
                                                if (_clients.Remove($"{client.HostName}:{client.PortNumber}"))
                                                {
                                                    DebugLog($"FAILED: Removed {client}");
                                                    return StopClientWorker(client);
                                                }
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Log(ex);
                                        }
                                        return Task.CompletedTask;
                                    }).ToArray();
                                    if (tasks.Any())
                                    {
                                        Task.WaitAll(tasks.ToArray());
                                    }
                                }
                            }
                            break;
                    }
                }
            }
        }

        private static int _processId;
        private static void Main(string[] args)
        {
            _processId = Process.GetCurrentProcess().Id;
            try
            {
                if (args == null || args.Length == 0)
                {
                    PrintHelp();
                    return;
                }
                UpdateDynamicDns();
                var opcode = args[0].ToUpperInvariant();
                var keyid = args.Length > 1
                    ? args[1]
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
                            var rsa = LoadKeypair(keyid, true); // ie. "My" key, the key used to decrypt incoming data
                            var cancellationTokenSource = new CancellationTokenSource();
                            SwitchToInteractiveMode(rsa, cancellationTokenSource);
                        }
                        return;

                    case "GENKEYS":
                    case "G":
                        GenerateKeypair(keyid, int.Parse(input ?? "8192"));
                        return;

                    case "ENCRYPT":
                    case "E":
                        Encrypt(keyid, input);
                        break;

                    case "DECRYPT":
                    case "D":
                        Decrypt(keyid, input);
                        break;

                    case "HASH":
                    case "H":
                        Hash(keyid);
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
