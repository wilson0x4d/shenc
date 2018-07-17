using CQ.Crypto;
using CQ.Network;
using CQ.Settings;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using X4D.Diagnostics.Logging;

namespace shenc
{
    /// <summary>
    /// Embodies the "interactive shell", separating it further away from the
    /// CLI interface exposed in <see cref="Program"/>.
    /// </summary>
    internal sealed class InteractiveShell
    {
        private readonly Whitelist _whitelist;

        private readonly Netwk _netwk;

        private readonly Crypt _crypt;

        private readonly int _processId;

        private readonly RSA _rsa;

        private readonly CancellationTokenSource _cancellationTokenSource;

        public InteractiveShell(
            Whitelist whitelist,
            Netwk netwk,
            Crypt crypt,
            int processId,
            RSA rsa,
            Action<string> onStatusChange,
            CancellationTokenSource cancellationTokenSource)
        {
            _whitelist = whitelist;
            _netwk = netwk;
            _crypt = crypt;
            _processId = processId;
            _rsa = rsa;
            _cancellationTokenSource = cancellationTokenSource;
            _netwk = new Netwk(_crypt, _whitelist, rsa, onStatusChange);
            _netwk.MessageReceived += (s, e) =>
            {
                Console.WriteLine($"({DateTime.UtcNow.ToString("HH:mm:ss")}) {e.Client}> {e.Message}");
            };
            _netwk.UpdateDynamicDns()
                .ContinueWith(t =>
                {
                    if (t.Exception == null)
                    {
                        Console.WriteLine(t.Result);
                    }
                });
        }

        public static void PrintInteractiveHelp(string commandName)
        {
            #region Interactive Help

            switch (commandName.Trim('/').ToUpperInvariant())
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

Typing text and pressing ENTER will send your message to all connected remotes.

");
                    break;
            }

            #endregion Interactive Help
        }

        public void ProcessCommand(string command)
        {
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
                            _cancellationTokenSource.Cancel(false);
                        }
                        break;

                    case "/LISTEN":
                        {
                            // TODO: control accept queue length
                            var portNumber = commandParts.Length > 1 ? int.Parse(commandParts[1]) : 18593;
                            Console.WriteLine($"Listening for connections on port '{portNumber}'..");
                            _netwk
                                .StartListening(
                                    _cancellationTokenSource,
                                    portNumber)
                                .ContinueWith(t =>
                                {
                                    if (t.Exception == null)
                                    {
                                        Console.WriteLine($"LISTEN: Stopped listening on {portNumber}.");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"LISTEN: Failed to stop listening on {portNumber}.");
                                    }
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
                                var client = await _netwk.ConnectTo(
                                    hostport, 
                                    _rsa);
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
}
