using CQ.Crypto;
using CQ.Network;
using CQ.Settings;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
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

        private readonly CQHub _cqHub;

        private readonly Crypt _crypt;

        private readonly int _processId;

        private readonly RSA _rsa;

        private readonly CancellationTokenSource _cancellationTokenSource;

        public InteractiveShell(
            Whitelist whitelist,
            CQHub cqHub,
            Crypt crypt,
            int processId,
            RSA rsa,
            Action<string> onStatusChange,
            CancellationTokenSource cancellationTokenSource)
        {
            _whitelist = whitelist;
            _cqHub = cqHub;
            _crypt = crypt;
            _processId = processId;
            _rsa = rsa;
            _cancellationTokenSource = cancellationTokenSource;
            _cqHub.NewConnection += Hub_NewConnection;
        }

        private void Hub_NewConnection(object sender, CQConnectionEventArgs e)
        {
            e.Connection.MessageReceived += Connection_MessageReceived;
        }

        private void Connection_MessageReceived(object sender, CQConnection.MessageReceivedEventArgs e)
        {
            Console.WriteLine($"({DateTime.UtcNow.ToString("HH:mm:ss")}) {e.Peer}> {e.Message}");
        }

        public static void PrintInteractiveHelp(string commandName = "HELP")
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

See also: /WHITELIST, /NOLISTEN
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

                case "WHITELIST":
                    Console.WriteLine(@"

Summary:

    If called without parameters, displays the current WHITELIST entries.

    Otherwise, adds the specifiedi thumbprint to the WHITELIST, and 
    optionally assign it an alias.

Usage:
    /WHITELIST [<thumbprint> [alias]]

    thumbprint = (optional) a thumbrint associated
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

/CONNECT <host[:port]>
/DISCONNECT <alias|<host[:port]>>

/WHITELIST [<thumbprint> [alias]]
/BAN <thumbprint|alias|<host[:port]>>
/WHITELIST

/QUIT

Typing text and pressing ENTER will send your message to all connected remotes.

");
                    break;
            }

            #endregion Interactive Help
        }

        public async Task ProcessCommand(string command)
        {
            var commandParts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (commandParts.Length > 0)
            {
                commandParts[0] = commandParts[0].ToUpperInvariant();
                switch (commandParts[0])
                {
                    case "/QUIT":
                        await QUIT(commandParts);
                        return;

                    case "/LISTEN":
                        await LISTEN(commandParts);
                        return;

                    case "/DISCONNECT":
                        await DISCONNECT(commandParts);
                        return;

                    case "/CONNECT":
                        await CONNECT(commandParts);
                        return;

                    case "/NOLISTEN":
                        await NOLISTEN(commandParts);
                        return;

                    case "/PING":
                        await PING(commandParts);
                        return;

                    case "/BAN":
                        await BAN(commandParts);
                        return;

                    case "/WHITELIST":
                        await WHITELIST(commandParts);
                        return;

                    case "/SAY":
                        await SAY(commandParts);
                        return;

                    default:
                        var helpTopic = commandParts.Length > 1
                                ? commandParts[1]
                                : commandParts[0];
                        PrintInteractiveHelp(helpTopic);
                        break;
                }
            }
        }

        private async Task SAY(string[] commandParts)
        {
            var message = string.Join(' ', commandParts.Skip(1));
            await _cqHub.RelayChatMessage(message);
        }

        private async Task WHITELIST(string[] commandParts)
        {
            if (commandParts?.Length > 1)
            {
                Console.WriteLine(
                    AcceptClient(commandParts));
            }
            else
            {
                foreach (var entry in _whitelist)
                {
                    Console.WriteLine($"WHITELIST: {entry}");
                }
            }
            await Task.CompletedTask;
        }

        private async Task BAN(string[] commandParts)
        {
            // remove from whitelist, each command part would be a new thumbprint/alias
            foreach (var thumbprintOrAlias in commandParts)
            {
                try
                {
                    _whitelist.Remove(thumbprintOrAlias);
                    await _cqHub.DisconnectClients(new[] { thumbprintOrAlias });
                }
                catch (Exception ex)
                {
                    ex.Log();
                }
            }
        }

        public string AcceptClient(string[] commandParts)
        {
            if (commandParts.Length < 2)
            {
                // TODO: PrintInteractiveHelp(commandParts[0]);
                throw new ArgumentException("invalid command parts");
            }
            else
            {
                lock (_whitelist)
                {
                    var thumbprint = commandParts[1];
                    _whitelist.TryGetAlias(thumbprint, out string alias);
                    alias = commandParts.Length > 2
                        ? commandParts[2]
                        : alias
                        ?? thumbprint;
                    _whitelist.Set(thumbprint, alias);
                    _cqHub.UpdatePeerInfo(peer =>
                    {
                        if (peer.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                        {
                            peer.Alias = alias;
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    });
                    _whitelist.StoreWhitelist();
                    return $"ACCEPT: '{thumbprint}' => '{alias}'".Log();
                }
            }
        }

        private async Task PING(string[] commandParts)
        {
            // TODO: ping specific client(s)
            await _cqHub.PingAllClients();
            // TODO: correlation of PONG! for latency info?
        }

        private async Task NOLISTEN(string[] commandParts)
        {
            await _cqHub.StopListening();
        }

        private async Task CONNECT(string[] commandParts)
        {
            var hostport = string.Join(' ', commandParts.Skip(1).ToArray());
            try
            {
                Console.WriteLine($"Establishing connection to [{hostport}]");
                await _cqHub.ConnectTo(hostport);
            }
            catch (Exception ex)
            {
                // TODO: console?
                ex.Log();
            }
        }

        private async Task DISCONNECT(string[] commandParts)
        {
            var hostportOrThumbprintOrAlias = string.Join(' ', commandParts.Skip(1).ToArray());
            try
            {
                Console.WriteLine($"Disconnecting from [{hostportOrThumbprintOrAlias}]");
                await _cqHub.DisconnectClients(new[] { hostportOrThumbprintOrAlias });
            }
            catch (Exception ex)
            {
                // TODO: console?
                ex.Log();
            }
        }

        private async Task LISTEN(string[] commandParts)
        {
            // TODO: control accept queue length
            var portNumber = commandParts.Length > 1 ? int.Parse(commandParts[1]) : 18593;
            Console.WriteLine($"Listening for connections on port '{portNumber}'..");
#pragma warning disable 4014
            _cqHub
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
#pragma warning restore 4014
            await Task.CompletedTask;
        }

        private async Task QUIT(string[] commandParts)
        {
            try
            {
                Console.WriteLine("Disconnecting..".Log());
                await _cqHub.DisconnectClients();
            }
            finally
            {
                Console.WriteLine("Shutting down..".Log());
                _cancellationTokenSource.Cancel(false);
            }
        }
    }
}
