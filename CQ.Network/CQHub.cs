using CQ.Crypto;
using CQ.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using X4D.Diagnostics.Logging;

namespace CQ.Network
{
    public sealed class CQConnectionEventArgs :
        EventArgs
    {
        public CQConnection Connection { get; set; }
    }

    public sealed class CQHub
    {
        private static readonly TimeSpan s_pingInterval = TimeSpan.FromSeconds(47);

        private readonly ICollection<CQConnection> _connections = new List<CQConnection>();

        private readonly Action<string> _onStatusChange;

        private readonly Crypt _crypt;

        private readonly Whitelist _whitelist;

        private readonly RSA _rsa;

        private TcpListener _listener;

        public CQHub(Crypt crypt, Whitelist whitelist, RSA rsa, Action<string> onStatusChange)
        {
            _crypt = crypt;
            _whitelist = whitelist;
            _rsa = rsa;
            _onStatusChange = onStatusChange;
        }

        public event EventHandler<CQConnectionEventArgs> NewConnection;

        public async Task ShutdownAllConnections(string message)
        {
            // scatter-gather shutdown of all connections
            IEnumerable<CQConnection> connections;
            lock (_connections)
            {
                connections = _connections.ToArray();
            }
            await Task.WhenAll(
                connections.Select((connection) =>
                {
                    return connection.Shutdown(message);
                }));
        }

        public async Task<CQConnection> ConnectTo(string hostport)
        {
            var parts = hostport.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            var hostName = parts[0];
            var portNumber = parts.Length > 1 ? int.Parse(parts[1]) : 18593;

            var connection = await CQConnection.Create(_crypt, hostName, portNumber, _rsa, _onStatusChange);

            ValidateWhitelistAndSetAlias(connection);

            lock (_connections)
            {
                // NOTE: prior connections to same peer are not removed, by design
                _connections.Add(connection);
            }
            try
            {
                NewConnection?.Invoke(this, new CQConnectionEventArgs
                {
                    Connection = connection
                });
            }
            catch (Exception ex)
            {
                ex.Log();
            }
            $"Connected to [{connection}]".Log();

            return connection;
        }

        public async Task RelayChatMessage(string message)
        {
            // write message to all connected clients (like a chat room)
            var tasks = default(IEnumerable<Task>);
            IEnumerable<CQConnection> connections;
            lock (_connections)
            {
                connections = _connections.ToArray();
            }
            if (!connections.Any())
            {
                return;
            }
            var buf = Encoding.UTF8.GetBytes(message);
            tasks = connections
                .Select(async (connection) =>
                {
                    try
                    {
                        await connection.WriteMessage(buf);
                        return true;
                    }
                    catch (Exception ex)
                    {
                        ex.Log();
                        var removed = false;
                        lock (_connections)
                        {
                            removed = _connections.Remove(connection);
                        }
                        if (removed)
                        {
                            $"{nameof(RelayChatMessage)}: Ending conversation with {connection.Peer}".Log(System.Diagnostics.TraceEventType.Verbose);
                            await connection.EndConversation();
                        }
                        return false;
                    }
                });
            await Task.WhenAll(tasks.ToArray());
        }

        public async Task StartListening(
            CancellationTokenSource cancellationTokenSource,
            int portNumber)
        {
            if (_listener == null)
            {
                $"Listening for connections on port '{portNumber}'.".Log();
                _listener = new TcpListener(IPAddress.Any, portNumber);
                _listener.Start(10);
                while (!cancellationTokenSource.IsCancellationRequested)
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync();
                    tcpClient.NoDelay = true;
                    tcpClient.ReceiveBufferSize = 16;
                    var remoteEndPoint = (tcpClient.Client.RemoteEndPoint as IPEndPoint);
                    $"Connection request from [{remoteEndPoint.Address}:{remoteEndPoint.Port}]".Log();
                    await OnConnectionAccepted(tcpClient);
                }
                _listener.Stop();
                $"Stopped listening for connections on port '{portNumber}'.".Log();
            }
        }

        public async Task OnConnectionAccepted(TcpClient tcpClient)
        {
            var connection = await CQConnection.Create(
                _crypt,
                tcpClient,
                _rsa,
                _onStatusChange);

            connection.ConversationEnded += (s, e) =>
            {
                lock (_connections)
                {
                    if (_connections.Remove(connection))
                    {
                        $"Removed {connection}".Log();
                    }
                }
            };

            ValidateWhitelistAndSetAlias(connection);

            $"Accepted [{connection}]".Log();
            lock (_connections)
            {
                _connections.Add(connection);
                try
                {
                    NewConnection?.Invoke(this, new CQConnectionEventArgs
                    {
                        Connection = connection
                    });
                }
                catch (Exception ex)
                {
                    ex.Log();
                }
            }
        }

        public async Task StopListening()
        {
            $"{nameof(StopListening)}()".Log(System.Diagnostics.TraceEventType.Verbose);
            var listener = _listener;
            _listener = null;
            if (listener != null)
            {
                try
                {
                    listener.Stop();
                }
                catch (Exception ex)
                {
                    ex.Log();
                }
            }
            await Task.CompletedTask;
        }

        public async Task DisconnectClients(string[] criteria = null)
        {
            IEnumerable<CQConnection> connections;
            lock (_connections)
            {
                connections = _connections.ToArray();
            }
            var tasks = connections
                .Where(connection =>
                    criteria == null
                    || criteria.Any(e =>
                       e == "*" // accept a wildcard for "all" clients
                       || e.Equals(connection.Peer.Alias, StringComparison.InvariantCultureIgnoreCase)
                       || e.Equals($"{connection.Peer.HostName}:{connection.Peer.PortNumber}", StringComparison.OrdinalIgnoreCase)
                       || e.Equals(connection.Peer.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                .Select(e => e.EndConversation("BYE!"))
                .ToArray();
            await Task.WhenAll(tasks);
        }

        public async Task PingAllClients()
        {
            IEnumerable<CQConnection> connections;
            lock (_connections)
            {
                connections = _connections.ToArray();
            }
            var tasks = connections.Select(e => e.Ping()).ToArray();
            await Task.WhenAll(tasks);
        }

        public void UpdatePeerInfo(Func<CQPeer, bool> mutator)
        {
            IEnumerable<CQConnection> connections;
            lock (_connections)
            {
                connections = _connections.ToArray();
            }
            var peers = connections.Select(e => e.Peer);
            var isDirty = false;
            foreach (var peer in peers)
            {
                isDirty = mutator(peer) || isDirty;
            }
        }

        private void ValidateWhitelistAndSetAlias(CQConnection connection)
        {
            $"Checking whitelist for {connection}".Log();
            // check thumbprint against whitelist, if not in whitelist then
            // force a disconnect
            if (_whitelist.TryGetAlias(connection.Peer.Thumbprint, out string alias))
            {
                connection.Peer.Alias = alias;
                _onStatusChange($"{connection} whitelisted as '{connection.Peer.Alias}' ({connection.Peer.Thumbprint})".Log());
            }
            else
            {
                connection.Peer.Alias = connection.Peer.Thumbprint;
                var err = $@"Rejecting {connection.Peer.Thumbprint} -- not authorized.
Use `/WHITELIST <thumbprint>` and `/BAN <thumbprint>` to authorized/deauthorize.".Log();
                _onStatusChange(err);
                throw new Exception(err);
            }
        }

        private async Task StartPingWorker()
        {
            while (true)
            {
                try
                {
                    await Task.Delay(s_pingInterval);
                    await PingAllClients();
                }
                catch (Exception ex)
                {
                    ex.Log();
                }
            }
        }
    }
}
