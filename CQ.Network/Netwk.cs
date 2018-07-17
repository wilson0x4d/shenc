using CQ.Crypto;
using CQ.Settings;
using Newtonsoft.Json;
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
    public sealed class Netwk
    {
        public sealed class MessageReceivedEventArgs :
            EventArgs
        {
            /// <summary>
            /// The `ClientState` associated with `Message`.
            /// </summary>
            public ClientState Client { get; set; }

            /// <summary>
            /// The message.
            /// </summary>
            public string Message { get; set; }
        }

        public event EventHandler<MessageReceivedEventArgs> MessageReceived;

        private readonly Crypt _crypt;

        private readonly IDictionary<string, ClientState> _clients;

        private readonly Whitelist _whitelist;

        private readonly Action<string> _onStatusChange;

        private readonly RSA _rsa;

        private TcpListener _listener;

        public Netwk(Crypt crypt, Whitelist whitelist, RSA rsa, Action<string> onStatusChange)
        {
            _rsa = rsa;
            _crypt = crypt;
            _clients = new Dictionary<string, ClientState>(StringComparer.OrdinalIgnoreCase);
            _whitelist = whitelist;
            _onStatusChange = onStatusChange;
        }

        public async Task UpdateDynamicDnsAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    var hostname = System.Configuration.ConfigurationManager.AppSettings["no-ip:hostname"];
                    var auth = System.Configuration.ConfigurationManager.AppSettings["no-ip:auth"];
                    var keyid = System.Configuration.ConfigurationManager.AppSettings["no-ip:key"] ?? "chat";
                    if (!string.IsNullOrEmpty(hostname) && !string.IsNullOrEmpty(auth))
                    {
                        var key = _crypt.LoadKeypair(keyid, false);
                        var edata = Convert.FromBase64String(auth);
                        var data = key.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                        var parts = Encoding.UTF8.GetString(data).Split(':');

                        var userName = parts[0];
                        var password = parts[1];

                        var ipaddr = System.Configuration.ConfigurationManager.AppSettings["no-ip:address"] ?? WhatsMyIP();

                        var ddnsSuccess = TryWebGet(
                            new Uri($"https://dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={ipaddr}"),
                            userName,
                            password,
                            out string result);

                        _onStatusChange($"DDNS RESULT: {(ddnsSuccess ? "SUCCESS" : "FAILED")}> {result}"
                            .Log(ddnsSuccess
                                ? System.Diagnostics.TraceEventType.Information
                                : System.Diagnostics.TraceEventType.Warning));
                    }
                }
                catch (Exception ex)
                {
                    ex.Log();
                }
            });
        }


            public bool TryGetClient(string hostport, out ClientState client)
        {
            return _clients.TryGetValue(hostport, out client);
        }

        public void ShutdownAllClientWorkers()
        {
            // shutdown all client workers
            lock (_clients)
            {
                Task.WaitAll(
                    _clients.Values.Select(StopClientWorker).ToArray(),
                    5000);
            }
        }

        public async Task<ClientState> ConnectTo(string hostport, RSA rsa)
        {
            var parts = hostport.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            var hostName = parts[0];
            var portNumber = parts.Length > 1 ? int.Parse(parts[1]) : 18593;
            hostport = $"{hostName}:{portNumber}";
            var tcpClient = new TcpClient();
            tcpClient.NoDelay = true;
            $"Establishing connection to [{hostport}]..".Log();
            await tcpClient.ConnectAsync(hostName, portNumber);
            var client = default(ClientState);
            lock (_clients)
            {
                client = new ClientState(
                    hostName,
                    portNumber,
                    tcpClient);
                if (_clients.TryGetValue(hostport, out ClientState existingClient))
                {
                    _clients[hostport] = client;
                    $"Replacing '{existingClient}' with '{client}'..".Log();
#pragma warning disable 4014
                    StopClientWorker(existingClient);
#pragma warning restore 4014
                }
                else
                {
                    _clients[hostport] = client;
                    $"Added '{client}'".Log();
                }
            }
#pragma warning disable 4014
            client.Worker = StartClientWorker(client, rsa);
            client.Worker.ContinueWith((t) =>
            {
                lock (_clients)
                {
                    if (_clients.Remove(hostport))
                    {
                        $"Removed {client}".Log(System.Diagnostics.TraceEventType.Verbose);
                    }
                }
            });
#pragma warning restore 4014
            return client;
        }

        public string Ban(string[] commandParts)
        {
            var result = new StringBuilder();
            // remove from whitelist, each command part would be a new thumbprint
            lock (_clients)
            {
                lock (_whitelist)
                {
                    var clients = _clients.Values
                        .Where(client => commandParts.Any(e =>
                            e.Equals(client.Alias, StringComparison.InvariantCultureIgnoreCase)
                            || e.Equals($"{client.HostName}:{client.PortNumber}", StringComparison.OrdinalIgnoreCase)
                            || e.Equals(client.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                        .ToArray();

                    var blacklist = _whitelist.GetMatchingThumbprints(commandParts);
                    foreach (var thumbprint in blacklist)
                    {
                        _whitelist.Remove(thumbprint);
                        result.AppendLine($"BAN: {thumbprint}".Log());
                    }

                    _whitelist.StoreWhitelist();

                    foreach (var client in clients)
                    {
#pragma warning disable 4014
                        StopClientWorker(client);
#pragma warning restore 4014
                    }
                }
            }

            return result.ToString();
        }

        public void SendChatMessage(string command)
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
                            ex.Log();
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
                                $"FAILED: Removed {client}".Log(System.Diagnostics.TraceEventType.Verbose);
                                return StopClientWorker(client);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        ex.Log();
                    }
                    return Task.CompletedTask;
                }).ToArray();
                if (tasks.Any())
                {
                    Task.WaitAll(tasks.ToArray());
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
                    _whitelist.StoreWhitelist();
                    return $"ACCEPT: '{thumbprint}' => '{alias}'".Log();
                }
            }
        }

        public void PingAllClients()
        {
            // manual ping initiation for all hosts
            var clients = default(IEnumerable<Task>);
            lock (_clients)
            {
                clients = _clients.Values
                    .Select(PingClient)
                    .ToArray(); // fire and forget.
            }
        }

        public void DisconnectAllClients(string[] commandParts)
        {
            // disconnect all clients and stop all client workers
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

        public void Send(ClientState client, string message)
        {
            $"{nameof(Send)}({client},{message})".Log(System.Diagnostics.TraceEventType.Verbose);
            var data = Encoding.UTF8.GetBytes(message);
            var edata = client.RSA == null ? data : client.RSA.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            client.TcpClient.Client.Send(BitConverter.GetBytes(edata.Length), SocketFlags.Partial);
            client.TcpClient.Client.Send(edata, SocketFlags.Partial);
        }

        public async Task PingClient(ClientState client)
        {
            // TODO: ping should execute at regular intervals for keepalive and/or orphan/stale/dead link detection
            // TODO: ping should perform a "CHAL", ie. the PONG response should contain our signature, signed by the remote, which we can then use to authenticate the link. in a "man in the middle" attack should yield either a bad PING sig or a bad PONG sig which should result in a hard disconnect from either end
            await Task.CompletedTask; // in most cases, ping() is fire-and-forget. except during initial connection, we use ping/pong as an initial CHAL
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
                    var client = await _listener.AcceptTcpClientAsync();
                    client.NoDelay = true;
                    var remoteEndPoint = (client.Client.RemoteEndPoint as IPEndPoint);
                    $"Connection request from [{remoteEndPoint.Address}:{remoteEndPoint.Port}]".Log();
                    OnClientAcceptCallback(
                        new ClientState(
                            $"{remoteEndPoint.Address}",
                            remoteEndPoint.Port,
                            client),
                        _rsa);
                }
                _listener.Stop();
                $"Stopped listening for connections on port '{portNumber}'.".Log();
            }
        }

        public void StopListening()
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
        }

        public async Task StopClientWorker(ClientState client)
        {
            $"{nameof(StopClientWorker)}({client})".Log(System.Diagnostics.TraceEventType.Verbose);
            try
            {
                var clientWorker = client.Worker;
                client.CancellationTokenSource.Cancel();
                if (clientWorker != null)
                {
                    await clientWorker;
                }
            }
            catch (Exception ex)
            {
                ex.Log();
            }
        }

        public async Task StartClientWorker(
            ClientState client,
            RSA rsa)
        {
            client.CancellationTokenSource = new CancellationTokenSource();

            // exchange our pubkey in the clear, this starts our conversation with remote
            var rsaParameters = rsa.ExportParameters(false);
            var pubkey = JsonConvert.SerializeObject(rsaParameters);
            Send(client, pubkey);

            var buf = new byte[1024 * 1024 * 48];
            var expectedSize = 0;
            var writeOffset = 0;
            var readOffset = 0;
            try
            {
                using (var stream = client.TcpClient.GetStream())
                {
                    var isSTUN = false;
                    while (!client.CancellationTokenSource.IsCancellationRequested)
                    {
                        if (expectedSize == 0)
                        {
                            var availableCount = (writeOffset - readOffset);
                            if (availableCount >= 4)
                            {
                                expectedSize = BitConverter.ToInt32(buf, readOffset);
                                if (expectedSize == 0)
                                {
                                    isSTUN = true;
                                    expectedSize = 4;
                                }
                                else
                                {
                                    isSTUN = false;
                                }
                                readOffset += 4;
                                if (expectedSize > (buf.Length - readOffset))
                                {
                                    throw new IndexOutOfRangeException($"Size Prefix '{expectedSize}' exceeds '{buf.Length}' for [{client.HostName}:{client.PortNumber}]");
                                }
                            }
                        }
                        else if ((writeOffset - readOffset) >= expectedSize)
                        {
                            var edata = new byte[expectedSize];
                            expectedSize = 0;
                            Array.Copy(buf, readOffset, edata, 0, edata.Length);
                            readOffset += edata.Length;
                            if (client.RSA == null)
                            {
                                // expect to receive pubkey from remote in the clear
                                var clientRSA = RSA.Create(); // TODO: verify disposal
                                clientRSA.ImportParameters(
                                    JsonConvert.DeserializeObject<RSAParameters>(
                                        Encoding.UTF8.GetString(edata)));
                                client.RSA = clientRSA; // late assignment avoids race condition (invalid thumbprint result) from interstitial before import completes.
                                client.Thumbprint = _crypt.GetThumbprint(clientRSA);
                                // check client pubkey thumbprint against whitelist, if not in whitelist then force a disconnect
                                if (_whitelist.TryGetAlias(client.Thumbprint, out string alias))
                                {
                                    client.Alias = alias;
                                    _onStatusChange($"Connected to {client}");
                                }
                                else
                                {
                                    client.Alias = client.Thumbprint;
                                    _onStatusChange($@"Rejecting {client}, thumbprint is not authorized.
You can use the `/ACCEPT <thumbprint>` and `/BAN <thumbprint>` commands to authorized/deauthorize.".Log());
                                    break;
                                }
                            }
                            else
                            {
                                var data = rsa.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                                if (isSTUN)
                                {
                                    // TODO: stun
                                }
                                else
                                {
                                    var message = Encoding.UTF8.GetString(data);
                                    MessageReceived?.Invoke(this, new MessageReceivedEventArgs // [pleXus]
                                    {
                                        Client = client,
                                        Message = message
                                    });
                                }
                            }
                        }
                        var count = (expectedSize > 0)
                            ? expectedSize
                            : 4;
                        var cb = 0;
                        try
                        {
                            // TODO: implement PING, and then set a timeout for this read op that is (ping_interval*1.5) (ie. if no read within ping interval + grace period assume a dead link.)
                            var readTimeoutToken = new CancellationTokenSource(TimeSpan.FromMinutes(2)).Token;
                            cb = await stream.ReadAsync(buf, writeOffset, count, readTimeoutToken);
                        }
                        catch (Exception)// ex)
                        {
                            // NOP: the reasons for a failed read are all valid, and should result in a disconnect sequence
                            break;
                        }
                        writeOffset += cb;
                        if (cb == 0)
                        {
                            _onStatusChange($"WORKER: Disconnection request detected for [{client.HostName}:{client.PortNumber}]".Log());
                            // remote closure initiated
                            client.CancellationTokenSource.Cancel();
                            break;
                        }
                        else if (writeOffset >= buf.Length)
                        {
                            // TODO: gracefully d/c the offending client instead
                            throw new RankException($"Internal buffer overflow detected for [{client.HostName}:{client.PortNumber}]".Log());
                        }
                        else if (readOffset > writeOffset)
                        {
                            throw new RankException($"Internal buffer underflow detected for [{client.HostName}:{client.PortNumber}]".Log());
                        }
                        else if (readOffset == writeOffset && expectedSize == 0)
                        {
                            // the logic basically states if we're not expecting data, reset buffer state to avoid overflow
                            readOffset = 0;
                            writeOffset = 0;
                        }
                    }
                    stream.Close(10 * 1000);
                }
            }
            catch (Exception ex)
            {
                ex.Log();
            }
            finally
            {
                client.TcpClient.Close();
                client.TcpClient.Dispose();
                client.TcpClient = null;
                _onStatusChange($"WORKER: Disconnected from client".Log());
            }
        }

        public void OnClientAcceptCallback(ClientState client, RSA rsa)
        {
            var hostport = $"{client.HostName}:{client.PortNumber}";
            $"{nameof(OnClientAcceptCallback)}({client},{_crypt.GetThumbprint(rsa)}) via [{hostport}]".Log(System.Diagnostics.TraceEventType.Verbose);
            lock (_clients)
            {
                if (_clients.TryGetValue(hostport, out ClientState existingClient))
                {
                    if (client.Thumbprint == existingClient.Thumbprint || string.IsNullOrEmpty(existingClient.Thumbprint))
                    {
                        _clients[hostport] = client;
                        $"LISTEN: Replacing '{existingClient}' with '{client}'..".Log();
#pragma warning disable 4014
                        StopClientWorker(existingClient);
#pragma warning restore 4014
                    }
                    else
                    {
                        $"LISTEN: Denying reconnction attempt for {hostport} because thumbprint '{client.Thumbprint}' does not match prior thumbprint '{existingClient.Thumbprint}'.".Log();
                        return;
                    }
                }
                else
                {
                    _clients[hostport] = client;
                    $"LISTEN: Added '{client}'".Log();
                }
            }
            client.Worker = StartClientWorker(client, rsa);
            client.Worker.ContinueWith((t) =>
            {
                lock (_clients)
                {
                    if (_clients.Remove(hostport))
                    {
                        $"LISTEN: Removed {client}".Log(System.Diagnostics.TraceEventType.Verbose);
                    }
                }
            });
        }

        private bool TryWebGet(
            Uri uri,
            string userName,
            string password,
            out string result)
        {
            try
            {
                var webClient = new WebClient
                {
                    Credentials = new NetworkCredential(userName, password),
                    CachePolicy = new System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore),
                    Encoding = Encoding.UTF8
                };
                webClient.Headers.Add("User-Agent", "shenc/0.1 shenc@mrshaunwilson.com");
                result = webClient.DownloadString(uri);
                return true;
            }
            catch (Exception ex)
            {
                // TODO: use a logging framework, instead
                result = (new StringBuilder($"Exception: {ex.GetType().FullName}"))
                    .AppendLine($"Exception: {ex.GetType().FullName}")
                    .AppendLine($"Message: {ex.Message}")
                    .AppendLine($"StackTrace: {ex.StackTrace}")
                    .ToString();
                return false;
            }
        }

        private string WhatsMyIP()
        {
            var webClient = new WebClient();
            webClient.Headers.Add("User-Agent", "shenc/0.1 shenc@mrshaunwilson.com");
            var response = webClient.DownloadString("https://ipapi.co/json/");
            dynamic obj = JsonConvert.DeserializeObject(response);
            return (obj != null && !string.IsNullOrWhiteSpace(Convert.ToString(obj.ip)))
                ? obj.ip
                : Dns.GetHostEntry(IPAddress.Any).AddressList.FirstOrDefault();
        }
    }
}
