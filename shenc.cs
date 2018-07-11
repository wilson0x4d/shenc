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
    /// <summary>
    /// A quick and dirty tool for encrypting/decrypting text from a shell prompt.
    /// <para>Generates a one-time keypair, used for encryption/decryption.</para>
    /// <para>PUBLIC  key stored to `.pubkey` file.</para>
    /// <para>PRIVATE key stored to `.prikey` file.</para>
    /// <para>Now offers a "chat" mode.</para>
    /// </summary>
    internal class Program
    {
        private static TcpListener _listener;

        private static IDictionary<string, ClientState> _clients;

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
                var keyid = args.Length > 1
                    ? args[1]
                    : default(string);
                var input = args.Length > 2
                    ? string.Join(" ", args.Skip(2))
                    : default(string);

                switch (opcode)
                {
                    case "CHAT":
                        if (string.IsNullOrWhiteSpace(keyid))
                        {
                            keyid = "chat";
                        }
                        var csp = LoadKeypair(keyid, true); // ie. "My" key, the key used to decrypt incoming data
                        var cancellationTokenSource = new CancellationTokenSource();
                        SwitchToInteractiveMode(csp, cancellationTokenSource)
                            .Wait();
                        return;

                    case "G":
                        GenerateKeypair(keyid);
                        return;

                    case "E":
                        Encrypt(keyid, input);
                        break;

                    case "D":
                        Decrypt(keyid, input);
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

        private static async Task SwitchToInteractiveMode(
            RSA csp,
            CancellationTokenSource cancellationTokenSource)
        {
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
                    switch (commandParts[0].ToUpperInvariant())
                    {
                        case "/HELP":
                        case "/?":
                            PrintInteractiveHelp();
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
                        case "/HOST":
                            // TODO: control accept queue length
                            // TODO: limit who to accept connections from (thumbprints?)
#pragma warning disable 4014
                            StartListening(
                                cancellationTokenSource,
                                commandParts.Length > 1 ? int.Parse(commandParts[1]) : 18593,
                                (client) =>
                                {
                                    var hostport = $"{client.HostName}:{client.PortNumber}";
                                    lock (_clients)
                                    {
                                        if (_clients.TryGetValue(hostport, out ClientState existingClient))
                                        {
                                            StopClientWorker(existingClient);
                                        }
                                        _clients[hostport] = client;
                                    }
                                    StartClientWorker(client, csp)
                                        .ContinueWith((t) =>
                                        {
                                            _clients.Remove(hostport);
                                        });
                                });
#pragma warning restore 4014
                            break;

                        case "/DISCONNECT":
                        case "/PART":
                            foreach (var hostport in commandParts)
                            {
                                lock (_clients)
                                {
                                    if (_clients.TryGetValue(hostport, out ClientState client))
                                    {
                                        if (_clients.Remove(hostport))
                                        {
#pragma warning disable 4014
                                            StopClientWorker(client);
#pragma warning restore 4014
                                        }
                                    }
                                }
                            }
                            break;

                        case "/CONNECT":
                        case "/JOIN":
                            // treat each command input as a 'hostport'
                            commandParts.Skip(1).Select(async hostport =>
                            {
                                try
                                {
                                    var client = await ConnectTo(hostport, csp);
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
                                    tasks = failures.Select(async client =>
                                    {
                                        try
                                        {
                                            if (_clients.Remove($"{client.HostName}:{client.PortNumber}"))
                                            {
                                                await StopClientWorker(client);
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Log(ex);
                                        }
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

        private static async Task<ClientState> ConnectTo(
            string hostport,
            RSA csp)
        {
            var parts = hostport.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            var hostName = parts[0];
            var portNumber = parts.Length > 1 ? int.Parse(parts[1]) : 18593;
            hostport = $"{hostName}:{portNumber}";
            var tcpClient = new TcpClient();
            tcpClient.NoDelay = true;
            Console.WriteLine($"Requesting connection to [{hostport}]..");
            await tcpClient.ConnectAsync(hostName, portNumber);
            var client = default(ClientState);
            lock (_clients)
            {
                if (_clients.TryGetValue(hostport, out client))
                {
#pragma warning disable 4014
                    StopClientWorker(client);
#pragma warning restore 4014
                }
                client = new ClientState
                {
                    HostName = hostName,
                    PortNumber = portNumber,
                    TcpClient = tcpClient
                };
                _clients[hostport] = client;
            }
#pragma warning disable 4014
            StartClientWorker(client, csp)
                .ContinueWith((t) =>
                {
                    _clients.Remove(hostport);
                });
#pragma warning restore 4014
            return client;
        }

        private static void Send(ClientState client, string message)
        {
            var data = Encoding.UTF8.GetBytes(message);
            var edata = client.CSP == null ? data : client.CSP.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            client.TcpClient.Client.Send(BitConverter.GetBytes(edata.Length), SocketFlags.Partial);
            client.TcpClient.Client.Send(edata, SocketFlags.Partial);
        }

        private static async Task StartClientWorker(
            ClientState client,
            RSA csp)
        {
            client.CancellationTokenSource = new CancellationTokenSource();

            // send pubkey in the clear, this starts our conversation with remote
            Send(client, csp.ToXmlString(false));

            var buf = new byte[1024 * 1024 * 48];
            var expectedSize = 0;
            var writeOffset = 0;
            var readOffset = 0;
            try
            {
                using (var stream = client.TcpClient.GetStream())
                {
                    while (!client.CancellationTokenSource.IsCancellationRequested)
                    {
                        if (expectedSize == 0)
                        {
                            var availableCount = (writeOffset - readOffset);
                            if (availableCount >= 4)
                            {
                                expectedSize = BitConverter.ToInt32(buf, readOffset);
                                readOffset += 4;
                                if (expectedSize > (buf.Length - readOffset))
                                {
                                    throw new IndexOutOfRangeException($"Size Prefix '{expectedSize}' exceeds internal limit '{buf.Length}' for [{client.HostName}:{client.PortNumber}]");
                                }
                            }
                        }
                        else if ((writeOffset - readOffset) >= expectedSize)
                        {
                            var edata = new byte[expectedSize];
                            expectedSize = 0;
                            Array.Copy(buf, readOffset, edata, 0, edata.Length);
                            readOffset += edata.Length;
                            if (client.CSP == null)
                            {
                                // expect to receive CSP from remote
                                var xml = Encoding.UTF8.GetString(edata);
                                client.CSP = new RSACryptoServiceProvider(new CspParameters { ProviderType = 1 });
                                client.CSP.FromXmlString(xml);
                                Console.WriteLine($"Connected to [{client.HostName}:{client.PortNumber}]");
                            }
                            else
                            {
                                var data = csp.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
                                var message = Encoding.UTF8.GetString(data);
                                Console.WriteLine($"[{client.HostName}:{client.PortNumber}] {message}");
                            }
                        }
                        var count = buf.Length - writeOffset;
                        count = (count > 128) ? 128 : count;
                        var cb = await stream.ReadAsync(buf, writeOffset, count);
                        writeOffset += cb;
                        if (cb == 0)
                        {
                            Console.WriteLine($"Disconnection request detected for [{client.HostName}:{client.PortNumber}]");
                            // remote closure initiated
                            client.CancellationTokenSource.Cancel();
                            break;
                        }
                        else if (writeOffset >= buf.Length)
                        {
                            // TODO: gracefully d/c the offending client instead
                            throw new RankException($"Internal buffer overflow detected for [{client.HostName}:{client.PortNumber}]");
                        }
                        else if (readOffset > writeOffset)
                        {
                            throw new RankException($"Internal buffer underflow detected for [{client.HostName}:{client.PortNumber}]");
                        }
                        else if (readOffset == writeOffset)
                        {
                            //readOffset = 0;
                            //writeOffset = 0;
                        }
                    }
                    stream.Close(10 * 1000);
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
            finally
            {
                client.TcpClient.Close();
                client.TcpClient.Dispose();
                client.TcpClient = null;
                Console.WriteLine($"Disconnected from [{client.HostName}:{client.PortNumber}]");
            }
        }

        private static async Task PING(ClientState client)
        {
            // TODO: ping should execute at regular intervals for keepalive and/or orphan/stale/dead link detection
            // TODO: ping should perform a "CHAL", ie. the PONG response should contain our signature, signed by the remote, which we can then use to authenticate the link. in a "man in the middle" attack should yield either a bad PING sig or a bad PONG sig which should result in a hard disconnect from either end
            await Task.CompletedTask; // in most cases, ping() is fire-and-forget. except during initial connection, we use ping/pong as an initial CHAL
        }

        private static async Task StartListening(
            CancellationTokenSource cancellationTokenSource,
            int port,
            Action<ClientState> onAcceptCallback)
        {
            if (_listener == null)
            {
                _listener = new TcpListener(System.Net.IPAddress.Any, port);
                _listener.Start(10);
                Console.WriteLine($"Listening for clients on port '{port}'..");
                while (!cancellationTokenSource.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    client.NoDelay = true;
                    var remoteEndPoint = (client.Client.RemoteEndPoint as IPEndPoint);
                    Console.WriteLine($"Connection request from [{remoteEndPoint.Address}:{remoteEndPoint.Port}]..");
                    onAcceptCallback(new ClientState
                    {
                        HostName = $"{remoteEndPoint.Address}",
                        PortNumber = remoteEndPoint.Port,
                        TcpClient = client
                    });
                }
                _listener.Stop();
            }
        }

        private static void StopListening()
        {
            if (_listener != null)
            {
                if (_clients != null && _clients.Count > 0)
                {
                    // NOTE: this initiates asynchronous 'client worker
                    //       stops' for all clients, and then waits on all of
                    //       them to complete. it is done this way rather
                    //       than one at a time so any delays can be
                    //       overlapped (ie. it takes less time to shutdown
                    //       for a large number of connections)
                    Task.WaitAll(
                        _clients
                            .Values
                            .Select(client => StopClientWorker(client))
                            .ToArray());
                    _clients.Clear();
                    _clients = null;
                }
            }
        }

        private static async Task StopClientWorker(ClientState client)
        {
            var clientWorker = client.Worker;
            client.CancellationTokenSource.Cancel();
            if (clientWorker != null)
            {
                await clientWorker;
            }
        }

        private static void PrintInteractiveHelp()
        {
            Console.WriteLine();
            Console.WriteLine("/HELP");
            Console.WriteLine();
            Console.WriteLine("/LISTEN <port-number>");
            Console.WriteLine("/NOLISTEN");
            Console.WriteLine();
            Console.WriteLine("/CONNECT <host>:<port>");
            Console.WriteLine("/DISCONNECT <host>:<port>");
            Console.WriteLine();
            Console.WriteLine("/QUIT");
            Console.WriteLine();
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

        private static RSA GenerateKeypair(string keyid = null)
        {
            keyid = keyid ?? $"{Guid.NewGuid()}";
            var cspParameters = new CspParameters
            {
                ProviderType = 1,
                Flags = CspProviderFlags.UseArchivableKey,
                KeyNumber = (int)KeyNumber.Exchange
            };
            var csp = new RSACryptoServiceProvider(cspParameters);
            var prikey = csp.ToXmlString(true);
            var pubkey = csp.ToXmlString(false);
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
            return csp;
        }

        private static RSA LoadKeypair(string keyid, bool generateIfMissing = false)
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
                    return GenerateKeypair(keyid);
                }
                else
                {
                    throw new FileNotFoundException(keyid);
                }
            }
            var csp = new RSACryptoServiceProvider(new CspParameters
            {
                ProviderType = 1
            });
            using (var file = File.OpenText(keyid))
            {
                var xml = file.ReadToEnd();
                csp.FromXmlString(xml);
                file.Close();
            }
            Console.WriteLine($"Loaded Key '{keyid}'");
            return csp;
        }

        private static void EncryptText(string keyfile, string input)
        {
            var csp = LoadKeypair(keyfile);
            var data = Encoding.UTF8.GetBytes(input);
            var edata = csp.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            var output = Convert.ToBase64String(edata, Base64FormattingOptions.None);
            Console.WriteLine(output);
        }

        private static void EncryptFile(string keyfile, string input)
        {
            var csp = LoadKeypair(keyfile);
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
            var csp = LoadKeypair(keyfile);
            var edata = Convert.FromBase64String(input);
            var data = csp.Decrypt(edata, RSAEncryptionPadding.Pkcs1);
            var output = Encoding.UTF8.GetString(data);
            Console.WriteLine(output);
        }

        private static void DecryptFile(string keyfile, string input)
        {
            var csp = LoadKeypair(keyfile);
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

        private sealed class ClientState
        {
            public CancellationTokenSource CancellationTokenSource { get; set; }

            public string HostName { get; set; }

            public int PortNumber { get; set; }

            public RSA CSP { get; set; }

            public TcpClient TcpClient { get; set; }

            public Task Worker { get; set; }
        }
    }
}
