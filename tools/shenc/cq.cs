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
        private sealed class ClientState :
            IDisposable
        {
            private RSA _rsa;

            ~ClientState()
            {
                Dispose(false);
            }

            public CancellationTokenSource CancellationTokenSource { get; set; }

            public string Alias { get; set; }

            public string HostName { get; set; }

            public int PortNumber { get; set; }

            public RSA RSA
            {
                get
                {
                    return _rsa;
                }
                set
                {
                    if (_rsa != value)
                    {
                        _rsa = value;
                        if (_rsa != null)
                        {
                            Thumbprint = GetThumbprint(_rsa);
                            Alias = GetAlias(Thumbprint);
                        }
                        else
                        {
                            Thumbprint = "(null)";
                            Alias = $"{HostName}:{PortNumber}";
                        }
                    }
                }
            }

            public string Thumbprint { get; set; }

            public TcpClient TcpClient { get; set; }

            public Task Worker { get; set; }

            public override string ToString()
            {
                return $"{Alias ?? Thumbprint ?? HostName + ":" + PortNumber}";
            }

            public void Dispose()
            {
                Dispose(true);
            }

            private void Dispose(bool disposing)
            {
                try
                {
                    var rsa = RSA;
                    RSA = null;
                    if (rsa != null)
                    {
                        rsa.Dispose();
                    }
                }
                catch { /* NOP */ }
            }
        }
    }
}
