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
        private static IEnumerable<KeyValuePair<string, string>> LoadWhitelist()
        {
            if (File.Exists("whitelist.txt"))
            {
                using (var reader = new StreamReader(
                    File.Open("whitelist.txt", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)))
                {
                    var line = reader.ReadLine();
                    while (line != null)
                    {
                        var parts = line.Split(',');
                        var thumbprint = parts[0];
                        var alias = parts.Length > 1 ? parts[1] : thumbprint;
                        yield return new KeyValuePair<string, string>(thumbprint, alias);
                        line = reader.ReadLine();
                    }
                }
            }
        }

        private static string GetAlias(string thumbprint)
        {
            lock (_whitelist)
            {
                foreach (var kvp in _whitelist)
                {
                    if (kvp.Key.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return kvp.Value;
                    }
                }
            }
            return thumbprint;
        }
        private static IDictionary<string/*thumbprint*/, string/*display alias*/> _whitelist;

        private static void StoreWhitelist()
        {
            lock (_whitelist)
            {
                if (_whitelist.Count > 0)
                {
                    using (var writer = new StreamWriter(
                        File.Open("whitelist.txt", FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete)))
                    {
                        _whitelist.ToList().ForEach(kvp => writer.WriteLine($"{kvp.Key},{kvp.Value}"));
                        writer.Flush();
                        writer.Close();
                    }
                }
            }
        }


    }
}
