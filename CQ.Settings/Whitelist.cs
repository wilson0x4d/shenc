using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CQ.Settings
{
    public sealed class Whitelist :
        IEnumerable<KeyValuePair<string, string>>
    {
        private readonly IDictionary<string/*thumbprint*/, string/*display alias*/> _thumbprints;

        public Whitelist()
        {
            _thumbprints = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public Whitelist ReloadWhitelist()
        {
            lock (_thumbprints)
            {
                var items = LoadWhitelistInternal();
                _thumbprints.Clear();
                foreach (var item in items)
                {
                    _thumbprints.Add(item);
                }
                return this;
            }
        }

        public IEnumerable<KeyValuePair<string, string>> LoadWhitelistInternal()
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

        public void StoreWhitelist()
        {
            lock (_thumbprints)
            {
                if (_thumbprints.Count > 0)
                {
                    using (var writer = new StreamWriter(
                        File.Open("whitelist.txt", FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete)))
                    {
                        lock (_thumbprints)
                        {
                            _thumbprints.ToList().ForEach(kvp => writer.WriteLine($"{kvp.Key},{kvp.Value}"));
                        }
                        writer.Flush();
                        writer.Close();
                    }
                }
            }
        }

        public bool TryGetAlias(string thumbprint, out string alias)
        {
            lock (_thumbprints)
            {
                return _thumbprints.TryGetValue(thumbprint, out alias);
            }
        }

        public void Set(string thumbprint, string alias)
        {
            lock (_thumbprints)
            {
                _thumbprints[thumbprint] = alias;
            }
        }

        public IEnumerable<string> GetMatchingThumbprints(IEnumerable<string> criteria)
        {
            lock (_thumbprints)
            {
                return _thumbprints
                    .Where(kvp => criteria.Any(e =>
                        kvp.Key.Equals(e, StringComparison.OrdinalIgnoreCase))
                        || criteria.Any(e => kvp.Value.Equals(e, StringComparison.OrdinalIgnoreCase)))
                    .Select(kvp => kvp.Key)
                    .ToArray();
            }
        }

        public bool Remove(string criteria)
        {
            lock (_thumbprints)
            {
                var thumbprint = _thumbprints
                    .Where(kvp =>
                        kvp.Key.Equals(criteria, StringComparison.InvariantCultureIgnoreCase)
                        || kvp.Value.Equals(criteria, StringComparison.InvariantCultureIgnoreCase))
                    .Select(kvp => kvp.Key)
                    .FirstOrDefault();
                return (!string.IsNullOrWhiteSpace(thumbprint))
                    && _thumbprints.Remove(thumbprint);
            }
        }

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            lock (_thumbprints)
            {
                foreach (var kvp in _thumbprints)
                {
                    yield return kvp;
                }
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            lock (_thumbprints)
            {
                foreach (var kvp in _thumbprints)
                {
                    yield return kvp;
                }
            }
        }
    }
}
