#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;

namespace TrafficFilter
{
    public enum FilterActionKind
    {
        ALLOW,
        DROP
    }

    public sealed class Administrator
    {
        public int Id { get; }
        public string Name { get; }
        public int AccessLevel { get; }

        public Administrator(int id, string name, int accessLevel)
        {
            Id = id;
            Name = name ?? throw new ArgumentNullException(nameof(name));
            AccessLevel = accessLevel;
        }

        public bool ConfigurePolicy(FilterPolicy policy, FilteringSubsystem subsystem)
        {
            if (policy is null) throw new ArgumentNullException(nameof(policy));
            if (subsystem is null) throw new ArgumentNullException(nameof(subsystem));

            return subsystem.AssignPolicy(policy);
        }
    }

    public sealed class NetworkPacket
    {
        public int Id { get; }
        public string SourceAddress { get; }
        public string DestinationAddress { get; }
        public string Protocol { get; }
        public int Size { get; }

        public NetworkPacket(
            int id,
            string sourceAddress,
            string destinationAddress,
            string protocol,
            int size)
        {
            if (size < 0)
                throw new ArgumentOutOfRangeException(nameof(size));

            Id = id;
            SourceAddress = sourceAddress ?? throw new ArgumentNullException(nameof(sourceAddress));
            DestinationAddress = destinationAddress ?? throw new ArgumentNullException(nameof(destinationAddress));
            Protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
            Size = size;
        }
    }

    // Поток трафика, содержащий сетевые пакеты.
    public sealed class TrafficFlow
    {
        private readonly List<NetworkPacket> _packets = new();

        public int Id { get; }
        public string SourceAddress { get; }
        public string DestinationAddress { get; }
        public string Protocol { get; }
        public IReadOnlyList<NetworkPacket> Packets => _packets.AsReadOnly();

        public TrafficFlow(int id, string sourceAddress, string destinationAddress, string protocol)
        {
            Id = id;
            SourceAddress = sourceAddress ?? throw new ArgumentNullException(nameof(sourceAddress));
            DestinationAddress = destinationAddress ?? throw new ArgumentNullException(nameof(destinationAddress));
            Protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
        }

        public void AddPacket(NetworkPacket packet)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));
            _packets.Add(packet);
        }
    }

    public sealed class FilterRule
    {
        public int Id { get; }
        public string Condition { get; }
        public int Priority { get; }
        public FilterActionKind Action { get; }

        public FilterRule(int id, string condition, int priority, FilterActionKind action)
        {
            Id = id;
            Condition = condition ?? throw new ArgumentNullException(nameof(condition));
            Priority = priority;
            Action = action;
        }

        public bool Matches(NetworkPacket packet)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));

            if (Condition.Trim() == "*")
                return true;

            string[] terms = Condition.Split(
                '&',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (terms.Length == 0)
                return false;

            foreach (string term in terms)
            {
                string[] pair = term.Split('=', 2, StringSplitOptions.TrimEntries);
                if (pair.Length != 2)
                    return false;

                string key = pair[0].ToLowerInvariant();
                string expected = pair[1];

                string? actual = key switch
                {
                    "protocol" => packet.Protocol,
                    "source" => packet.SourceAddress,
                    "destination" => packet.DestinationAddress,
                    _ => null
                };

                if (actual is null ||
                    !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }

        public FilterActionKind GetAction() => Action;
    }

    public sealed class FilterPolicy
    {
        private readonly List<FilterRule> _rules;
        private readonly HashSet<string> _requiredProtocols;

        public int Id { get; }
        public string Name { get; }
        public bool IsEnabled { get; private set; }
        public FilterActionKind DefaultAction { get; }
        public IReadOnlyList<FilterRule> Rules => _rules.AsReadOnly();

        public FilterPolicy(
            int id,
            string name,
            bool isEnabled,
            FilterActionKind defaultAction,
            IEnumerable<FilterRule> rules,
            IEnumerable<string>? requiredProtocols = null)
        {
            Id = id;
            Name = name ?? throw new ArgumentNullException(nameof(name));
            IsEnabled = isEnabled;
            DefaultAction = defaultAction;

            if (rules is null) throw new ArgumentNullException(nameof(rules));

            _rules = rules.ToList();

            if (_rules.Count == 0)
                throw new ArgumentException(
                    "Политика должна содержать хотя бы одно правило.",
                    nameof(rules));

            if (_rules.Any(rule => rule is null))
                throw new ArgumentException("Список правил не должен содержать null.", nameof(rules));

            _requiredProtocols = new HashSet<string>(
                requiredProtocols ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);
        }

        public IReadOnlyList<FilterRule> GetRulesOrdered()
        {
            return _rules.OrderBy(rule => rule.Priority).ToArray();
        }

        public IEnumerable<string> GetRequiredProtocols()
        {
            return _requiredProtocols;
        }

        public FilterActionKind GetDefaultAction()
        {
            return DefaultAction;
        }

        public void Enable() => IsEnabled = true;
        public void Disable() => IsEnabled = false;
    }

    public sealed class FilteringSubsystem
    {
        private readonly HashSet<string> _supportedProtocols;

        public int Id { get; }
        public string Name { get; }
        public string Purpose { get; }
        public bool IsEnabled { get; private set; }

        public FilterPolicy? ActivePolicy { get; private set; }

        public FilteringSubsystem(
            int id,
            string name,
            string purpose,
            bool isEnabled,
            IEnumerable<string> supportedProtocols)
        {
            Id = id;
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Purpose = purpose ?? throw new ArgumentNullException(nameof(purpose));
            IsEnabled = isEnabled;

            if (supportedProtocols is null)
                throw new ArgumentNullException(nameof(supportedProtocols));

            _supportedProtocols = new HashSet<string>(
                supportedProtocols,
                StringComparer.OrdinalIgnoreCase);
        }

        public bool AssignPolicy(FilterPolicy policy)
        {
            if (policy is null) throw new ArgumentNullException(nameof(policy));

            if (!IsCompatible(policy))
                return false;

            ActivePolicy = policy;
            return true;
        }

        public FilterPolicy GetActivePolicy()
        {
            if (!IsEnabled)
                throw new InvalidOperationException("Подсистема фильтрации отключена.");

            if (ActivePolicy is null)
                throw new InvalidOperationException("Подсистеме не назначена политика.");

            if (!ActivePolicy.IsEnabled)
                throw new InvalidOperationException("Назначенная политика отключена.");

            return ActivePolicy;
        }

        private bool IsCompatible(FilterPolicy policy)
        {
            if (!IsEnabled || !policy.IsEnabled)
                return false;

            foreach (string protocol in policy.GetRequiredProtocols())
            {
                if (!SupportsProtocol(protocol))
                    return false;
            }

            return true;
        }

        private bool SupportsProtocol(string protocol)
        {
            return _supportedProtocols.Contains(protocol);
        }

        public void Enable() => IsEnabled = true;
        public void Disable() => IsEnabled = false;
    }

    public interface IPacketAction
    {
        FilterActionKind Execute(NetworkPacket packet);
    }

    public sealed class AllowAction : IPacketAction
    {
        public FilterActionKind Execute(NetworkPacket packet)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));
            return FilterActionKind.ALLOW;
        }
    }

    public sealed class DropAction : IPacketAction
    {
        public FilterActionKind Execute(NetworkPacket packet)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));
            return FilterActionKind.DROP;
        }
    }

    public sealed class FilterResult
    {
        public DateTime ProcessedAt { get; }
        public FilterActionKind Decision { get; }
        public string Reason { get; }
        public NetworkPacket Packet { get; }
        public FilteringSubsystem Subsystem { get; }

        public FilterRule? Rule { get; }

        public FilterResult(
            DateTime processedAt,
            FilterActionKind decision,
            string reason,
            NetworkPacket packet,
            FilteringSubsystem subsystem,
            FilterRule? rule)
        {
            ProcessedAt = processedAt;
            Decision = decision;
            Reason = reason ?? throw new ArgumentNullException(nameof(reason));
            Packet = packet ?? throw new ArgumentNullException(nameof(packet));
            Subsystem = subsystem ?? throw new ArgumentNullException(nameof(subsystem));
            Rule = rule;
        }

        public string ToLogDescription()
        {
            string ruleText = Rule is null
                ? "правило не совпало"
                : $"правило #{Rule.Id}";

            return $"Пакет #{Packet.Id}: {Decision}; {ruleText}; основание: {Reason}";
        }
    }

    public sealed class LogEntry
    {
        public DateTime EventTime { get; }
        public string EventType { get; }
        public string Description { get; }

        public LogEntry(DateTime eventTime, string eventType, string description)
        {
            EventTime = eventTime;
            EventType = eventType ?? throw new ArgumentNullException(nameof(eventType));
            Description = description ?? throw new ArgumentNullException(nameof(description));
        }
    }

    public sealed class FilterJournal
    {
        private readonly List<LogEntry> _entries = new();
        private readonly List<FilterResult> _results = new();

        public IReadOnlyList<LogEntry> Entries => _entries.AsReadOnly();
        public IReadOnlyList<FilterResult> Results => _results.AsReadOnly();

        public FilterResult RecordResult(
            NetworkPacket packet,
            FilteringSubsystem subsystem,
            FilterRule? rule,
            FilterActionKind decision,
            string reason)
        {
            DateTime timestamp = DateTime.UtcNow;

            var result = new FilterResult(
                timestamp, decision, reason, packet, subsystem, rule);

            _results.Add(result);

            var entry = new LogEntry(
                timestamp,
                decision.ToString(),
                result.ToLogDescription());

            _entries.Add(entry);

            return result;
        }

        public IReadOnlyList<LogEntry> Find(string criteria)
        {
            if (string.IsNullOrWhiteSpace(criteria))
                return Entries;

            return _entries
                .Where(entry =>
                    entry.Description.Contains(criteria, StringComparison.OrdinalIgnoreCase) ||
                    entry.EventType.Contains(criteria, StringComparison.OrdinalIgnoreCase))
                .ToList()
                .AsReadOnly();
        }
    }

    // Сервис фильтрации использует журнал и две стратегии обработки пакетов.
    public sealed class PacketFilteringService
    {
        private readonly FilterJournal _journal;
        private readonly IPacketAction _allowAction;
        private readonly IPacketAction _dropAction;

        public PacketFilteringService(
            FilterJournal journal,
            IPacketAction allowAction,
            IPacketAction dropAction)
        {
            _journal = journal ?? throw new ArgumentNullException(nameof(journal));
            _allowAction = allowAction ?? throw new ArgumentNullException(nameof(allowAction));
            _dropAction = dropAction ?? throw new ArgumentNullException(nameof(dropAction));
        }

        public FilterResult FilterPacket(
            NetworkPacket packet,
            FilteringSubsystem subsystem)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));
            if (subsystem is null) throw new ArgumentNullException(nameof(subsystem));

            FilterPolicy policy;

            try
            {
                policy = subsystem.GetActivePolicy();
            }
            catch (InvalidOperationException exception)
            {
                return _journal.RecordResult(
                    packet,
                    subsystem,
                    null,
                    FilterActionKind.DROP,
                    exception.Message);
            }

            FilterRule? matchedRule = null;

            // Проверяем правила по возрастанию Priority.
            foreach (FilterRule rule in policy.GetRulesOrdered())
            {
                if (rule.Matches(packet))
                {
                    matchedRule = rule;
                    break;
                }
            }

            FilterActionKind requestedDecision = matchedRule is not null
                ? matchedRule.GetAction()
                : policy.GetDefaultAction();

            string reason = matchedRule is not null
                ? $"Совпало правило #{matchedRule.Id} с приоритетом {matchedRule.Priority}"
                : "Совпадающее правило не найдено; применено действие по умолчанию";

            IPacketAction action = requestedDecision == FilterActionKind.ALLOW
                ? _allowAction
                : _dropAction;

            FilterActionKind actualDecision = action.Execute(packet);

            return _journal.RecordResult(
                packet,
                subsystem,
                matchedRule,
                actualDecision,
                reason);
        }
    }
}
