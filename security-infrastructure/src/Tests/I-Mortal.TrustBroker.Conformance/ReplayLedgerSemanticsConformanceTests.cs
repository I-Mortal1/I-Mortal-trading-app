using System.Collections.Concurrent;
using IMortal.TrustBroker.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ReplayLedgerSemanticsConformanceTests
{
    private static readonly DateTimeOffset Now =
        new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private sealed class ReferenceReplayLedger
    {
        private readonly object _gate = new();

        private readonly HashSet<string> _requestIds =
            new(StringComparer.Ordinal);

        private readonly HashSet<string> _nonces =
            new(StringComparer.Ordinal);

        public ReplayConsumeResult TryConsume(
            AuthorizationRequest? request,
            DateTimeOffset now)
        {
            var validation =
                AuthorizationRequestValidator.Validate(
                    request,
                    now);

            if (!validation.Success)
            {
                return new ReplayConsumeResult(
                    false,
                    validation.ErrorCode);
            }

            // Validate() succeeded, so request cannot be null here.
            var validated = request!;

            lock (_gate)
            {
                if (_requestIds.Contains(validated.RequestId))
                {
                    return new ReplayConsumeResult(
                        false,
                        "REQUEST_ID_REPLAYED");
                }

                if (_nonces.Contains(validated.Nonce))
                {
                    return new ReplayConsumeResult(
                        false,
                        "NONCE_REPLAYED");
                }

                // Both identifiers are committed under the same lock.
                // No partially-consumed state is externally observable.
                _requestIds.Add(validated.RequestId);
                _nonces.Add(validated.Nonce);

                return new ReplayConsumeResult(
                    true,
                    null);
            }
        }
    }

    private sealed record ReplayConsumeResult(
        bool Success,
        string? ErrorCode);

    private static AuthorizationRequest Request(
        string requestId = "request-001",
        string nonce = "nonce-001",
        DateTimeOffset? expiresAt = null) =>
        new(
            RequestId: requestId,
            Operation: "sign",
            DeviceIdentity: "device-001",
            Nonce: nonce,
            ExpiresAt: expiresAt ?? Now.AddMinutes(5),
            PolicyVersion: "policy-v1",
            AuthorizationState: "requested");

    [TestMethod]
    public void First_Consumption_Succeeds()
    {
        var ledger = new ReferenceReplayLedger();

        var result =
            ledger.TryConsume(
                Request(),
                Now);

        Assert.IsTrue(result.Success);
        Assert.IsNull(result.ErrorCode);
    }

    [TestMethod]
    public void Exact_Replay_Is_Rejected()
    {
        var ledger = new ReferenceReplayLedger();
        var request = Request();

        var first = ledger.TryConsume(request, Now);
        var second = ledger.TryConsume(request, Now);

        Assert.IsTrue(first.Success);
        Assert.IsFalse(second.Success);
        Assert.AreEqual(
            "REQUEST_ID_REPLAYED",
            second.ErrorCode);
    }

    [TestMethod]
    public void RequestId_Reuse_With_Different_Nonce_Is_Rejected()
    {
        var ledger = new ReferenceReplayLedger();

        var first =
            ledger.TryConsume(
                Request(
                    requestId: "request-A",
                    nonce: "nonce-A"),
                Now);

        var second =
            ledger.TryConsume(
                Request(
                    requestId: "request-A",
                    nonce: "nonce-B"),
                Now);

        Assert.IsTrue(first.Success);
        Assert.IsFalse(second.Success);
        Assert.AreEqual(
            "REQUEST_ID_REPLAYED",
            second.ErrorCode);
    }

    [TestMethod]
    public void Nonce_Reuse_With_Different_RequestId_Is_Rejected()
    {
        var ledger = new ReferenceReplayLedger();

        var first =
            ledger.TryConsume(
                Request(
                    requestId: "request-A",
                    nonce: "nonce-A"),
                Now);

        var second =
            ledger.TryConsume(
                Request(
                    requestId: "request-B",
                    nonce: "nonce-A"),
                Now);

        Assert.IsTrue(first.Success);
        Assert.IsFalse(second.Success);
        Assert.AreEqual(
            "NONCE_REPLAYED",
            second.ErrorCode);
    }

    [TestMethod]
    public void Rejected_Nonce_Replay_Does_Not_Consume_New_RequestId()
    {
        var ledger = new ReferenceReplayLedger();

        Assert.IsTrue(
            ledger.TryConsume(
                Request("request-A", "nonce-A"),
                Now).Success);

        var rejected =
            ledger.TryConsume(
                Request("request-B", "nonce-A"),
                Now);

        Assert.IsFalse(rejected.Success);
        Assert.AreEqual(
            "NONCE_REPLAYED",
            rejected.ErrorCode);

        var retry =
            ledger.TryConsume(
                Request("request-B", "nonce-B"),
                Now);

        Assert.IsTrue(retry.Success);
    }

    [TestMethod]
    public void Invalid_Request_Does_Not_Consume_Replay_State()
    {
        var ledger = new ReferenceReplayLedger();

        var invalid =
            Request(
                requestId: "request-A",
                nonce: "nonce-A") with
            {
                DeviceIdentity = ""
            };

        var rejected =
            ledger.TryConsume(
                invalid,
                Now);

        Assert.IsFalse(rejected.Success);
        Assert.AreEqual(
            "DEVICE_IDENTITY_REQUIRED",
            rejected.ErrorCode);

        var corrected =
            ledger.TryConsume(
                Request(
                    requestId: "request-A",
                    nonce: "nonce-A"),
                Now);

        Assert.IsTrue(corrected.Success);
    }

    [TestMethod]
    public void Expired_Request_Does_Not_Consume_Replay_State()
    {
        var ledger = new ReferenceReplayLedger();

        var expired =
            ledger.TryConsume(
                Request(
                    requestId: "request-A",
                    nonce: "nonce-A",
                    expiresAt: Now),
                Now);

        Assert.IsFalse(expired.Success);
        Assert.AreEqual(
            "REQUEST_EXPIRED",
            expired.ErrorCode);

        var fresh =
            ledger.TryConsume(
                Request(
                    requestId: "request-A",
                    nonce: "nonce-A",
                    expiresAt: Now.AddMinutes(5)),
                Now);

        Assert.IsTrue(fresh.Success);
    }

    [TestMethod]
    public async Task Concurrent_Exact_Replay_Has_Exactly_One_Winner()
    {
        var ledger = new ReferenceReplayLedger();
        var request = Request();

        const int attempts = 64;

        var start =
            new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously);

        var tasks =
            Enumerable.Range(0, attempts)
                .Select(
                    async _ =>
                    {
                        await start.Task;

                        return ledger.TryConsume(
                            request,
                            Now);
                    })
                .ToArray();

        start.SetResult(true);

        var results =
            await Task.WhenAll(tasks);

        Assert.AreEqual(
            1,
            results.Count(result => result.Success));

        Assert.AreEqual(
            attempts - 1,
            results.Count(
                result =>
                    !result.Success &&
                    result.ErrorCode ==
                        "REQUEST_ID_REPLAYED"));
    }

    [TestMethod]
    public async Task Concurrent_Nonce_Reuse_Has_Exactly_One_Winner()
    {
        var ledger = new ReferenceReplayLedger();

        const int attempts = 64;

        var start =
            new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously);

        var tasks =
            Enumerable.Range(0, attempts)
                .Select(
                    async index =>
                    {
                        await start.Task;

                        return ledger.TryConsume(
                            Request(
                                requestId:
                                    $"request-{index:D3}",
                                nonce:
                                    "shared-nonce"),
                            Now);
                    })
                .ToArray();

        start.SetResult(true);

        var results =
            await Task.WhenAll(tasks);

        Assert.AreEqual(
            1,
            results.Count(result => result.Success));

        Assert.AreEqual(
            attempts - 1,
            results.Count(
                result =>
                    !result.Success &&
                    result.ErrorCode ==
                        "NONCE_REPLAYED"));
    }
}
