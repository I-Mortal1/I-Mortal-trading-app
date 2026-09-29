using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Production wall-clock implementation of ISecurityClock.
///
/// This type provides UTC time only.
///
/// Reading the clock grants no authorization or authority.
///
/// In particular, this type does not:
///
/// - approve workloads,
/// - verify project integrity,
/// - verify challenges,
/// - consume replay state,
/// - activate confidential computing,
/// - authorize production,
/// - grant signing authority,
/// - grant developer source authority,
/// - grant source-mutation authority,
/// - grant I-Mortal Security Umbrella root authority.
///
/// Security-sensitive consumers remain responsible for fail-closed
/// validation of timestamps, freshness, expiration, replay state,
/// challenge binding, and every independent authorization prerequisite.
///
/// This implementation contains no mutable authorization state.
/// </summary>
public sealed class SystemSecurityClock : ISecurityClock
{
    public DateTimeOffset UtcNow =>
        DateTimeOffset.UtcNow;
}