//! Partial resource comparison, not complete live preflight or authorization.
use crate::{ExecutionTime, VerifiedExecutionCandidate};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeMethod {
    Merge,
    Squash,
    Rebase,
}
impl MergeMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Squash => "squash",
            Self::Rebase => "rebase",
        }
    }
}

/// Trusted current method restrictions and revision, not full policy evaluation.
/// The coordinator must recheck policy/registry atomically before reservation.
pub struct CurrentMergePolicy {
    pub revision: u64,
    pub allowed_methods: Vec<MergeMethod>,
}
/// Required facts from the coordinator-selected metadata provider. Missing or
/// unavailable facts must be an error, never substituted from the request.
pub struct MergeObservation {
    pub repository_id: String,
    pub repository_label: String,
    pub pull_request_number: u32,
    pub head_sha: String,
    pub base_ref: String,
    /// Methods supported by the repository, not the agent's requested choice.
    pub allowed_methods: Vec<MergeMethod>,
}
pub struct MergeResourceRequest<'a> {
    repository_id: &'a str,
    pull_request_number: u32,
}
impl MergeResourceRequest<'_> {
    pub fn host(&self) -> &'static str {
        "github.com"
    }
    pub fn repository_id(&self) -> &str {
        self.repository_id
    }
    pub fn pull_request_number(&self) -> u32 {
        self.pull_request_number
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataError;
impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("resource metadata unavailable")
    }
}
impl std::error::Error for MetadataError {}

/// Trusted coordinator-selected adapter, never selected by an artifact.
/// Each call must obtain current facts, not reuse a prior approval snapshot.
/// Implementing this trait incorrectly can bypass resource comparison. The
/// type system does not establish provider integrity or remote atomicity.
pub trait MergeMetadataProvider {
    fn observe(
        &self,
        request: &MergeResourceRequest<'_>,
    ) -> Result<MergeObservation, MetadataError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceComparisonError;
impl fmt::Display for ResourceComparisonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("resource comparison rejected")
    }
}
impl std::error::Error for ResourceComparisonError {}

/// Candidate-bound, partial comparison only. NOT complete live preflight, a
/// reservation, or a dispatch permit. Disposable fixture qualification, the
/// no-retarget assumption, current API eligibility, trusted provider deployment
/// and final atomic registry/policy checks remain separate requirements.
pub struct ResourceComparedCandidate<'candidate, 'context> {
    candidate: &'candidate VerifiedExecutionCandidate<'context>,
    observation: MergeObservation,
    observed_at: ExecutionTime,
}
impl<'candidate, 'context> ResourceComparedCandidate<'candidate, 'context> {
    pub fn candidate(&self) -> &'candidate VerifiedExecutionCandidate<'context> {
        self.candidate
    }
    pub fn observation(&self) -> &MergeObservation {
        &self.observation
    }
    /// Local post-provider sample, not a remote snapshot freshness guarantee.
    pub fn observed_at(&self) -> &ExecutionTime {
        &self.observed_at
    }
}
impl fmt::Debug for ResourceComparedCandidate<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResourceComparedCandidate { .. }")
    }
}

/// Compare exact approved resource facts using a fresh provider invocation.
/// `clock` is trusted coordinator configuration and is sampled after the call.
/// Errors must leave the already claimed attempt consumed. Successful return
/// cannot prevent subsequent remote changes and does not authorize reservation.
pub fn compare_merge_resource<'candidate, 'context>(
    candidate: &'candidate VerifiedExecutionCandidate<'context>,
    policy: &CurrentMergePolicy,
    provider: &impl MergeMetadataProvider,
    clock: impl FnOnce() -> ExecutionTime,
) -> Result<ResourceComparedCandidate<'candidate, 'context>, ResourceComparisonError> {
    let context = candidate.context();
    let trust = context.trust();
    if policy.revision != trust.policy_revision {
        return Err(ResourceComparisonError);
    }
    let operation = candidate.operation();
    let resource = &operation["resource"];
    let constraints = &operation["constraints"];
    let method = constraints["merge_method"]
        .as_str()
        .ok_or(ResourceComparisonError)?;
    if !policy.allowed_methods.iter().any(|m| m.as_str() == method) {
        return Err(ResourceComparisonError);
    }
    let request = MergeResourceRequest {
        repository_id: resource["repository_id"]
            .as_str()
            .ok_or(ResourceComparisonError)?,
        pull_request_number: resource["pull_request_number"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(ResourceComparisonError)?,
    };
    let observation = provider
        .observe(&request)
        .map_err(|_| ResourceComparisonError)?;
    let time = clock();
    let approval = context.approved().approval().fields();
    let pending = context.pending();
    if time.session_id != trust.session_id
        || time.monotonic >= trust.approval_deadline
        || time.monotonic >= pending.deadline
        || time.wall_seconds
            < approval["issued_at"]
                .as_u64()
                .ok_or(ResourceComparisonError)?
        || time.wall_seconds
            >= approval["expires_at"]
                .as_u64()
                .ok_or(ResourceComparisonError)?
        || time.wall_seconds < pending.issued_at
        || time.wall_seconds >= pending.expires_at
        || time.wall_seconds < candidate.proof_issued_at()
        || time.wall_seconds >= candidate.proof_expires_at()
        || observation.repository_id != request.repository_id
        || observation.pull_request_number != request.pull_request_number
        || Some(observation.repository_label.as_str()) != approval["display"]["repository"].as_str()
        || Some(observation.head_sha.as_str()) != constraints["expected_head_sha"].as_str()
        || Some(observation.base_ref.as_str()) != constraints["base_ref"].as_str()
        || !observation
            .allowed_methods
            .iter()
            .any(|m| m.as_str() == method)
    {
        return Err(ResourceComparisonError);
    }
    Ok(ResourceComparedCandidate {
        candidate,
        observation,
        observed_at: time,
    })
}
