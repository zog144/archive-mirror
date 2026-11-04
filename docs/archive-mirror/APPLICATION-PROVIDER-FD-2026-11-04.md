# Archive-mirror application-owned credential FD adapter — source candidate

**Status: disabled by default; native acceptance NO-GO.** This source contract
implements the archive application's side of the protected Unix credential
handoff described in [host-install PR #23](https://github.com/zog144/host-install/pull/23)
and [root-control PR #31](https://github.com/zog144/root-control/pull/31).
It does not add a listener, credential authority, live installation, or trust
in a caller-supplied installation policy.

## Ownership and receive boundary

`zog.archive_mirror.provider_fd_adapter.receive_verified_fd` accepts
a single connected `AF_UNIX/SOCK_SEQPACKET` socket **only when explicitly
enabled by its selected caller**; the function defaults to denied. The archive
application supplies the locally selected, exact
`zog-archive-provider-protected-ipc-policy-v1` object, sender PID/UID/GID,
canonical authorization/request/secret-free delivery metadata and the
protected owner's already-durable `installing` operation state. These are
**not** chosen by the sender's JSON frame.

The app checks its own effective UID/GID, PID and supplementary group set,
exact Host/installation/STATE/registry, scope, credential/authority revisions,
purpose `archive-mirror-upstream-fetch`, selected application source digest,
boot and InvocationID fields, and kernel sender `SO_PEERCRED`. The selected
sender identity must originate from root-control's independent runtime grant
and original installation operation; synthetic tests use a non-root sender
solely to exercise the real kernel peer check.

The sole accepted frame is exact canonical
`zog-archive-provider-fd-handoff-v1`, matching the stricter host-install
PR #23 control schema. Its `action="deliver"` identifies the *FD dispatch*,
not the canonical credential request action (which may be `renew`).
It contains no provider secret, token, issuer key or file path.

Only **one** `SCM_RIGHTS` descriptor is accepted, with bounded ancillary
buffer, no truncation, `MSG_CMSG_CLOEXEC`, and automatic closure after
success or failure. The descriptor must be a genuinely anonymous sealed Linux
memfd (`F_SEAL_WRITE|SHRINK|GROW|SEAL`), ordinary regular-file mode,
zero hardlinks, bounded 1–16384 bytes and `FD_CLOEXEC`; named disk files,
unsealed memfds, symlinks, extra FDs and unknown control messages fail closed.

## Secret-free protocol projection and installation

The protected native receiver verifies the **original** signed canonical
HTTPS delivery, current signed authorization and durable replay/nonce ledger
**before** transferring a secret. The archive application receives only the
`zog-archive-provider-verified-delivery-metadata-v1` projection containing
nonsecret canonical IDs, revisions, purpose, timestamps and expiry. That
projection is not itself a signed credential authorization; trusting it without
the separately protected receiving owner would be unsafe.

`provider_credentials.install_verified_fd` does not accept `secret` in a
delivery dictionary. It checks canonical request and nonsecret delivery
fields, revalidates the sealed FD, then streams from `os.pread` into the
application's existing `0700/0600` protected persistent store. It uses
the same v2 installation record, atomic pending marker, revision/chained
renewal, role-lease check, replay-byte comparison and persistent signed
revocation tombstone as the established legacy in-memory path. An eventual
native FD-only application can set
`ARCHIVE_MIRROR_CREDENTIAL_FD_ONLY=1` to deny that legacy path; this
candidate **does not set or deploy** that environment variable.

The result is
`zog-archive-provider-application-fd-result-v1` with
`status="installed-unattested"` and `native_accepted=false`. It never
constitutes a signed receipt, installed-byte attestation or redelivery
permission. Host-install's independently pinned Ed25519 attester and
monotonic fresh-nonce acknowledgment are mandatory after this stage.
On a lost ACK, root-control must reconcile the **original** handoff and
protected installed bytes without sending the secret FD again.

Signed revocations are handled separately by the existing
`apply_signed_revocation` interface **after** the protected owner commits
the common durable deny. They require no provider FD and do not delete
retained archives, source pins, catalogue or download state.

## Source tests and native hold

`tests/test_provider_fd_adapter.py` tests a disposable separate-process
sender using real Linux `AF_UNIX`, `SO_PEERCRED`, sealed memfd and
`SCM_RIGHTS` with **synthetic credentials only**. Other tests reject disabled
operation, wrong peer/app identity, wrong purpose/Host/STATE/scope/revision,
non-installing/revoked fences, unsealed/extra/malformed FDs, stale delivery
metadata and blocked revocation. Existing provider tests cover the
store/replay/rotation/withdrawal lifecycle.

Native activation remains blocked pending root-control and host-install
selection of protected application identity, real root sender PID/starttime,
socket inode/owner, cgroup/InvocationID, selected source and STATE identity,
original durable sending ledger, independently pinned authority and
attester, signed installed-byte receipt, reboot recovery and same/other-UID
negative acceptance. No tool in this source pass accesses production
credentials or starts a service.
