# Multi-Agent CTF Orchestration

> Host-neutral guidance for coordinating CTF challenge skills, optional agent personas, and evidence.
> Related: [Repository guide](../AGENTS.md) | [CTF safety and scope rules](../rules/ctf-safety-framing-rules.md)

## Security context

Before analyzing a challenge, record the authorization, target, objective, environment, and limits. Pass this context along when handing work to another agent. This is a communication format; it does not grant permission or enforce isolation.

```yaml
security_context:
  mode: ctf | lab | audit
  authorization: confirmed
  target:
    type: ctf_challenge | educational_lab
    scope:
      - challenge files or organizer-provided endpoint
  environment:
    isolated: true | false | unknown
  objective: vulnerability verification and/or flag retrieval
  constraints:
    - no production targets
    - no persistence or unrelated data access
```

Use `unknown` when isolation has not been verified. Do not describe an environment as isolated without evidence.

## Task envelope

Give each handoff a narrow objective with the relevant assets and limits:

```yaml
task_envelope:
  task_id: challenge-identifier
  category: web | pwn | crypto | reverse | forensics | osint | malware | misc | ai-ml
  mode: blitz | deep
  target_assets:
    - path or organizer-provided challenge endpoint
  objective: one concrete task
  constraints:
    timeout_seconds: 60
    preserve_original_files: true
```

Use the current host's documented skill and agent mechanisms. Skill names in this package are identifiers such as `ctf-web` and `ctf-pwn`; hosts may expose them through different commands or interfaces. If the host cannot delegate, continue in the current session.

## Delegation

- Keep delegation shallow: a controller may hand one bounded task to a specialist. The specialist should return findings rather than create another delegation chain.
- Include the security context, task envelope, relevant evidence, and expected output in each handoff.
- Keep challenge artifacts local unless sharing them is authorized and permitted by the host.
- If work crosses categories, return findings to the controller and load the next matching skill through the host's mechanism.
- Follow the host's permission controls. A refusal or unavailable capability is not a reason to disguise the task or route it through another tool or agent.

## Evidence ledger

Keep observations separate from hypotheses and invalidated ideas:

```yaml
evidence_ledger:
  confirmed_facts:
    - observation with source path or command output
  hypotheses:
    - idea awaiting verification
  invalidated_hypotheses:
    - idea and the evidence that ruled it out
  current_objective: next bounded verification step
```

Record exact file paths, relevant versions, and fresh outputs. Do not report a flag as verified unless it appears in direct challenge output or a platform response and matches the expected format.

## Suggested flow

```text
authorize and scope -> inspect challenge -> choose category skill
         -> verify one hypothesis -> record evidence -> pivot or finish
```

For blitz mode, stop after directly verifying the flag and keep the report concise. For deep mode, document the root cause and provide a reproducible write-up when requested.
