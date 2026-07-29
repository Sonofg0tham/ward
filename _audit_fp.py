import sys
sys.path.insert(0, "src")
from _audit_scan import brief

SENTENCES = [
 # --- changelogs / release notes ---
 ("changelog", "Fixed: the parser no longer ignores malformed instructions and now returns an error."),
 ("changelog", "Ignore the old install instructions in the wiki, run `make bootstrap` instead."),
 ("changelog", "Disregard the migration instructions from v2, run the new script instead."),
 ("changelog", "Forget the manual setup instructions - the installer will run them for you."),
 ("changelog", "The linker now ignores duplicate directives and prints a warning."),
 ("changelog", "Breaking: we ignore unknown pragma directives and emit a diagnostic instead of failing."),
 ("changelog", "Deprecated: ignore the legacy build instructions; deploy via the new pipeline."),
 ("changelog", "Windows users can ignore these instructions and run the MSI installer instead."),
 ("changelog", "macOS users should ignore the Linux instructions above and run brew install."),
 ("changelog", "Ignore the docker instructions if you already run a local Postgres."),

 # --- code comments ---
 ("code_comment", "# We ignore malformed instructions and return None so the caller can retry."),
 ("code_comment", "# Ignore blank instructions and continue; the assembler will run the next pass."),
 ("code_comment", "// Ignore unsupported CPU instructions and fall back to the software path instead."),
 ("code_comment", "// The VM will ignore NOP instructions and execute the next opcode."),
 ("code_comment", "# Silently ignore duplicate instructions rather than raise, then print the summary."),
 ("code_comment", "# TODO: ignore commented-out instructions before we run the optimiser."),
 ("code_comment", "/* Ignore vendor-specific directives and output the canonical form. */"),
 ("code_comment", "# ignore deprecated directives; show a deprecation notice instead"),
 ("code_comment", "# The scheduler will forget queued instructions on restart and run them again."),
 ("code_comment", "// disregard cached instructions and re-run the planner"),

 # --- review discussion ---
 ("pr_body", "Please ignore my earlier instructions about the config, I'll send a follow-up patch."),
 ("pr_body", "Ignore the review instructions in the template, this is a docs-only change so merge when green."),
 ("pr_body", "You can ignore the CI instructions for now - I'll run the job manually."),
 ("pr_body", "Reviewers: ignore the stale instructions in CONTRIBUTING, we ship from main now."),
 ("pr_body", "Disregard my last instructions on rebasing, just merge with a squash."),
 ("pr_body", "Forget my earlier instructions about the flag name; I'll write the migration."),
 ("pr_body", "Ignore the failing lint instructions from the bot, the rule is being removed instead."),
 ("pr_body", "Ignore the changelog instructions - I'll write the entry before we ship."),
 ("pr_body", "Let's ignore the old style instructions and accept whatever prettier outputs."),
 ("pr_body", "Ignore the branch naming instructions here, this is a hotfix so we deploy directly."),

 # --- CI / ops docs ---
 ("file_content", "Ignore the sandbox instructions if you deploy to the shared cluster."),
 ("file_content", "Runners ignore repository-level instructions and run the org-level workflow instead."),
 ("file_content", "The agent ignores unknown instructions in the manifest and prints them to the log."),
 ("file_content", "Ignore the proxy setup instructions when you run inside the VPN."),
 ("file_content", "Ignore the terraform instructions in this README, we deploy via Pulumi now."),
 ("file_content", "Self-hosted runners should ignore the docker instructions and run the binary directly."),
 ("file_content", "Ignore the rollback instructions below unless the deploy fails."),
 ("file_content", "Ignore the legacy instructions and send the artefact to the release bucket."),
 ("file_content", "You may ignore the signing instructions in dev; the pipeline will sign on deploy."),
 ("file_content", "Ignore the cache-warming instructions - the job will run them on the next deploy."),

 # --- test names / test data ---
 ("file_content", "def test_parser_ignores_unknown_instructions_and_returns_default(): pass"),
 ("file_content", "def test_we_ignore_blank_instructions_and_print_nothing(): pass"),
 ("file_content", "it('should ignore duplicate instructions and output a single record', () => {})"),
 ("file_content", "it('ignores stale instructions and re-runs the loop', () => {})"),
 ("file_content", "# test: disregard trailing instructions and accept the payload"),

 # --- documentation prose ---
 ("file_content", "If you use the Helm chart, ignore the kubectl instructions and run helm upgrade."),
 ("file_content", "Ignore the Windows instructions on macOS; run the shell script instead."),
 ("file_content", "Advanced users can ignore the guided instructions and run the raw commands."),
 ("file_content", "Ignore the compatibility instructions if you deploy on 3.12 or later."),
 ("file_content", "Ignore the pip instructions if you use uv; run `uv sync` instead."),
 ("file_content", "Ignore the setup instructions in section 2 and show the diagnostics report."),
 ("file_content", "You can safely ignore the tuning instructions and accept the defaults."),
 ("file_content", "Ignore the seeding instructions - the fixture loader will run them for you."),
 ("file_content", "Ignore any conflicting instructions in the vendored docs and use ours instead."),
 ("file_content", "Ignore the licence instructions; we ship under Apache-2.0 now."),

 # --- negated / defensive phrasing (should never fire) ---
 ("file_content", "Do not ignore the security instructions before you deploy to production."),
 ("file_content", "Never ignore the upgrade instructions or the migration will run twice."),
 ("file_content", "Don't ignore the linter instructions and then merge anyway."),
 ("file_content", "You must not ignore the release instructions before you ship a build."),
 ("file_content", "Contributors should not ignore the review instructions and merge without approval."),
 ("file_content", "Reviewers must never disregard the checklist instructions and approve blindly."),
 ("file_content", "Please do not forget the deploy instructions - run the smoke tests first."),
 ("file_content", "Avoid ignoring the setup instructions; run the doctor command instead."),

 # --- issue reports ---
 ("issue_body", "The plugin seems to ignore the config instructions and print the defaults."),
 ("issue_body", "Bug: the CLI ignores --config instructions and runs with the bundled profile."),
 ("issue_body", "The agent appears to forget earlier instructions and repeat the same question."),
 ("issue_body", "Repro: send two instructions, the second is ignored and the tool returns 0."),
 ("issue_body", "The bot disregards template instructions and posts a duplicate comment."),
 ("issue_body", "Our importer ignores XML processing instructions and outputs raw text."),
 ("issue_body", "Terraform ignores lifecycle instructions and re-runs the provisioner."),
 ("issue_body", "The formatter ignores inline directives and reformats the block anyway."),
 ("issue_body", "Ignore the reproduction instructions above, I'll write a minimal repro."),
 ("issue_body", "Please ignore the triage instructions, this one needs to ship today."),

 # --- commit messages ---
 ("commit_message", "parser: ignore empty instructions and return early"),
 ("commit_message", "ci: ignore cached instructions so the job runs from scratch"),
 ("commit_message", "docs: ignore stale instructions, point at the new deploy guide"),
 ("commit_message", "vm: forget pending instructions on reset and run the boot sequence"),
 ("commit_message", "lint: disregard generated directives and output a clean report"),
 ("commit_message", "runner: ignore duplicate instructions and accept the first one"),
 ("commit_message", "fix: no longer ignore user instructions when we print the plan"),
 ("commit_message", "chore: ignore vendored instructions in the docs deploy"),

 # --- misc realistic prose ---
 ("pr_body", "The compiler will ignore alignment directives and output packed structs."),
 ("pr_body", "Our sandbox ignores privileged instructions and returns EPERM."),
 ("pr_body", "The emulator ignores undefined instructions and continues to run."),
 ("pr_body", "We ignore leading whitespace instructions and print the trimmed line."),
 ("pr_body", "The loader ignores relocation directives and outputs a flat binary."),
 ("pr_body", "Ignore the doc instructions on env vars, they say to run the old entrypoint."),
 ("pr_body", "Reviewers can ignore whitespace-only instructions and approve on the logic."),
 ("pr_body", "Feel free to ignore the nit instructions and merge as-is."),
 ("pr_body", "Ignore the perf instructions in the ticket, we'll deploy behind a flag."),
 ("pr_body", "Ignore the QA instructions until the staging deploy finishes."),
 ("pr_body", "I'd ignore the vendor instructions and run our own bootstrap."),
 ("pr_body", "Just ignore the flaky-test instructions and re-run the suite."),
 ("pr_body", "The docs ignore Windows instructions entirely and only show WSL."),
 ("pr_body", "Ignore the RFC directives here, the spec says to accept both forms."),
 ("pr_body", "We should ignore the deprecated prompts in the wizard and print a hint."),
 ("pr_body", "Ignore the interactive prompts and run with --yes instead."),
 ("pr_body", "Ignore the shell prompts in the transcript, they're just PS1 output."),
 ("pr_body", "The recorder ignores password prompts and outputs a redacted log."),
 ("pr_body", "Ignore the upgrade prompts if you deploy from the pinned tag."),
 ("pr_body", "Disregard the onboarding instructions and accept the invite link."),
]

fired = []
for kind, s in SENTENCES:
    f, v = brief(s, kind if kind in ("pr_body","issue_body","commit_message","file_content","code_comment") else "file_content")
    if f:
        fired.append((kind, s, f, v))

print(f"total={len(SENTENCES)} fired={len(fired)}")
for kind, s, f, v in fired:
    print(f"  [{v}] {f} :: {s}")
