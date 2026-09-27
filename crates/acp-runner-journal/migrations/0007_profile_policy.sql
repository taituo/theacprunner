-- acp-runner journal schema v7: who may lease a credential profile.
--
-- A profile is leased only to runs in one of `allowed_namespaces` ('*' = any namespace) and,
-- when `allowed_classes` is not empty, only through one of those runner classes.
-- Default deny: existing profiles have no namespaces until an administrator grants them
-- (`acp-runnerctl auth allow <profile> --namespace <ns>`).
ALTER TABLE credential_profiles
    ADD COLUMN allowed_namespaces text[] NOT NULL DEFAULT '{}',
    ADD COLUMN allowed_classes    text[] NOT NULL DEFAULT '{}';
