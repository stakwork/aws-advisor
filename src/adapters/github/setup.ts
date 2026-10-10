/**
 * The permissions the read-only GitHub App asks for, as GitHub's "Register new GitHub App" form names them, each with
 * the sections of the collection it opens. Every one is Read-only; none is needed beyond these. Shown in Settings next
 * to the form, and used to name the missing permission when a section is refused.
 */
export const GITHUB_APP_PERMISSIONS: { scope: "organization" | "repository"; permission: string; access: "Read-only"; sections: string[] }[] = [
  { scope: "organization", permission: "Members", access: "Read-only", sections: ["members", "members_2fa", "outside_collaborators", "outside_collaborators_2fa", "invitations", "teams"] },
  { scope: "organization", permission: "Administration", access: "Read-only", sections: ["audit_log", "credential_authorizations", "installations", "billing_usage"] },
  { scope: "organization", permission: "Personal access tokens", access: "Read-only", sections: ["personal_access_tokens"] },
  { scope: "organization", permission: "Personal access token requests", access: "Read-only", sections: ["personal_access_token_requests"] },
  { scope: "organization", permission: "Secrets", access: "Read-only", sections: ["org_secrets"] },
  { scope: "organization", permission: "Webhooks", access: "Read-only", sections: ["org_hooks"] },
  { scope: "organization", permission: "GitHub Copilot Business", access: "Read-only", sections: ["copilot"] },
  { scope: "repository", permission: "Metadata", access: "Read-only", sections: ["repos"] },
  { scope: "repository", permission: "Administration", access: "Read-only", sections: ["collaborators", "deploy_keys"] },
  { scope: "repository", permission: "Secrets", access: "Read-only", sections: ["repo_secrets"] },
  { scope: "repository", permission: "Environments", access: "Read-only", sections: ["repo_secrets"] },
  { scope: "repository", permission: "Dependabot secrets", access: "Read-only", sections: ["org_secrets"] },
  { scope: "repository", permission: "Webhooks", access: "Read-only", sections: ["repo_hooks"] },
];
