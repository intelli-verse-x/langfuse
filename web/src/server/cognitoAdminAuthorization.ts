import { createHash } from "node:crypto";

export type CognitoAuthorizationOutcome =
  | "allow"
  | "deny_invalid_profile"
  | "deny_missing_subject"
  | "deny_wrong_issuer"
  | "deny_wrong_audience"
  | "deny_unverified_email"
  | "deny_missing_groups"
  | "deny_unapproved_group";

export type CognitoAuthorizationDecision = {
  allowed: boolean;
  outcome: CognitoAuthorizationOutcome;
  subjectRef: string;
  approvedGroups: string[];
};

type CognitoProfile = {
  sub?: unknown;
  iss?: unknown;
  aud?: unknown;
  email_verified?: unknown;
  "cognito:groups"?: unknown;
};

export function parseCognitoAllowedGroups(value: string | undefined): string[] {
  return [
    ...new Set(
      (value ?? "")
        .split(",")
        .map((group) => group.trim())
        .filter(Boolean),
    ),
  ];
}

function subjectReference(subject: unknown): string {
  if (typeof subject !== "string" || subject.length === 0) return "unknown";
  return createHash("sha256").update(subject).digest("hex").slice(0, 12);
}

export function evaluateCognitoAdminAuthorization(params: {
  profile: unknown;
  expectedIssuer: string;
  expectedAudience: string;
  allowedGroups: string[];
}): CognitoAuthorizationDecision {
  const deny = (
    outcome: Exclude<CognitoAuthorizationOutcome, "allow">,
    subject: unknown = undefined,
  ): CognitoAuthorizationDecision => ({
    allowed: false,
    outcome,
    subjectRef: subjectReference(subject),
    approvedGroups: [],
  });

  if (!params.profile || typeof params.profile !== "object") {
    return deny("deny_invalid_profile");
  }

  const profile = params.profile as CognitoProfile;
  if (typeof profile.sub !== "string" || profile.sub.length === 0) {
    return deny("deny_missing_subject");
  }

  if (profile.iss !== params.expectedIssuer) {
    return deny("deny_wrong_issuer", profile.sub);
  }

  const audiences =
    typeof profile.aud === "string"
      ? [profile.aud]
      : Array.isArray(profile.aud)
        ? profile.aud.filter(
            (audience): audience is string => typeof audience === "string",
          )
        : [];
  if (!audiences.includes(params.expectedAudience)) {
    return deny("deny_wrong_audience", profile.sub);
  }

  if (profile.email_verified !== true) {
    return deny("deny_unverified_email", profile.sub);
  }

  if (!Array.isArray(profile["cognito:groups"])) {
    return deny("deny_missing_groups", profile.sub);
  }

  const claimedGroups = profile["cognito:groups"].filter(
    (group): group is string => typeof group === "string",
  );
  const allowlist = new Set(params.allowedGroups);
  const approvedGroups = claimedGroups.filter((group) => allowlist.has(group));
  if (approvedGroups.length === 0) {
    return deny("deny_unapproved_group", profile.sub);
  }

  return {
    allowed: true,
    outcome: "allow",
    subjectRef: subjectReference(profile.sub),
    approvedGroups,
  };
}
