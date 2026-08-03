import {
  evaluateCognitoAdminAuthorization,
  parseCognitoAllowedGroups,
} from "@/src/server/cognitoAdminAuthorization";

const issuer =
  "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example";
const audience = "langfuse-client";
const allowedGroups = [
  "ivx-admin-super",
  "ivx-admin-platform",
  "service-langfuse-admin",
  "service-langfuse-operator",
  "service-langfuse-viewer",
];

const profile = {
  sub: "subject-never-log-raw",
  iss: issuer,
  aud: audience,
  email_verified: true,
  "cognito:groups": ["service-langfuse-viewer"],
};

describe("Cognito admin authorization", () => {
  it("allows an identity in an approved service group", () => {
    const decision = evaluateCognitoAdminAuthorization({
      profile,
      expectedIssuer: issuer,
      expectedAudience: audience,
      allowedGroups,
    });

    expect(decision).toMatchObject({
      allowed: true,
      outcome: "allow",
      approvedGroups: ["service-langfuse-viewer"],
    });
    expect(decision.subjectRef).not.toContain(profile.sub);
  });

  it("denies a verified consumer identity with an unrelated group", () => {
    expect(
      evaluateCognitoAdminAuthorization({
        profile: { ...profile, "cognito:groups": ["users-professional"] },
        expectedIssuer: issuer,
        expectedAudience: audience,
        allowedGroups,
      }).outcome,
    ).toBe("deny_unapproved_group");
  });

  it("denies when the groups claim is missing", () => {
    const { ["cognito:groups"]: _groups, ...withoutGroups } = profile;
    expect(
      evaluateCognitoAdminAuthorization({
        profile: withoutGroups,
        expectedIssuer: issuer,
        expectedAudience: audience,
        allowedGroups,
      }).outcome,
    ).toBe("deny_missing_groups");
  });

  it("denies a token issued to a different audience", () => {
    expect(
      evaluateCognitoAdminAuthorization({
        profile: { ...profile, aud: "different-client" },
        expectedIssuer: issuer,
        expectedAudience: audience,
        allowedGroups,
      }).outcome,
    ).toBe("deny_wrong_audience");
  });

  it("denies a token from a different issuer", () => {
    expect(
      evaluateCognitoAdminAuthorization({
        profile: { ...profile, iss: "https://issuer.invalid" },
        expectedIssuer: issuer,
        expectedAudience: audience,
        allowedGroups,
      }).outcome,
    ).toBe("deny_wrong_issuer");
  });

  it("denies an unverified email", () => {
    expect(
      evaluateCognitoAdminAuthorization({
        profile: { ...profile, email_verified: false },
        expectedIssuer: issuer,
        expectedAudience: audience,
        allowedGroups,
      }).outcome,
    ).toBe("deny_unverified_email");
  });

  it("parses and deduplicates the configured allowlist", () => {
    expect(
      parseCognitoAllowedGroups(
        "service-langfuse-viewer, ivx-admin-platform,service-langfuse-viewer",
      ),
    ).toEqual(["service-langfuse-viewer", "ivx-admin-platform"]);
  });
});
