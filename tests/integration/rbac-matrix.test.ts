import { afterEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import mongoose from "mongoose";
import app from "../../src/app.js";
import { Session, User } from "../../src/modules/auth/auth.models.js";
import {
  effectivePermissions,
  rolePolicy,
} from "../../src/modules/auth/auth.permissions.js";

vi.mock("../../src/config/database.js", () => ({
  connectDB: vi.fn().mockResolvedValue({}),
  isDbConnected: () => false,
}));
vi.mock("../../src/modules/auth/auth.email.js", () => ({
  sendVerification: vi.fn().mockResolvedValue(true),
}));

const origin = "http://localhost:5173";
const cookie = "floraconnect_session=" + "a".repeat(64);
const csrf = "csrf-fixture";
const ROLES = [
  "SUPER_ADMIN",
  "PLATFORM_ADMIN",
  "ORGANIZATION_ADMIN",
  "ORGANIZATION_MEMBER",
  "FLORIST",
  "GROWER",
  "USER",
] as const;

const fixtureUser = (role: string, overrides: Record<string, unknown> = {}) => ({
  _id: new mongoose.Types.ObjectId(),
  publicId: "78ed06ba-8a40-4425-a430-a7d297f4a21c",
  name: "Fixture",
  email: `${role.toLowerCase()}@example.test`,
  role,
  status: "ACTIVE",
  emailVerified: true,
  mustChangePassword: false,
  ...overrides,
});

function actAs(role: string, overrides: Record<string, unknown> = {}) {
  vi.spyOn(Session, "findOne").mockResolvedValue({
    userId: new mongoose.Types.ObjectId(),
    csrfToken: csrf,
  } as never);
  vi.spyOn(User, "findById").mockResolvedValue(
    fixtureUser(role, overrides) as never,
  );
}

afterEach(() => vi.restoreAllMocks());

// Static SUPER_ADMIN-only endpoint (no DB needed), used for the role matrix.
const ADMIN_ONLY_GET = "/api/admin/console/access-policy";

describe("RBAC: authentication (401)", () => {
  it("rejects a request with no session cookie", async () => {
    const res = await request(app).get(ADMIN_ONLY_GET);
    expect(res.status).toBe(401);
  });

  it("rejects a malformed session cookie", async () => {
    const res = await request(app)
      .get(ADMIN_ONLY_GET)
      .set("Cookie", "floraconnect_session=not-a-valid-token");
    expect(res.status).toBe(401);
  });

  it("rejects an expired or unknown session", async () => {
    vi.spyOn(Session, "findOne").mockResolvedValue(null as never);
    const res = await request(app).get(ADMIN_ONLY_GET).set("Cookie", cookie);
    expect(res.status).toBe(401);
  });

  it.each(["SUSPENDED", "PENDING"])(
    "rejects a %s account with 403",
    async (status) => {
      actAs("SUPER_ADMIN", { status });
      const res = await request(app).get(ADMIN_ONLY_GET).set("Cookie", cookie);
      expect(res.status).toBe(403);
    },
  );

  it("rejects an unverified account with 403", async () => {
    actAs("SUPER_ADMIN", { emailVerified: false });
    const res = await request(app).get(ADMIN_ONLY_GET).set("Cookie", cookie);
    expect(res.status).toBe(403);
  });
});

describe("RBAC: role matrix on SUPER_ADMIN-only endpoint", () => {
  it("allows SUPER_ADMIN", async () => {
    actAs("SUPER_ADMIN");
    const res = await request(app).get(ADMIN_ONLY_GET).set("Cookie", cookie);
    expect(res.status).toBe(200);
  });

  it.each(ROLES.filter((r) => r !== "SUPER_ADMIN"))(
    "forbids %s with 403",
    async (role) => {
      actAs(role);
      const res = await request(app).get(ADMIN_ONLY_GET).set("Cookie", cookie);
      expect(res.status).toBe(403);
    },
  );

  it("blocks SUPER_ADMIN who must still change a temporary password", async () => {
    actAs("SUPER_ADMIN", { mustChangePassword: true });
    const res = await request(app).get(ADMIN_ONLY_GET).set("Cookie", cookie);
    expect(res.status).toBe(403);
  });
});

describe("RBAC: direct API access to admin reads", () => {
  it.each([
    "/api/admin/users",
    "/api/admin/console/summary",
    "/api/admin/console/roles",
    "/api/admin/console/analytics",
  ])("%s rejects unauthenticated requests", async (path) => {
    const res = await request(app).get(path);
    expect(res.status).toBe(401);
  });

  it.each(
    ROLES.filter((r) => r !== "SUPER_ADMIN").flatMap((role) =>
      [
        "/api/admin/users",
        "/api/admin/console/summary",
        "/api/admin/console/roles",
      ].map((path) => [role, path] as const),
    ),
  )("%s gets 403 on %s", async (role, path) => {
    actAs(role);
    const res = await request(app).get(path).set("Cookie", cookie);
    expect(res.status).toBe(403);
  });
});

describe("RBAC: privilege escalation attempts", () => {
  const targetId = "10c45050-d898-4b52-935f-bfa5b991d391";

  it.each(ROLES.filter((r) => r !== "SUPER_ADMIN"))(
    "%s cannot change a user's access",
    async (role) => {
      actAs(role);
      const res = await request(app)
        .patch(`/api/admin/console/users/${targetId}/access`)
        .set("Cookie", cookie)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send({ role: "SUPER_ADMIN", reason: "escalation test" });
      expect(res.status).toBe(403);
    },
  );

  it("rejects a state-changing request with a wrong CSRF token", async () => {
    actAs("SUPER_ADMIN");
    const res = await request(app)
      .patch(`/api/admin/console/users/${targetId}/access`)
      .set("Cookie", cookie)
      .set("Origin", origin)
      .set("X-CSRF-Token", "wrong")
      .send({ role: "USER" });
    expect(res.status).toBe(403);
  });

  it("cannot self-escalate through profile update (role field ignored)", async () => {
    actAs("USER");
    const save = vi.fn();
    vi.spyOn(User, "findById").mockResolvedValue({
      ...fixtureUser("USER"),
      save,
    } as never);
    await request(app)
      .patch("/api/auth/profile")
      .set("Cookie", cookie)
      .set("Origin", origin)
      .set("X-CSRF-Token", csrf)
      .send({ name: "Me", role: "SUPER_ADMIN", permissions: ["users.access.manage"] });
    // Whatever the status, the role must never have been written as SUPER_ADMIN.
    for (const call of save.mock.instances) {
      expect((call as { role?: string }).role).not.toBe("SUPER_ADMIN");
    }
  });
});

describe("RBAC: permission policy (unit)", () => {
  it("only SUPER_ADMIN has users.access.manage", () => {
    for (const role of ROLES) {
      const has = rolePolicy[role].permissions.includes("users.access.manage");
      expect(has).toBe(role === "SUPER_ADMIN");
    }
  });

  it("PLATFORM_ADMIN cannot manage users or roles", () => {
    const p = effectivePermissions({ role: "PLATFORM_ADMIN", permissions: null });
    expect(p).toContain("applications.review");
    expect(p).not.toContain("users.read");
    expect(p).not.toContain("users.access.manage");
  });

  it.each(ROLES.filter((r) => r !== "SUPER_ADMIN" && r !== "PLATFORM_ADMIN"))(
    "%s cannot gain admin permissions via a tampered permissions array",
    (role) => {
      const p = effectivePermissions({
        role,
        permissions: ["users.access.manage", "users.read", "audit.read"],
      });
      expect(p).not.toContain("users.access.manage");
      expect(p).not.toContain("users.read");
      expect(p).not.toContain("audit.read");
    },
  );

  it("unknown roles get no permissions", () => {
    expect(effectivePermissions({ role: "ROOT", permissions: null })).toEqual([]);
  });
});
