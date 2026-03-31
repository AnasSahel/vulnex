import {
  pgTable,
  text,
  timestamp,
  boolean,
  serial,
  real,
  date,
  integer,
  unique,
  index,
} from "drizzle-orm/pg-core";

// ─── Auth tables (better-auth) ──────────────────────────────────────────────

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const session = pgTable("session", {
  id: text("id").primaryKey(),
  expiresAt: timestamp("expires_at").notNull(),
  token: text("token").notNull().unique(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
});

export const account = pgTable("account", {
  id: text("id").primaryKey(),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: timestamp("access_token_expires_at"),
  refreshTokenExpiresAt: timestamp("refresh_token_expires_at"),
  scope: text("scope"),
  password: text("password"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const verification = pgTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// ─── Vulnerability data tables ──────────────────────────────────────────────

export const cve = pgTable("cve", {
  id: text("id").primaryKey(),
  description: text("description"),
  publishedAt: timestamp("published_at"),
  lastModified: timestamp("last_modified"),
  sourceId: text("source_id"),
  status: text("status"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (t) => [
  index("cve_last_modified_idx").on(t.lastModified),
]);

export const cveScore = pgTable("cve_score", {
  id: serial("id").primaryKey(),
  cveId: text("cve_id")
    .notNull()
    .references(() => cve.id, { onDelete: "cascade" }),
  cvssV3Score: real("cvss_v3_score"),
  cvssV3Vector: text("cvss_v3_vector"),
  epssScore: real("epss_score"),
  epssPercentile: real("epss_percentile"),
  source: text("source").notNull(),
  scoredAt: timestamp("scored_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (t) => [
  index("cve_score_lookup_idx").on(t.cveId, t.source, t.scoredAt),
]);

export const kevEntry = pgTable("kev_entry", {
  id: serial("id").primaryKey(),
  cveId: text("cve_id")
    .notNull()
    .references(() => cve.id, { onDelete: "cascade" }),
  vendor: text("vendor"),
  product: text("product"),
  vulnerabilityName: text("vulnerability_name"),
  dateAdded: date("date_added"),
  dueDate: date("due_date"),
  knownRansomware: boolean("known_ransomware").default(false),
  notes: text("notes"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (t) => [
  index("kev_entry_cve_id_idx").on(t.cveId),
]);

export const exploit = pgTable("exploit", {
  id: serial("id").primaryKey(),
  cveId: text("cve_id")
    .notNull()
    .references(() => cve.id, { onDelete: "cascade" }),
  source: text("source").notNull(),
  title: text("title"),
  url: text("url").unique(),
  publishedAt: timestamp("published_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const advisory = pgTable("advisory", {
  id: serial("id").primaryKey(),
  ghsaId: text("ghsa_id").unique(),
  cveId: text("cve_id").references(() => cve.id, { onDelete: "set null" }),
  severity: text("severity"),
  summary: text("summary"),
  description: text("description"),
  publishedAt: timestamp("published_at"),
  updatedAt: timestamp("updated_at"),
  url: text("url"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const syncLog = pgTable("sync_log", {
  id: serial("id").primaryKey(),
  source: text("source").notNull().unique(),
  lastCursor: text("last_cursor"),
  lastSyncedAt: timestamp("last_synced_at"),
  status: text("status"),
  errorMessage: text("error_message"),
  itemsSynced: integer("items_synced"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const watchlist = pgTable(
  "watchlist",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    cveId: text("cve_id")
      .notNull()
      .references(() => cve.id, { onDelete: "cascade" }),
    addedAt: timestamp("added_at").notNull().defaultNow(),
    notes: text("notes"),
  },
  (t) => [unique().on(t.userId, t.cveId)]
);

// ─── Product tables ─────────────────────────────────────────────────────────

export const product = pgTable("product", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  source: text("source").notNull().default("manual"),
  lastScannedAt: timestamp("last_scanned_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (t) => [
  index("product_user_id_idx").on(t.userId),
]);

export const productCve = pgTable("product_cve", {
  id: serial("id").primaryKey(),
  productId: text("product_id")
    .notNull()
    .references(() => product.id, { onDelete: "cascade" }),
  cveId: text("cve_id")
    .notNull()
    .references(() => cve.id, { onDelete: "cascade" }),
  addedAt: timestamp("added_at").notNull().defaultNow(),
}, (t) => [
  unique().on(t.productId, t.cveId),
  index("product_cve_product_id_idx").on(t.productId),
]);

export const productSbom = pgTable("product_sbom", {
  id: serial("id").primaryKey(),
  productId: text("product_id")
    .notNull()
    .references(() => product.id, { onDelete: "cascade" }),
  filename: text("filename").notNull(),
  format: text("format").notNull(), // 'cyclonedx' | 'spdx' | 'unknown'
  content: text("content").notNull(),
  fileSize: integer("file_size").notNull(),
  uploadedAt: timestamp("uploaded_at").notNull().defaultNow(),
}, (t) => [
  index("product_sbom_product_id_idx").on(t.productId),
]);
