import { z } from "zod";

import type { AgUiRunAgentInput } from "@/src/features/in-app-agent/schema";

const AgUiContextSchema = z.object({
  description: z.string(),
  value: z.string(),
});

const InAppAgentScreenContextInputSchema = z.object({
  currentUrl: z.url().max(4096),
});

const ID_REGEX = /^[a-f0-9]{8,64}$/i;
const PROJECT_ID_REGEX = /^[a-z0-9_-]{1,128}$/i;
const FILTER_VALUE_REGEX = /^[\w@.+:-]{1,200}$/;
const ALLOWED_RESOURCES = [
  "traces",
  "sessions",
  "datasets",
  "prompts",
  "dashboards",
  "evals",
  "playground",
  "settings",
] as const;

const SafeIdSchema = z.string().regex(ID_REGEX);
const ProjectIdSchema = z.string().regex(PROJECT_ID_REGEX);
const ResourceSchema = z.enum(ALLOWED_RESOURCES);
const FilterValueSchema = z.string().regex(FILTER_VALUE_REGEX);
const FilterTypeSchema = z.enum(["stringOptions", "boolean"]);
const FilterOperatorSchema = z.enum(["any of", "="]);
const SafeFilterPartsSchema = z.object({
  field: FilterValueSchema,
  type: FilterTypeSchema,
  operator: FilterOperatorSchema,
});
const SafeTimestampSchema = z.string().refine((timestamp) => {
  return !Number.isNaN(Date.parse(timestamp));
});

const OptionalSafeIdSchema = SafeIdSchema.nullish()
  .catch(undefined)
  .transform((value) => value ?? undefined);
const OptionalProjectIdSchema = ProjectIdSchema.nullish()
  .catch(undefined)
  .transform((value) => value ?? undefined);
const OptionalResourceSchema = ResourceSchema.nullish()
  .catch(undefined)
  .transform((value) => value ?? undefined);
const OptionalTimestampSchema = SafeTimestampSchema.nullish()
  .catch(undefined)
  .transform((value) => value ?? undefined);

const SanitizedScreenContextFilterSchema = z.union([
  z.object({
    field: FilterValueSchema,
    type: z.literal("boolean"),
    operator: FilterOperatorSchema,
    value: z.boolean(),
  }),
  z.object({
    field: FilterValueSchema,
    type: z.literal("stringOptions"),
    operator: FilterOperatorSchema,
    values: z.array(FilterValueSchema).max(10),
  }),
]);
type SafeScreenContextFilter = z.infer<
  typeof SanitizedScreenContextFilterSchema
>;
const OptionalFiltersSchema = z
  .array(SanitizedScreenContextFilterSchema)
  .max(10)
  .transform((filters) => (filters.length > 0 ? filters : undefined));

const SanitizedInAppAgentScreenContextOutputSchema = z.object({
  currentPage: z
    .object({
      path: z.string().max(2048),
      projectId: OptionalProjectIdSchema,
      resource: OptionalResourceSchema,
      traceId: OptionalSafeIdSchema,
      observationId: OptionalSafeIdSchema,
      peekId: OptionalSafeIdSchema,
      timestamp: OptionalTimestampSchema,
      filters: OptionalFiltersSchema,
    })
    .transform(removeUndefinedFields),
});

// Security boundary for prompt context: this schema accepts client-controlled
// AG-UI context, rejects untrusted URLs, and emits only bounded, allowlisted
// URL facts. Localhost URLs are accepted only in development. Do not pass raw
// context values into prompts or tracing.
export const SanitizedInAppAgentScreenContextSchema = z
  .array(AgUiContextSchema)
  .transform((context, ctx) => {
    const currentUrl = context.find(
      (item) => item.description === "currentUrl",
    )?.value;
    const parsedInput = InAppAgentScreenContextInputSchema.safeParse({
      currentUrl,
    });

    if (!parsedInput.success) {
      ctx.addIssue({
        code: "custom",
        message: "Screen context URL is invalid",
      });
      return z.NEVER;
    }

    const url = new URL(parsedInput.data.currentUrl);

    if (!isAllowedScreenContextUrl(url)) {
      ctx.addIssue({
        code: "custom",
        message: "Screen context URL host is not allowed",
      });
      return z.NEVER;
    }

    const path = url.pathname.slice(0, 2048);
    const pathSegments = path.split("/").filter(Boolean);
    const projectIndex = pathSegments.indexOf("project");
    const projectId = pathSegments[projectIndex + 1];
    const resource = pathSegments[projectIndex + 2];
    const currentPage = {
      path,
      projectId,
      resource,
      traceId: url.searchParams.get("traceId"),
      observationId: url.searchParams.get("observation"),
      peekId: url.searchParams.get("peek"),
      timestamp: url.searchParams.get("timestamp"),
      filters: parseSafeFilters(url.searchParams.get("filter")),
    };

    const parsedContext =
      SanitizedInAppAgentScreenContextOutputSchema.safeParse({ currentPage });

    if (!parsedContext.success) {
      ctx.addIssue({
        code: "custom",
        message: "Screen context URL could not be sanitized",
      });
      return z.NEVER;
    }

    return parsedContext.data;
  });

export type SanitizedInAppAgentScreenContext = z.infer<
  typeof SanitizedInAppAgentScreenContextSchema
>;

export type InAppAgentRunInput = Omit<AgUiRunAgentInput, "context"> & {
  context: SanitizedInAppAgentScreenContext | null;
};

export function sanitizeInAppAgentScreenContext(
  context: AgUiRunAgentInput["context"],
): SanitizedInAppAgentScreenContext | null {
  const parsedContext =
    SanitizedInAppAgentScreenContextSchema.safeParse(context);

  return parsedContext.success ? parsedContext.data : null;
}

function isAllowedScreenContextUrl(url: URL): boolean {
  if (url.hostname === "localhost" || url.hostname === "127.0.0.1") {
    return (
      process.env.NODE_ENV === "development" &&
      (url.protocol === "http:" || url.protocol === "https:")
    );
  }

  return url.protocol === "https:" && url.hostname.endsWith(".langfuse.com");
}

function parseSafeFilters(filter: string | null): SafeScreenContextFilter[] {
  if (!filter) {
    return [];
  }

  return filter
    .split(",")
    .flatMap((rawFilter) => parseSafeFilter(rawFilter))
    .slice(0, 10);
}

function parseSafeFilter(rawFilter: string): SafeScreenContextFilter[] {
  const [
    field,
    type,
    maybeOperator,
    maybeRawValue,
    maybeRawValueWithEmptySlot,
  ] = rawFilter.split(";");
  const operator = maybeRawValueWithEmptySlot ? maybeRawValue : maybeOperator;
  const rawValue = maybeRawValueWithEmptySlot ?? maybeRawValue;

  if (!field || !type || !operator || rawValue === undefined) {
    return [];
  }

  const parsedFilterParts = SafeFilterPartsSchema.safeParse({
    field,
    type,
    operator,
  });

  if (!parsedFilterParts.success) {
    return [];
  }

  if (parsedFilterParts.data.type === "boolean") {
    if (rawValue !== "true" && rawValue !== "false") {
      return [];
    }

    return [
      {
        field: parsedFilterParts.data.field,
        type: parsedFilterParts.data.type,
        operator: parsedFilterParts.data.operator,
        value: rawValue === "true",
      },
    ];
  }

  const values = rawValue
    .split("|")
    .flatMap((value) => {
      const decodedValue = safelyDecodeUriComponent(value);

      return decodedValue && FilterValueSchema.safeParse(decodedValue).success
        ? [decodedValue]
        : [];
    })
    .slice(0, 10);

  return values.length > 0
    ? [
        {
          field: parsedFilterParts.data.field,
          type: parsedFilterParts.data.type,
          operator: parsedFilterParts.data.operator,
          values,
        },
      ]
    : [];
}

function removeUndefinedFields<T extends Record<string, unknown>>(value: T) {
  return Object.fromEntries(
    Object.entries(value).filter(([, fieldValue]) => fieldValue !== undefined),
  ) as T;
}

function safelyDecodeUriComponent(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}
