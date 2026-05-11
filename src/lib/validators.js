import { z } from "zod";

export const loginSchema = z.object({
  clientId: z.string().min(1, "clientId is required"),
  clientSecret: z.string().min(1, "clientSecret is required"),
  username: z.string().min(1, "username is required"),
  password: z.string().min(1, "password is required"),
  scope: z.array(z.string()).optional()
});

export const refreshSchema = z.object({
  clientId: z.string().min(1, "clientId is required"),
  clientSecret: z.string().min(1, "clientSecret is required"),
  refreshToken: z.string().min(1, "refreshToken is required")
});

export const introspectSchema = z.object({
  clientId: z.string().min(1, "clientId is required"),
  clientSecret: z.string().min(1, "clientSecret is required"),
  token: z.string().min(1, "token is required")
});

export const logoutSchema = z
  .object({
    refreshToken: z.string().optional(),
    accessToken: z.string().optional()
  })
  .refine((data) => data.refreshToken || data.accessToken, {
    message: "Either refreshToken or accessToken must be provided",
    path: ["refreshToken"]
  });
