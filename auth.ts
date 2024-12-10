import { db } from "@/db";
import { users } from "@/db/schema";
import { signInSchema } from "@/lib/zod";
import { DrizzleAdapter } from "@auth/drizzle-adapter";
import { compare } from "bcrypt-ts";
import { eq } from "drizzle-orm";
import NextAuth from "next-auth";
import credentials from "next-auth/providers/credentials";
import type { Adapter } from "@auth/core/adapters";

export const { handlers, signIn, signOut, auth } = NextAuth({
  adapter: DrizzleAdapter(db) as Adapter,
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/sign-in",
  },
  providers: [
    credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const validatedFields = signInSchema.safeParse(credentials);

        if (!validatedFields.success) {
          return null;
        }

        const { email, password } = validatedFields.data;

        const user = await db
          .select()
          .from(users)
          .where(eq(users.email, email))
          .then(([user]) => user);

        if (!user || !user.password) {
          throw new Error("User not found");
        }

        const passwordsMatch = await compare(password, user.password);

        if (!passwordsMatch) return null;

        return {
          id: user.id,
          email: user.email,
          role: user.role,
        };
      },
    }),
  ],
  callbacks: {
    jwt({ token, user }) {
      if (user) {
        token.role = user.role;
      }
      return token;
    },
    session({ session, token }) {
      session.user.id = token.sub!;
      session.user.role = token.role!;
      return session;
    },
  },
});
