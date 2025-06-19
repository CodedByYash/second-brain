"use client";
import {
  signIn,
  getProviders,
  LiteralUnion,
  ClientSafeProvider,
} from "next-auth/react";
import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { BuiltInProviderType } from "next-auth/providers/index";

export default function SignIn() {
  const [providers, setProviders] = useState<Record<
    LiteralUnion<BuiltInProviderType, string>,
    ClientSafeProvider
  > | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const setAuthProviders = async () => {
      const res = await getProviders();
      setProviders(res);
    };
    setAuthProviders();
  }, []);

  const handleCredentialsSignIn = async (
    e: React.FormEvent<HTMLFormElement>
  ) => {
    e.preventDefault();
    setLoading(true);

    const result = await signIn("credentials", {
      email,
      password,
      redirect: false,
    });

    if (result?.error) {
      alert("invalid credentials");
    } else {
      router.push("/dashboard");
    }
    setLoading(false);
  };

  const handleEmailSignIn = async () => {
    await signIn("email", { email, callbackUrl: "/dashboard" });
  };

  return (
    <div className="max-w-md mx-auto mt-8 p-6 bg-white rounded-lg shadow-md">
      <h1 className="text-2xl font-bold mb=6">Sign In</h1>
      <form onSubmit={handleCredentialsSignIn} className="mb-6">
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full p-2 border rounded-md"
            required
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-500 text-white p-2 rounded-md hover:bg-blue-600 disabled:opacity-50 "
        >
          {loading ? "Signing in..." : "Sign in with Email/Password"}
        </button>
      </form>

      <div className="mb-4">
        <button
          onClick={handleEmailSignIn}
          className="w-full bg-green-500 text-white p-2 rounded-md hover:bg-green-600"
        >
          Send Magic Link
        </button>
      </div>

      <div className="space-y-2">
        {providers &&
          Object.values(providers).map((provider) => {
            if (provider.id === "credentials" || provider.id === "email")
              return null;

            return (
              <button
                key={provider.name}
                onClick={() =>
                  signIn(provider.id, { callbackUrl: "/dashboard" })
                }
                className="w-full bg-bray-800 text-white p-2 rounded-md hover:bg-gray-700"
              >
                Sign in with {provider.name}
              </button>
            );
          })}
      </div>
      <p className="mt-4 text-center">
        Don't have an account?{" "}
        <a href="/auth/signup" className="text-blue-500 hover:underline">
          Sign up
        </a>
      </p>
    </div>
  );
}
