import {
  useOidc,
  useOidcAccessToken,
  useOidcIdToken,
} from "@axa-fr/react-oidc";
import loadConfig from "@utils/config";
import { sleep } from "@utils/helpers";
import { usePathname } from "next/navigation";
// import { isExpired } from "react-jwt";
import useSWR from "swr";
import { useErrorBoundary } from "@/contexts/ErrorBoundary";

type Method = "GET" | "POST" | "PUT" | "DELETE";

export type ErrorResponse = {
  code: number;
  message: string;
};

const config = loadConfig();

const map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const reverseMap = new Map();

for (let i = 0; i < map.length; i++) {
  let bits: string = i.toString(2);
  const padding: number = 6 - bits.length;
  bits = "0".repeat(padding) + bits;

  reverseMap.set(map.charCodeAt(i), bits);
}

/**
 * Convert base64 string to an array of bytes
 * @param base64Str - Base64 string
 * @returns Array of 1-byte elements
 */
function toByteArray(base64Str: string): string[] {
  let bits: string = "";

  // convert base64 string to bits
  for (let i = 0; i < base64Str.length; i++) {
    bits += reverseMap.get(base64Str.charCodeAt(i));
  }

  // Remove padding ("=" characters)
  bits = bits.slice(0, bits.length - (bits.length % 8));

  const bytesArray = [];

  // Separate string by 8-bit groups
  for (let i = 0; i < bits.length / 8; i++) {
    bytesArray.push(bits.slice(i * 8, i * 8 + 8));
  }

  return bytesArray;
}

/**
 * Convert a base64 string to an UTF-8 array
 * @param base64Str - Base64 string
 * @returns UTF-8 array
 */
export function base64DecToArray(base64Str: string): number[] {
  // Replace - _ and remove padding
  base64Str = base64Str.replaceAll("=", "");
  base64Str = base64Str.replaceAll("-", "+");
  base64Str = base64Str.replaceAll("_", "/");

  const charCodes: string[] = toByteArray(base64Str);

  return charCodes.map((code) => parseInt(code, 2));
}

/**
 * Convert a UTF-8 array to string
 * @param bytes
 * @returns Decoded string
 */
export function UTF8ArrToStr(bytes: number[]): string {
  let decoded: string = ""; // Decoded string
  let nPart: number;
  const arrayLength: number = bytes.length;

  for (let i = 0; i < arrayLength; i++) {
    nPart = bytes[i];
    decoded += String.fromCodePoint(
      nPart > 251 && nPart < 254 && i + 5 < arrayLength /* six bytes */
        ? /* (nPart - 252 << 30) may be not so safe in ECMAScript! So... */
          (nPart - 252) * 1073741824 +
            ((bytes[++i] - 128) << 24) +
            ((bytes[++i] - 128) << 18) +
            ((bytes[++i] - 128) << 12) +
            ((bytes[++i] - 128) << 6) +
            bytes[++i] -
            128
        : nPart > 247 && nPart < 252 && i + 4 < arrayLength /* five bytes */
        ? ((nPart - 248) << 24) +
          ((bytes[++i] - 128) << 18) +
          ((bytes[++i] - 128) << 12) +
          ((bytes[++i] - 128) << 6) +
          bytes[++i] -
          128
        : nPart > 239 && nPart < 248 && i + 3 < arrayLength /* four bytes */
        ? ((nPart - 240) << 18) +
          ((bytes[++i] - 128) << 12) +
          ((bytes[++i] - 128) << 6) +
          bytes[++i] -
          128
        : nPart > 223 && nPart < 240 && i + 2 < arrayLength /* three bytes */
        ? ((nPart - 224) << 12) + ((bytes[++i] - 128) << 6) + bytes[++i] - 128
        : nPart > 191 && nPart < 224 && i + 1 < arrayLength /* two bytes */
        ? ((nPart - 192) << 6) + bytes[++i] - 128 /* nPart < 127 ? */
        : /* one byte */
          nPart
    );
  }

  return decoded;
}

async function apiRequest<T>(
  oidcFetch: (input: RequestInfo, init?: RequestInit) => Promise<Response>,
  method: Method,
  url: string,
  data?: any,
) {
  const origin = config.apiOrigin;

  const res = await oidcFetch(`${origin}/api${url}`, {
    method,
    body: JSON.stringify(data),
  });

  try {
    if (!res.ok) {
      const error = (await res.json()) as ErrorResponse;
      return Promise.reject(error);
    }
    return (await res.json()) as T;
  } catch (e) {
    if (!res.ok) {
      const error = {
        code: res.status,
        message: res.statusText,
      } as ErrorResponse;
      return Promise.reject(error);
    }
    return res;
  }
}

function decodeToken<T = Object>(token: string): T | null {
  try {
    // if the token has more or less than 3 parts or is not a string
    // then is not a valid token
    if (typeof token !== "string" || token.split(".").length !== 3) {
      return null;
    }

    // payload ( index 1 ) has the data stored and
    // data about the expiration time
    const payload: string = token.split(".")[1];

    const base64Bytes: number[] = base64DecToArray(payload);
    // Convert utf-8 array to string
    const jsonPayload: string = decodeURIComponent(UTF8ArrToStr(base64Bytes));
    // Parse JSON
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error("There was an error decoding token: ", error);
    // Return null if something goes wrong
    return null;
  }
}

/**
 * Verify if the token is expired or not
 * @param token - Your JWT
 * @returns boolean
 */
function isExpired(token: string): boolean {
  const decodedToken: any = decodeToken(token);
  let result: boolean = true;

  if (decodedToken && decodedToken.exp) {
    const expirationDate: Date = new Date(0);
    console.log(decodedToken)
    console.log(`EXP ${decodedToken.exp}`)
    expirationDate.setUTCSeconds(decodedToken.exp); // sets the expiration seconds
    // compare the expiration time and the current time
    result = expirationDate.valueOf() < new Date().valueOf();
  }

  return result;
}

export function useNetBirdFetch(ignoreError: boolean = false) {
  const tokenSource = config.tokenSource || "accessToken";
  const { idToken } = useOidcIdToken();
  const { accessToken } = useOidcAccessToken();
  const token = tokenSource.toLowerCase() == "idtoken" ? idToken : accessToken;
  const handleErrors = useApiErrorHandling(ignoreError);

  const isTokenExpired = async () => {
    let attempts = 20;
    while (isExpired(token) && attempts > 0) {
      await sleep(500);
      attempts = attempts - 1;
    }
    return isExpired(token);
  };

  const nativeFetch = async (input: RequestInfo, init?: RequestInit) => {
    const tokenExpired = await isTokenExpired();
    if (tokenExpired) {
      return handleErrors({ code: 401, message: "token expired" });
    }

    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    };

    return fetch(input, {
      ...init,
      headers,
    });
  };

  return {
    fetch: nativeFetch,
  };
}

export default function useFetchApi<T>(
  url: string,
  ignoreError = false,
  revalidate = true,
  allowFetch = true,
) {
  const { fetch } = useNetBirdFetch(ignoreError);
  const handleErrors = useApiErrorHandling(ignoreError);

  const { data, error, isLoading, isValidating, mutate } = useSWR(
    url,
    async (url) => {
      if (!allowFetch) return;
      return apiRequest<T>(fetch, "GET", url).catch((err) =>
        handleErrors(err as ErrorResponse),
      );
    },
    {
      keepPreviousData: true,
      revalidateOnFocus: revalidate,
      revalidateIfStale: revalidate,
      revalidateOnReconnect: revalidate,
    },
  );

  return {
    data: data as T | undefined,
    error,
    isLoading,
    isValidating,
    mutate,
  } as const;
}

export function useApiCall<T>(url: string, ignoreError = false) {
  const { fetch } = useNetBirdFetch(ignoreError);
  const handleErrors = useApiErrorHandling(ignoreError);

  return {
    post: async (data: any, suffix = "") => {
      return apiRequest<T>(fetch, "POST", url + suffix, data)
        .then((res) => Promise.resolve(res as T))
        .catch((err) => handleErrors(err as ErrorResponse));
    },
    put: async (data: any, suffix = "") => {
      return apiRequest<T>(fetch, "PUT", url + suffix, data)
        .then((res) => Promise.resolve(res as T))
        .catch((err) => handleErrors(err as ErrorResponse));
    },
    del: async (data: any = "", suffix = "") => {
      return apiRequest<T>(fetch, "DELETE", url + suffix, data)
        .then((res) => Promise.resolve(res as T))
        .catch((err) => handleErrors(err as ErrorResponse));
    },
    get: async (suffix = "") => {
      return apiRequest<T>(fetch, "GET", url + suffix)
        .then((res) => Promise.resolve(res as T))
        .catch((err) => handleErrors(err as ErrorResponse));
    },
  };
}

export function useApiErrorHandling(ignoreError = false) {
  const { login } = useOidc();
  const currentPath = usePathname();
  const { setError } = useErrorBoundary();
  if (ignoreError)
    return (err: ErrorResponse) => {
      console.log(err);
      return Promise.reject(err);
    };

  return (err: ErrorResponse) => {
    if (err.code == 401 && err.message == "no valid authentication provided") {
      return login(currentPath);
    }
    if (err.code == 401 && err.message == "token expired") {
      return login(currentPath);
    }
    if (err.code == 401 && err.message == "token invalid") {
      setError(err);
    }
    if (err.code == 500 && err.message == "internal server error") {
      setError(err);
    }
    if (err.code > 400 && err.code <= 500) {
      setError(err);
    }

    return Promise.reject(err);
  };
}
