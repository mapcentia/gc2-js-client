var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};

// src/util/utils.ts
import { jwtDecode } from "jwt-decode";
var generatePkceChallenge = () => __async(void 0, null, function* () {
  const generateRandomString = () => {
    const array = new Uint32Array(28);
    crypto.getRandomValues(array);
    return Array.from(array, (dec) => ("0" + dec.toString(16)).substr(-2)).join("");
  };
  const sha256 = (plain) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return crypto.subtle.digest("SHA-256", data);
  };
  const base64urlencode = (str) => {
    return btoa(String.fromCharCode.apply(null, [...new Uint8Array(str)])).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  function pkceChallengeFromVerifier(v) {
    return __async(this, null, function* () {
      const hashed = yield sha256(v);
      return base64urlencode(hashed);
    });
  }
  const { state, codeVerifier } = {
    state: generateRandomString(),
    codeVerifier: generateRandomString()
  };
  const codeChallenge = yield pkceChallengeFromVerifier(codeVerifier);
  return {
    state,
    codeVerifier,
    codeChallenge
  };
});
var isTokenExpired = (token) => {
  let isJwtExpired = false;
  const { exp } = jwtDecode(token);
  const currentTime = (/* @__PURE__ */ new Date()).getTime() / 1e3;
  if (exp) {
    if (currentTime > exp) isJwtExpired = true;
  }
  return isJwtExpired;
};
var passwordIsStrongEnough = (password, allowNull = false) => {
  const message = "Entered password is too weak";
  if (password === "" && allowNull) return true;
  if (password.length < 8) return message;
  if (!/[A-Z]/.test(password)) return message;
  if (!/[a-z]/.test(password)) return message;
  if (!/\d/.test(password)) return message;
  return true;
};
var isLogin = (gc2) => __async(void 0, null, function* () {
  const accessToken = localStorage.getItem("accessToken");
  const refreshToken = localStorage.getItem("refreshToken");
  if (!accessToken && !refreshToken) {
    return false;
  }
  if (!accessToken || accessToken && isTokenExpired(accessToken)) {
    if (refreshToken && isTokenExpired(refreshToken)) {
      console.error("Refresh token has expired. Please login again");
      return false;
    }
    if (refreshToken) {
      try {
        const data = yield gc2.getRefreshToken(refreshToken);
        setTokens({ accessToken: data.access_token, refreshToken });
        console.log("Access token refreshed");
      } catch (e) {
        console.error("Could not get refresh token");
        return false;
      }
    }
  }
  return true;
});
var setTokens = (tokens) => {
  localStorage.setItem("accessToken", tokens.accessToken);
  localStorage.setItem("refreshToken", tokens.refreshToken);
};
var setOptions = (options) => {
  if (options.clientId) localStorage.setItem("clientId", options.clientId);
  if (options.host) localStorage.setItem("host", options.host);
  if (options.redirectUri) localStorage.setItem("redirectUri", options.redirectUri);
};
var getTokens = () => {
  return {
    accessToken: localStorage.getItem("accessToken") || "",
    refreshToken: localStorage.getItem("refreshToken") || ""
  };
};
var getOptions = () => {
  return {
    clientId: localStorage.getItem("clientId") || "",
    host: localStorage.getItem("host") || "",
    redirectUri: localStorage.getItem("redirectUri") || ""
  };
};
export {
  generatePkceChallenge,
  getOptions,
  getTokens,
  isLogin,
  isTokenExpired,
  passwordIsStrongEnough,
  setOptions,
  setTokens
};
//# sourceMappingURL=utils.mjs.map