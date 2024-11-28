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

// src/services/gc2.services.ts
import axios, { AxiosError } from "axios";
import * as querystring from "querystring";
var Gc2Service = class {
  constructor(options) {
    this.options = options;
    this.http = axios.create({
      baseURL: this.options.host
    });
  }
  getDeviceCode() {
    return __async(this, null, function* () {
      const { data } = yield this.http.post(
        `/api/v4/oauth/device`,
        {
          client_id: this.options.clientId
        },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
      return data;
    });
  }
  poolToken(deviceCode, interval) {
    return __async(this, null, function* () {
      const getToken = () => this.http.post(
        "/api/v4/oauth",
        {
          client_id: this.options.clientId,
          device_code: deviceCode,
          grant_type: "device_code"
        },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      ).then(({ data }) => data).catch((error) => {
        var _a;
        if (error instanceof AxiosError) {
          const err = (_a = error.response) == null ? void 0 : _a.data;
          if (err.error === "authorization_pending") {
            return null;
          } else {
            return err.error_description;
          }
        }
      });
      let response = yield getToken();
      while (response === null) {
        response = yield new Promise((resolve) => {
          setTimeout(() => __async(this, null, function* () {
            resolve(yield getToken());
          }), interval * 1100);
        });
      }
      return response;
    });
  }
  getAuthorizationCodeURL(codeChallenge, state) {
    const queryParams = querystring.stringify({
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    });
    return `${this.options.host}/auth/?${queryParams}`;
  }
  getAuthorizationCodeToken(code, codeVerifier) {
    return __async(this, null, function* () {
      return this.http.post(
        `/api/v4/oauth`,
        {
          client_id: this.options.clientId,
          redirect_uri: this.options.redirectUri,
          grant_type: "authorization_code",
          code,
          code_verifier: codeVerifier
        },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      ).then(({ data }) => data).catch((err) => {
        throw new Error(err.message);
      });
    });
  }
  // TODO use v4 when all has updated GC2
  getPasswordToken(username, password, database) {
    return __async(this, null, function* () {
      return this.http.post(
        `/api/v3/oauth/token`,
        {
          client_id: this.options.clientId,
          grant_type: "password",
          username,
          password,
          database
        },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      ).then(({ data }) => data);
    });
  }
  getRefreshToken(token) {
    return __async(this, null, function* () {
      return this.http.post(
        `/api/v4/oauth`,
        {
          client_id: this.options.clientId,
          grant_type: "refresh_token",
          refresh_token: token
        },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      ).then(({ data }) => data).catch((err) => {
      });
    });
  }
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

// src/CodeFlow.ts
import querystring2 from "querystring";
var CodeFlow = class {
  constructor(options) {
    this.options = options;
    this.service = new Gc2Service(options);
  }
  redirectHandle() {
    return __async(this, null, function* () {
      const url = window.location.search.substring(1);
      const queryString = querystring2.parse(url);
      if (queryString.error) {
        return Promise.reject(new Error(`Failed to redirect: ${url}`));
      }
      if (queryString.code) {
        if (queryString.state !== localStorage.getItem("state")) {
          return Promise.reject("Possible CSRF attack. Aborting login???");
        }
        try {
          const {
            access_token,
            refresh_token
          } = yield this.service.getAuthorizationCodeToken(queryString.code, localStorage.getItem("codeVerifier"));
          setTokens({ accessToken: access_token, refreshToken: refresh_token });
          setOptions({ clientId: this.options.clientId, host: this.options.host, redirectUri: this.options.redirectUri });
          localStorage.removeItem("state");
          localStorage.removeItem("codeVerifier");
          return Promise.resolve(true);
        } catch (e) {
          return Promise.reject(`Failed to redirect: ${url}`);
        }
      }
      if (yield isLogin(this.service)) {
        return Promise.resolve(true);
      }
      return Promise.resolve(false);
    });
  }
  signin() {
    return __async(this, null, function* () {
      const { state, codeVerifier, codeChallenge } = yield generatePkceChallenge();
      localStorage.setItem("state", state);
      localStorage.setItem("codeVerifier", codeVerifier);
      window.location = this.service.getAuthorizationCodeURL(
        codeChallenge,
        state
      );
    });
  }
};
export {
  CodeFlow as default
};
//# sourceMappingURL=CodeFlow.mjs.map