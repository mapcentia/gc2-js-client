"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
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

// src/index.ts
var src_exports = {};
__export(src_exports, {
  CodeFlow: () => CodeFlow,
  Sql: () => Sql
});
module.exports = __toCommonJS(src_exports);

// src/services/gc2.services.ts
var import_axios = __toESM(require("axios"));
var querystring = __toESM(require("querystring"));
var Gc2Service = class {
  constructor(options) {
    this.options = options;
    this.http = import_axios.default.create({
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
        if (error instanceof import_axios.AxiosError) {
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
  clearTokens() {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
  }
  clearOptions() {
    localStorage.removeItem("clientId");
    localStorage.removeItem("host");
    localStorage.removeItem("redirectUri");
  }
};

// src/util/utils.ts
var import_jwt_decode = require("jwt-decode");
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
  const { exp } = (0, import_jwt_decode.jwtDecode)(token);
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
      throw new Error("Refresh token has expired. Please login again.");
    }
    if (refreshToken) {
      try {
        const data = yield gc2.getRefreshToken(refreshToken);
        setTokens({ accessToken: data.access_token, refreshToken });
        console.log("Access token refreshed");
      } catch (e) {
        throw new Error("Could not get refresh token.");
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

// src/CodeFlow.ts
var import_querystring = __toESM(require("querystring"));
var CodeFlow = class {
  constructor(options) {
    this.options = options;
    this.service = new Gc2Service(options);
  }
  redirectHandle() {
    return __async(this, null, function* () {
      const url = window.location.search.substring(1);
      const queryString = import_querystring.default.parse(url);
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
          setOptions({
            clientId: this.options.clientId,
            host: this.options.host,
            redirectUri: this.options.redirectUri
          });
          localStorage.removeItem("state");
          localStorage.removeItem("codeVerifier");
          const params = new URLSearchParams(window.location.search);
          params.delete("code");
          params.delete("state");
          const loc = window.location;
          const newUrl = loc.origin + loc.pathname + (params.size > 1 ? "?" + params.toString() : "");
          history.pushState(null, "", newUrl);
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
  signIn() {
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
  signOut() {
    this.service.clearTokens();
    this.service.clearOptions();
  }
};

// src/util/request-headers.ts
var getHeaders = (contentType = "application/json") => __async(void 0, null, function* () {
  const options = getOptions();
  const service = new Gc2Service(options);
  if (!(yield isLogin(service))) {
    return Promise.reject("Is not logged in");
  }
  const { accessToken } = getTokens();
  const headers = {
    Accept: "application/json",
    Cookie: "XDEBUG_SESSION=XDEBUG_ECLIPSE",
    Authorization: accessToken ? "Bearer " + accessToken : null
  };
  if (contentType) {
    headers["Content-Type"] = contentType;
  }
  return headers;
});
var request_headers_default = getHeaders;

// src/util/make-request.ts
var make = (version, resource, method, payload, contentType = "application/json") => __async(void 0, null, function* () {
  const options = getOptions();
  const headers = yield request_headers_default(contentType);
  let request = {
    method,
    headers,
    redirect: "manual"
  };
  if (payload) {
    request.body = contentType === "application/json" ? JSON.stringify(payload) : payload;
  }
  return yield fetch(options.host + `/api/v${version}/${resource}`, request);
});
var make_request_default = make;

// src/util/get-response.ts
var get = (response, expectedCode, doNotExit = false) => __async(void 0, null, function* () {
  let res = null;
  if (![204, 303].includes(expectedCode)) {
    res = yield response.json();
  }
  if (response.status !== expectedCode) {
    if (res === null) {
      res = yield response.json();
    }
  }
  return res;
});
var get_response_default = get;

// src/Sql.ts
var Sql = class {
  constructor() {
  }
  select(query) {
    return __async(this, null, function* () {
      const body = { q: query };
      const response = yield make_request_default("4", `sql`, "POST", body);
      return yield get_response_default(response, 200);
    });
  }
};

// src/index.ts
module.exports = {
  CodeFlow,
  Sql
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  CodeFlow,
  Sql
});
/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2024 MapCentia ApS
 * @license    http://www.gnu.org/licenses/#AGPL  GNU AFFERO GENERAL PUBLIC LICENSE 3
 *
 */
//# sourceMappingURL=index.js.map