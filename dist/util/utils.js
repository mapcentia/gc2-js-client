"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getOptions = exports.getTokens = exports.isLogin = exports.setOptions = exports.setTokens = exports.noLogin = exports.passwordIsStrongEnough = exports.isTokenExpired = exports.generatePkceChallenge = void 0;
const jwt_decode_1 = require("jwt-decode");
const generatePkceChallenge = () => __awaiter(void 0, void 0, void 0, function* () {
    // Generate a secure random string using the browser crypto functions
    const generateRandomString = () => {
        const array = new Uint32Array(28);
        crypto.getRandomValues(array);
        return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
    };
    // Calculate the SHA256 hash of the input text.
    // Returns a promise that resolves to an ArrayBuffer
    const sha256 = (plain) => {
        const encoder = new TextEncoder();
        const data = encoder.encode(plain);
        return crypto.subtle.digest('SHA-256', data);
    };
    // Base64-urlencodes the input string
    const base64urlencode = (str) => {
        // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
        // btoa accepts chars only within ascii 0-255 and base64 encodes them.
        // Then convert the base64 encoded to base64url encoded
        //   (replace + with -, replace / with _, trim trailing =)
        return btoa(String.fromCharCode.apply(null, [...new Uint8Array(str)]))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    // Return the base64-urlencoded sha256 hash for the PKCE challenge
    function pkceChallengeFromVerifier(v) {
        return __awaiter(this, void 0, void 0, function* () {
            const hashed = yield sha256(v);
            return base64urlencode(hashed);
        });
    }
    const { state, codeVerifier } = {
        state: generateRandomString(),
        codeVerifier: generateRandomString(),
    };
    const codeChallenge = yield pkceChallengeFromVerifier(codeVerifier);
    return {
        state,
        codeVerifier,
        codeChallenge,
    };
});
exports.generatePkceChallenge = generatePkceChallenge;
const isTokenExpired = (token) => {
    let isJwtExpired = false;
    const { exp } = (0, jwt_decode_1.jwtDecode)(token);
    const currentTime = new Date().getTime() / 1000;
    if (exp) {
        if (currentTime > exp)
            isJwtExpired = true;
    }
    return isJwtExpired;
};
exports.isTokenExpired = isTokenExpired;
const passwordIsStrongEnough = (password, allowNull = false) => {
    const message = 'Entered password is too weak';
    if (password === '' && allowNull)
        return true;
    if (password.length < 8)
        return message;
    if (!(/[A-Z]/.test(password)))
        return message;
    if (!(/[a-z]/.test(password)))
        return message;
    if (!(/\d/.test(password)))
        return message;
    return true;
};
exports.passwordIsStrongEnough = passwordIsStrongEnough;
const noLogin = () => {
    throw new Error("You're not logged in. Please use the 'login' command.");
};
exports.noLogin = noLogin;
const setTokens = (tokens) => {
    localStorage.setItem('accessToken', tokens.accessToken);
    localStorage.setItem('refreshToken', tokens.refreshToken);
};
exports.setTokens = setTokens;
const setOptions = (options) => {
    if (options.clientId)
        localStorage.setItem('clientId', options.clientId);
    if (options.host)
        localStorage.setItem('host', options.host);
    if (options.redirectUri)
        localStorage.setItem('redirectUri', options.redirectUri);
};
exports.setOptions = setOptions;
const isLogin = (gc2) => __awaiter(void 0, void 0, void 0, function* () {
    const accessToken = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    if (!accessToken) {
        return false;
    }
    if (accessToken && (0, exports.isTokenExpired)(accessToken)) {
        if (refreshToken && (0, exports.isTokenExpired)(refreshToken)) {
            console.error('⚠️ Refresh token has expired. Please login again');
            return false;
        }
        if (refreshToken) {
            try {
                const data = yield gc2.getRefreshToken(refreshToken);
                (0, exports.setTokens)({ accessToken: data.access_token, refreshToken: data.refresh_token });
            }
            catch (e) {
                console.error('⚠️ Could not get refresh token');
                return false;
            }
        }
    }
    return true;
});
exports.isLogin = isLogin;
const getTokens = () => {
    return {
        accessToken: localStorage.getItem('accessToken') || '',
        refreshToken: localStorage.getItem('refreshToken') || '',
    };
};
exports.getTokens = getTokens;
const getOptions = () => {
    return {
        clientId: localStorage.getItem('clientId') || '',
        host: localStorage.getItem('host') || '',
        redirectUri: localStorage.getItem('redirectUri') || '',
    };
};
exports.getOptions = getOptions;
