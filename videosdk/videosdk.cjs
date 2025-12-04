'use strict';

var node_crypto = require('node:crypto');
var node_http = require('node:http');
var node_https = require('node:https');
var axios = require('axios');
var dayjs = require('dayjs');
var node_buffer = require('node:buffer');
var jose = require('jose');
var FormData = require('form-data');
var os = require('node:os');
var node_path = require('node:path');

/**
 * Guard if an object implements the {@link StateStore} interface — most notably,
 * `generateState()` and `verifyState(state: string)`.
 */
const isStateStore = (obj) => typeof obj.generateState === "function" && typeof obj.verifyState === "function";

const createRivetErrors = (errors) => ({
    createError: (errorCode) => class extends Error {
        errorCode = errors[errorCode];
        constructor(message, options) {
            const errorMessage = (message ??
                (options?.cause instanceof Error ? options.cause.message : errorCode));
            super(errorMessage, options);
            this.name = errorCode;
            Object.setPrototypeOf(this, new.target.prototype);
        }
    },
    isError: (obj, key) => key ?
        Object.keys(errors).some((code) => code === key) &&
            typeof obj.errorCode === "string" &&
            obj.errorCode === errors[key]
        : typeof obj.errorCode === "string"
});

const coreErrors = {
    ApiResponseError: "zoom_rivet_api_response_error",
    AwsReceiverRequestError: "zoom_rivet_aws_receiver_request_error",
    ClientCredentialsRawResponseError: "zoom_rivet_client_credentials_raw_response_error",
    S2SRawResponseError: "zoom_rivet_s2s_raw_response_error",
    CommonHttpRequestError: "zoom_rivet_common_http_request_error",
    ReceiverInconsistentStateError: "zoom_rivet_receiver_inconsistent_state_error",
    ReceiverOAuthFlowError: "zoom_rivet_receiver_oauth_flow_error",
    HTTPReceiverConstructionError: "zoom_rivet_http_receiver_construction_error",
    HTTPReceiverPortNotNumberError: "zoom_rivet_http_receiver_port_not_number_error",
    HTTPReceiverRequestError: "zoom_rivet_http_receiver_request_error",
    OAuthInstallerNotInitializedError: "zoom_rivet_oauth_installer_not_initialized_error",
    OAuthTokenDoesNotExistError: "zoom_rivet_oauth_does_not_exist_error",
    OAuthTokenFetchFailedError: "zoom_rivet_oauth_token_fetch_failed_error",
    OAuthTokenRawResponseError: "zoom_rivet_oauth_token_raw_response_error",
    OAuthTokenRefreshFailedError: "zoom_rivet_oauth_token_refresh_failed_error",
    OAuthStateVerificationFailedError: "zoom_rivet_oauth_state_verification_failed_error",
    ProductClientConstructionError: "zoom_rivet_product_client_construction_error"
};
const { createError: createCoreError, isError: isCoreError } = createRivetErrors(coreErrors);
const ApiResponseError = createCoreError("ApiResponseError");
const AwsReceiverRequestError = createCoreError("AwsReceiverRequestError");
const ClientCredentialsRawResponseError = createCoreError("ClientCredentialsRawResponseError");
const S2SRawResponseError = createCoreError("S2SRawResponseError");
const CommonHttpRequestError = createCoreError("CommonHttpRequestError");
const ReceiverInconsistentStateError = createCoreError("ReceiverInconsistentStateError");
const ReceiverOAuthFlowError = createCoreError("ReceiverOAuthFlowError");
const HTTPReceiverConstructionError = createCoreError("HTTPReceiverConstructionError");
const HTTPReceiverPortNotNumberError = createCoreError("HTTPReceiverPortNotNumberError");
const HTTPReceiverRequestError = createCoreError("HTTPReceiverRequestError");
const OAuthInstallerNotInitializedError = createCoreError("OAuthInstallerNotInitializedError");
const OAuthTokenDoesNotExistError = createCoreError("OAuthTokenDoesNotExistError");
const OAuthTokenFetchFailedError = createCoreError("OAuthTokenFetchFailedError");
const OAuthTokenRawResponseError = createCoreError("OAuthTokenRawResponseError");
const OAuthTokenRefreshFailedError = createCoreError("OAuthTokenRefreshFailedError");
const OAuthStateVerificationFailedError = createCoreError("OAuthStateVerificationFailedError");
const ProductClientConstructionError = createCoreError("ProductClientConstructionError");

exports.LogLevel = void 0;
(function (LogLevel) {
    LogLevel["ERROR"] = "error";
    LogLevel["WARN"] = "warn";
    LogLevel["INFO"] = "info";
    LogLevel["DEBUG"] = "debug";
})(exports.LogLevel || (exports.LogLevel = {}));
class ConsoleLogger {
    level;
    name;
    static labels = (() => {
        const entries = Object.entries(exports.LogLevel);
        const map = entries.map(([key, value]) => [value, `[${key}] `]);
        return new Map(map);
    })();
    static severity = {
        [exports.LogLevel.ERROR]: 400,
        [exports.LogLevel.WARN]: 300,
        [exports.LogLevel.INFO]: 200,
        [exports.LogLevel.DEBUG]: 100
    };
    constructor() {
        this.level = exports.LogLevel.INFO;
        this.name = "";
    }
    getLevel() {
        return this.level;
    }
    setLevel(level) {
        this.level = level;
    }
    setName(name) {
        this.name = name;
    }
    debug(...msg) {
        if (ConsoleLogger.isMoreOrEqualSevere(exports.LogLevel.DEBUG, this.level)) {
            console.debug(ConsoleLogger.labels.get(exports.LogLevel.DEBUG), this.name, ...msg);
        }
    }
    info(...msg) {
        if (ConsoleLogger.isMoreOrEqualSevere(exports.LogLevel.INFO, this.level)) {
            console.info(ConsoleLogger.labels.get(exports.LogLevel.INFO), this.name, ...msg);
        }
    }
    warn(...msg) {
        if (ConsoleLogger.isMoreOrEqualSevere(exports.LogLevel.WARN, this.level)) {
            console.warn(ConsoleLogger.labels.get(exports.LogLevel.WARN), this.name, ...msg);
        }
    }
    error(...msg) {
        if (ConsoleLogger.isMoreOrEqualSevere(exports.LogLevel.ERROR, this.level)) {
            console.error(ConsoleLogger.labels.get(exports.LogLevel.ERROR), this.name, ...msg);
        }
    }
    static isMoreOrEqualSevere(a, b) {
        return ConsoleLogger.severity[a] >= ConsoleLogger.severity[b];
    }
}

class EventManager {
    endpoints;
    /** @internal */
    listeners;
    constructor(endpoints) {
        this.endpoints = endpoints;
        this.listeners = {};
    }
    appendListener(eventName, predicate, listener) {
        if (this.listeners[eventName]) {
            this.listeners[eventName].push({ predicate, listener });
        }
        else {
            this.listeners[eventName] = [{ predicate, listener }];
        }
    }
    filteredEvent(eventName, predicate, listener) {
        if (typeof predicate !== "function" || typeof listener !== "function") {
            throw new Error("Event predicate and listener must be of type function.");
        }
        this.appendListener(eventName, predicate, listener);
    }
    async emit(eventName, payload) {
        if (!this.listeners[eventName])
            return;
        await Promise.all(this.listeners[eventName].map(async ({ predicate, listener }) => {
            if (typeof predicate !== "undefined" && !predicate(payload))
                return;
            await Promise.resolve(listener(payload));
        }));
    }
    event(eventName, listener) {
        if (typeof listener !== "function") {
            throw new Error("Event listener must be of type function.");
        }
        this.appendListener(eventName, undefined, listener);
    }
    withContext() {
        throw new Error("Method not implemented. Only to be used for type.");
    }
}

/** @internal */
const hashUrlValidationEvent = ({ payload: { plainToken } }, webhooksSecretToken) => ({
    encryptedToken: node_crypto.createHmac("sha256", webhooksSecretToken).update(plainToken).digest("hex"),
    plainToken
});
const isHashedUrlValidation = (obj) => typeof obj.encryptedToken === "string" &&
    typeof obj.plainToken === "string";
const isRawUrlValidationEvent = (obj) => obj.event === "endpoint.url_validation" && typeof obj.payload.plainToken === "string";
const isSkeletonEvent = (obj) => typeof obj.event === "string";
class CommonHttpRequest {
    headers;
    payload;
    webhooksSecretToken;
    constructor(headers, payload, webhooksSecretToken) {
        this.headers = headers;
        this.payload = payload;
        this.webhooksSecretToken = webhooksSecretToken;
    }
    static buildFromAwsEvent({ body, headers, isBase64Encoded }, webhooksSecretToken) {
        try {
            const rawBody = body ?? "";
            const decodedBody = isBase64Encoded ? Buffer.from(rawBody, "base64").toString("ascii") : rawBody;
            const payload = JSON.parse(decodedBody);
            return new CommonHttpRequest(headers, payload, webhooksSecretToken);
        }
        catch (err) {
            throw err instanceof SyntaxError ?
                new CommonHttpRequestError("Failed to parse payload string to JSON.", err)
                : err;
        }
    }
    static async buildFromIncomingMessage(incomingMessage, webhooksSecretToken) {
        const bufferAsString = () => {
            return new Promise((resolve, reject) => {
                const body = [];
                incomingMessage.on("data", (chunk) => body.push(chunk));
                incomingMessage.on("error", (err) => {
                    reject(err);
                });
                incomingMessage.on("end", () => {
                    resolve(Buffer.concat(body).toString());
                });
            });
        };
        try {
            const payload = JSON.parse(await bufferAsString());
            return new CommonHttpRequest(incomingMessage.headers, payload, webhooksSecretToken);
        }
        catch (err) {
            if (err instanceof SyntaxError) {
                throw new CommonHttpRequestError("Failed to parse payload string to JSON.", err);
            }
            throw err;
        }
    }
    isEventVerified() {
        const { signature, requestTimestamp } = this.parseHeaders();
        const messageToVerify = `v0:${requestTimestamp.toString()}:${JSON.stringify(this.payload)}`;
        const hashToVerify = node_crypto.createHmac("sha256", this.webhooksSecretToken).update(messageToVerify).digest("hex");
        const signatureToVerify = `v0=${hashToVerify}`;
        return signatureToVerify === signature;
    }
    parseHeaders() {
        const findHeader = (header) => {
            const foundHeader = Object.keys(this.headers).find((key) => key.toLowerCase() === header.toLowerCase());
            return foundHeader && this.headers[foundHeader];
        };
        const headerSignature = findHeader("x-zm-signature");
        const headerRequestTimestamp = findHeader("x-zm-request-timestamp");
        if (!headerSignature && !headerRequestTimestamp) {
            throw new CommonHttpRequestError("Request payload must have signature and request timestamp from Zoom.");
        }
        return {
            signature: headerSignature,
            requestTimestamp: Number(headerRequestTimestamp)
        };
    }
    processEvent() {
        if (!isSkeletonEvent(this.payload)) {
            throw new CommonHttpRequestError("Request payload structure does not match expected from Zoom.");
        }
        if (!this.isEventVerified()) {
            throw new CommonHttpRequestError("Failed to verify event originated from Zoom.");
        }
        if (isRawUrlValidationEvent(this.payload)) {
            return hashUrlValidationEvent(this.payload, this.webhooksSecretToken);
        }
        return this.payload;
    }
}

exports.StatusCode = void 0;
(function (StatusCode) {
    StatusCode[StatusCode["OK"] = 200] = "OK";
    StatusCode[StatusCode["TEMPORARY_REDIRECT"] = 302] = "TEMPORARY_REDIRECT";
    StatusCode[StatusCode["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    StatusCode[StatusCode["NOT_FOUND"] = 404] = "NOT_FOUND";
    StatusCode[StatusCode["METHOD_NOT_ALLOWED"] = 405] = "METHOD_NOT_ALLOWED";
    StatusCode[StatusCode["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
})(exports.StatusCode || (exports.StatusCode = {}));

class AwsLambdaReceiver {
    eventEmitter;
    webhooksSecretToken;
    constructor({ webhooksSecretToken }) {
        this.webhooksSecretToken = webhooksSecretToken;
    }
    buildResponse(statusCode, body) {
        return {
            body: JSON.stringify(body),
            headers: { "Content-Type": "application/json" },
            statusCode
        };
    }
    canInstall() {
        return false;
    }
    init({ eventEmitter }) {
        this.eventEmitter = eventEmitter;
    }
    start() {
        return async (event, context) => {
            console.debug("Processing Lambda event ", JSON.stringify(event), " with context ", JSON.stringify(context));
            try {
                const request = CommonHttpRequest.buildFromAwsEvent(event, this.webhooksSecretToken);
                const processedEvent = request.processEvent();
                if (isHashedUrlValidation(processedEvent)) {
                    return this.buildResponse(exports.StatusCode.OK, processedEvent);
                }
                else {
                    await this.eventEmitter?.emit(processedEvent.event, processedEvent);
                    return this.buildResponse(exports.StatusCode.OK, { message: "Zoom event processed successfully." });
                }
            }
            catch (err) {
                if (isCoreError(err, "CommonHttpRequestError")) {
                    return this.buildResponse(exports.StatusCode.BAD_REQUEST, { error: err.message });
                }
                else {
                    console.error(err);
                    return this.buildResponse(exports.StatusCode.INTERNAL_SERVER_ERROR, {
                        error: "An unknown error occurred. Please try again later."
                    });
                }
            }
        };
    }
    async stop() {
        return Promise.resolve();
    }
}

const prependSlashes = (strs) => {
    const rawStrs = Array.isArray(strs) ? strs : [strs];
    const mappedStrs = rawStrs.map((rawStr) => (rawStr.startsWith("/") ? rawStr : `/${rawStr}`));
    return (Array.isArray(strs) ? mappedStrs : mappedStrs[0]);
};

class TokenMemoryStore {
    currentToken;
    getLatestToken() {
        return this.currentToken;
    }
    storeToken(token) {
        this.currentToken = token;
    }
}

/** @internal */
const EXPIRATION_DELTA_SECONDS = 60;
/** @internal */
const OAUTH_BASE_URL = "https://zoom.us";
/** @internal */
const OAUTH_TOKEN_PATH = "/oauth/token";
/**
 * {@link Auth} is the base implementation of authentication for Zoom's APIs.
 *
 * It only requires a `clientId` and `tokenStore`, as these options are shared across
 * all authentication implementations, namely OAuth and server-to-server auth (client
 * credentials, JWT, and server-to-server OAuth.)
 */
class Auth {
    clientId;
    clientSecret;
    tokenStore;
    logger;
    constructor({ clientId, clientSecret, tokenStore, logger }) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenStore = tokenStore ?? new TokenMemoryStore();
        this.logger = logger;
    }
    getBasicAuthorization() {
        const clientCredentials = `${this.clientId}:${this.clientSecret}`;
        return node_buffer.Buffer.from(clientCredentials).toString("base64");
    }
    isAlmostExpired(isoTime) {
        const currentDate = dayjs();
        return dayjs(isoTime).diff(currentDate, "seconds") <= EXPIRATION_DELTA_SECONDS;
    }
    async makeOAuthTokenRequest(grantType, payload) {
        return await axios({
            method: "POST",
            url: new URL(OAUTH_TOKEN_PATH, OAUTH_BASE_URL).toString(),
            headers: {
                Authorization: `Basic ${this.getBasicAuthorization()}`,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data: new URLSearchParams({ grant_type: grantType, ...payload }),
            validateStatus: (status) => status >= 200 && status <= 299
        });
    }
}

const DEFAULT_EXPIRATION_SECONDS = 300; // 5 minutes
/** @internal */
const ISSUER_URN = "urn:zoom:rivet-sdk";
class JwtStateStore {
    encodedSecret;
    expirationSeconds;
    constructor({ expirationSeconds, stateSecret }) {
        this.encodedSecret = new TextEncoder().encode(stateSecret);
        this.expirationSeconds = expirationSeconds ?? DEFAULT_EXPIRATION_SECONDS;
    }
    async generateState() {
        const issuedTime = dayjs();
        const expirationTime = issuedTime.add(this.expirationSeconds, "seconds");
        return await new jose.SignJWT({ random: node_crypto.randomBytes(8).toString("hex") })
            .setProtectedHeader({ alg: "HS256", typ: "JWT" })
            .setExpirationTime(expirationTime.toDate())
            .setIssuedAt(issuedTime.toDate())
            .setIssuer(ISSUER_URN)
            .sign(this.encodedSecret);
    }
    async verifyState(state) {
        try {
            await jose.jwtVerify(state, this.encodedSecret, {
                algorithms: ["HS256"],
                issuer: ISSUER_URN,
                typ: "JWT"
            });
        }
        catch (err) {
            throw new OAuthStateVerificationFailedError(`Failed to verify OAuth state: ${err.name}.`, {
                cause: err
            });
        }
    }
}

const DEFAULT_INSTALL_PATH = "/zoom/oauth/install";
const DEFAULT_CALLBACK_PATH = "/zoom/oauth/callback";
const DEFAULT_STATE_COOKIE_NAME = "zoom-oauth-state";
const DEFAULT_STATE_COOKIE_MAX_AGE = 600; // 10 minutes in seconds
const MAXIMUM_STATE_MAX_AGE = 3600; // 1 hour in seconds
const OAUTH_AUTHORIZE_PATH = "/oauth/authorize";
/**
 * {@link InteractiveAuth}, an extension of {@link Auth}, is designed for use cases where authentication
 * is initiated server-side, but requires manual authorization from a user, by redirecting the user to Zoom.
 *
 * In addition to all required fields from {@link AuthOptions}, this class requires a `redirectUri`, as this
 * value is appended to the authorization URL when the user is redirected to Zoom and subsequently redirected
 * back to an endpoint on this server.
 *
 * @see {@link https://developers.zoom.us/docs/integrations/oauth/ | OAuth - Zoom Developers}
 */
class InteractiveAuth extends Auth {
    installerOptions;
    async getAuthorizationUrl() {
        if (!this.installerOptions?.stateStore) {
            throw new OAuthInstallerNotInitializedError("Cannot generate authorization URL, state store not initialized.");
        }
        const authUrl = new URL(OAUTH_AUTHORIZE_PATH, OAUTH_BASE_URL);
        const generatedState = await Promise.resolve(this.installerOptions.stateStore.generateState());
        const { searchParams } = authUrl;
        searchParams.set("client_id", this.clientId);
        searchParams.set("redirect_uri", this.getFullRedirectUri());
        searchParams.set("response_type", "code");
        searchParams.set("state", generatedState);
        return {
            fullUrl: authUrl.toString(),
            generatedState
        };
    }
    getFullRedirectUri() {
        if (!this.installerOptions?.redirectUri || !this.installerOptions.redirectUriPath) {
            throw new OAuthInstallerNotInitializedError("Cannot generate full redirect URI, redirect URI or redirect URI path not initialized.");
        }
        return new URL(this.installerOptions.redirectUriPath, this.installerOptions.redirectUri).toString();
    }
    // Don't return a type; we want it to be as narrow as possible (used for ReturnType).
    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    setInstallerOptions({ directInstall, installPath, redirectUri, redirectUriPath, stateStore, stateCookieName, stateCookieMaxAge }) {
        const updatedOptions = {
            directInstall: Boolean(directInstall),
            installPath: installPath ? prependSlashes(installPath) : DEFAULT_INSTALL_PATH,
            redirectUri,
            redirectUriPath: redirectUriPath ? prependSlashes(redirectUriPath) : DEFAULT_CALLBACK_PATH,
            stateStore: isStateStore(stateStore) ? stateStore : new JwtStateStore({ stateSecret: stateStore }),
            stateCookieName: stateCookieName ?? DEFAULT_STATE_COOKIE_NAME,
            stateCookieMaxAge: stateCookieMaxAge ?? DEFAULT_STATE_COOKIE_MAX_AGE
        };
        if (updatedOptions.stateCookieMaxAge > MAXIMUM_STATE_MAX_AGE) {
            // This method is always called from ProductClient, so this should be fine.
            throw new ProductClientConstructionError(`stateCookieMaxAge cannot be greater than ${MAXIMUM_STATE_MAX_AGE.toString()} seconds.`);
        }
        this.installerOptions = updatedOptions;
        return updatedOptions;
    }
}

const mergeDefaultOptions = (options, defaultOptions) => ({ ...defaultOptions, ...options });

const withDefaultTemplate = (cardContent, buttonContent) => `
<html lang="en">
<head>
  <title>Zoom Rivet</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>

<body>
  <div class="flex items-center justify-center min-h-screen bg-[#F4F9FF] bg-opacity-50">
    <div class="rounded-lg border bg-card w-full max-w-md mx-4 shadow-lg">
      <div class="flex flex-col p-6 space-y-1">
        <h3 class="whitespace-nowrap tracking-tight text-3xl font-bold text-center text-[#006EF0]">
          Zoom Rivet
        </h3>
      </div>
      <div class="p-6 space-y-4">
        ${cardContent}
      </div>
      ${buttonContent ?
    `<div class="items-center p-6 flex justify-center">
            <a href="${buttonContent.href}">
              <button class="inline-flex items-center justify-center whitespace-nowrap font-medium ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 h-11 rounded-md text-lg px-8 py-6 bg-[#006EF0] hover:bg-[#2681F2] text-white transition-all duration-300 ease-in-out transform scale-100">
                ${buttonContent.text}
              </button>
            </a>
          </div>`
    : ""}
      </div>
  </div>
</body>
</html>
`;
/**
 * Get the default HTML template that is shown to the developer/user when they visit the
 * `installPath` endpoint, if Rivet currently has OAuth enabled.
 *
 * If `directInstall` is set to `true`, this function is not called; instead, the developer
 * is directly redirected to Zoom's OAuth page.
 */
const defaultInstallTemplate = (authUrl) => withDefaultTemplate(`<p class="text-sm text-gray-600 text-center">Click the button below to navigate to Zoom to authorize your application for use with Rivet.</p>`, { href: authUrl, text: "Authorize with Zoom" });
/**
 * Get the default HTML template that is shown to the developer/user when they successfully
 * authorize Rivet with a Zoom application. This is shown once they have already been redirected
 * to Zoom, and the authorization attempt with Rivet was successful.
 */
const defaultCallbackSuccessTemplate = () => withDefaultTemplate(`<p class="text-sm text-gray-600 text-center">Your application has been successfully authorized with Rivet!</p>
     <p class="text-sm text-gray-600 text-center">You may now close this page, or click the button below to redirect to Zoom's Marketplace.</p>`, { href: "https://marketplace.zoom.us", text: "Go to Marketplace" });
/**
 * Get the default HTML template that is shown to the developer when a known error occurs, meaning
 * that the error is a core Rivet error.
 */
const defaultCallbackKnownErrorTemplate = (errName, errMessage) => withDefaultTemplate(`<p class="text-sm text-gray-600 text-center">An error occurred authorizing Rivet with Zoom.</p>
     <p class="text-sm text-gray-600 text-center">[${errName}]: ${errMessage}</p>`);
/**
 * Get the default HTML template that is shown to the developer when an unknown error occurs,
 * meaning that the error is not known to be a core Rivet error and was thrown and not wrapped elsewhere.
 */
const defaultCallbackUnknownErrorTemplate = () => withDefaultTemplate(`<p class="text-sm text-gray-600 text-center">An unknown error occurred authorizing Rivet with Zoom. Please see stacktrace for details.</p>
     <p class="text-sm text-gray-600 text-center">Please see stacktrace for further details.</p>`);

const secureServerOptionKeys = [
    "ALPNProtocols",
    "clientCertEngine",
    "enableTrace",
    "handshakeTimeout",
    "rejectUnauthorized",
    "requestCert",
    "sessionTimeout",
    "SNICallback",
    "ticketKeys",
    "pskCallback",
    "pskIdentityHint",
    "ca",
    "cert",
    "sigalgs",
    "ciphers",
    "clientCertEngine",
    "crl",
    "dhparam",
    "ecdhCurve",
    "honorCipherOrder",
    "key",
    "privateKeyEngine",
    "privateKeyIdentifier",
    "maxVersion",
    "minVersion",
    "passphrase",
    "pfx",
    "secureOptions",
    "secureProtocol",
    "sessionIdContext"
];
class HttpReceiver {
    /** @internal */
    static DEFAULT_ENDPOINT = "/zoom/events";
    eventEmitter;
    interactiveAuth;
    /** @internal */
    options;
    server;
    logger;
    constructor(options) {
        this.options = mergeDefaultOptions(options, { endpoints: HttpReceiver.DEFAULT_ENDPOINT });
        this.options.endpoints = prependSlashes(this.options.endpoints);
        this.logger =
            options.logger ??
                (() => {
                    const defaultLogger = new ConsoleLogger();
                    defaultLogger.setLevel(options.logLevel ?? exports.LogLevel.ERROR);
                    return defaultLogger;
                })();
    }
    canInstall() {
        return true;
    }
    buildDeletedStateCookieHeader(name) {
        return `${name}=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; Secure;`;
    }
    buildStateCookieHeader(name, value, maxAge) {
        return `${name}=${value}; HttpOnly; Max-Age=${maxAge.toString()}; Path=/; Secure;`;
    }
    getRequestCookie(req, name) {
        return req.headers.cookie
            ?.split(";")
            .find((cookie) => cookie.trim().startsWith(name))
            ?.split("=")[1]
            ?.trim();
    }
    getServerCreator() {
        return this.hasSecureOptions() ? node_https.createServer : node_http.createServer;
    }
    hasEndpoint(pathname) {
        const { endpoints } = this.options;
        return Array.isArray(endpoints) ? endpoints.includes(pathname) : endpoints === pathname;
    }
    hasSecureOptions() {
        return Object.keys(this.options).some((option) => secureServerOptionKeys.includes(option));
    }
    init({ eventEmitter, interactiveAuth }) {
        this.eventEmitter = eventEmitter;
        this.interactiveAuth = interactiveAuth;
    }
    setResponseCookie(res, cookie) {
        const existingCookies = res.getHeader("Set-Cookie") ?? [];
        const cookiesArray = Array.isArray(existingCookies) ? existingCookies
            : typeof existingCookies === "string" ? [existingCookies]
                : [existingCookies.toString()];
        res.setHeader("Set-Cookie", [...cookiesArray, cookie]);
    }
    areNormalizedUrlsEqual(firstUrl, secondUrl) {
        const normalizedFirstUrl = firstUrl.endsWith("/") ? firstUrl.slice(0, -1) : firstUrl;
        const normalizedSecondUrl = secondUrl.endsWith("/") ? secondUrl.slice(0, -1) : secondUrl;
        return normalizedFirstUrl == normalizedSecondUrl;
    }
    start(port) {
        if (typeof port !== "number" && isNaN(Number(port)) && !this.options.port && this.options.port !== 0) {
            const errorMessage = "HTTP receiver must have number-coercible port found in constructor option or method call.";
            this.logger.error(errorMessage);
            throw new HTTPReceiverPortNotNumberError(errorMessage);
        }
        const listenPort = port ?? this.options.port;
        return new Promise((resolve, reject) => {
            this.server = this.getServerCreator()(this.options, (req, res) => void (async () => {
                // `req.headers.host` should be used with care, as clients can manipulate this value.
                // However, for this use case, the value is completely discarded and only `pathname`
                // is used, which is why there's no further validation occurring.
                const { pathname, searchParams } = new URL(req.url ?? "", `http://${req.headers.host ?? "localhost"}`);
                const { interactiveAuth } = this;
                this.logger.debug([pathname, searchParams]);
                // Handle interactive OAuth flow, if user is going to installPath or redirectUriPath
                if (interactiveAuth && interactiveAuth instanceof InteractiveAuth && interactiveAuth.installerOptions) {
                    const { installerOptions } = interactiveAuth;
                    if (this.areNormalizedUrlsEqual(pathname, installerOptions.installPath)) {
                        const { fullUrl, generatedState } = await interactiveAuth.getAuthorizationUrl();
                        const stateCookie = this.buildStateCookieHeader(installerOptions.stateCookieName, generatedState, installerOptions.stateCookieMaxAge);
                        await (installerOptions.directInstall ?
                            this.writeTemporaryRedirect(res, fullUrl, stateCookie)
                            : this.writeResponse(res, exports.StatusCode.OK, defaultInstallTemplate(fullUrl), stateCookie));
                        return;
                    }
                    // The user has navigated to the redirect page; init the code
                    if (this.areNormalizedUrlsEqual(pathname, installerOptions.redirectUriPath)) {
                        const authCodeParam = searchParams.get("code");
                        const stateCodeParam = searchParams.get("state");
                        const stateCodeCookie = this.getRequestCookie(req, installerOptions.stateCookieName);
                        try {
                            // Can't proceed if no auth code or state code in search parameters
                            if (!authCodeParam || !stateCodeParam) {
                                const errorMessage = "OAuth callback did not include code and/or state in request.";
                                this.logger.error(errorMessage);
                                throw new ReceiverOAuthFlowError(errorMessage);
                            }
                            // Ensure that the state token is verified, according to our state store
                            await installerOptions.stateStore.verifyState(stateCodeParam);
                            // Ensure that the state token we received (in search parameters) IS THE SAME as the state cookie
                            if (!stateCodeCookie || stateCodeCookie !== stateCodeParam) {
                                const errorMessage = "The state parameter is not from this browser session.";
                                this.logger.error(errorMessage);
                                throw new ReceiverOAuthFlowError(errorMessage);
                            }
                            await interactiveAuth.initRedirectCode(authCodeParam);
                            const deletionStateCookie = this.buildDeletedStateCookieHeader(installerOptions.stateCookieName);
                            await this.writeResponse(res, exports.StatusCode.OK, defaultCallbackSuccessTemplate(), deletionStateCookie);
                            return;
                        }
                        catch (err) {
                            const htmlTemplate = isCoreError(err) ?
                                defaultCallbackKnownErrorTemplate(err.name, err.message)
                                : defaultCallbackUnknownErrorTemplate();
                            const deletionStateCookie = this.buildDeletedStateCookieHeader(installerOptions.stateCookieName);
                            await this.writeResponse(res, exports.StatusCode.INTERNAL_SERVER_ERROR, htmlTemplate, deletionStateCookie);
                            return;
                        }
                    }
                }
                // This section is only applicable if we have a webhooks secret token—if we don't, then this
                // receiver is, in effect, just for OAuth usage, meaning installing and validating.
                if (this.options.webhooksSecretToken) {
                    // We currently only support a single endpoint, though this will change in the future.
                    if (!this.hasEndpoint(pathname)) {
                        await this.writeResponse(res, exports.StatusCode.NOT_FOUND);
                        return;
                    }
                    // We currently only support POST requests, as that's what Zoom sends.
                    if (req.method !== "post" && req.method !== "POST") {
                        await this.writeResponse(res, exports.StatusCode.METHOD_NOT_ALLOWED);
                        return;
                    }
                    try {
                        const { webhooksSecretToken } = this.options;
                        const request = await CommonHttpRequest.buildFromIncomingMessage(req, webhooksSecretToken);
                        const processedEvent = request.processEvent();
                        if (isHashedUrlValidation(processedEvent)) {
                            await this.writeResponse(res, exports.StatusCode.OK, processedEvent);
                        }
                        else {
                            await this.eventEmitter?.emit(processedEvent.event, processedEvent);
                            await this.writeResponse(res, exports.StatusCode.OK, { message: "Zoom event processed successfully." });
                        }
                    }
                    catch (err) {
                        if (isCoreError(err, "CommonHttpRequestError")) {
                            await this.writeResponse(res, exports.StatusCode.BAD_REQUEST, { error: err.message });
                        }
                        else {
                            console.error(err);
                            await this.writeResponse(res, exports.StatusCode.INTERNAL_SERVER_ERROR, {
                                error: "An unknown error occurred. Please try again later."
                            });
                        }
                    }
                }
            })());
            this.server.on("close", () => (this.server = undefined));
            this.server.on("error", (err) => {
                this.logger.error(err.message);
                reject(err);
            });
            this.server.listen(listenPort, () => {
                if (!this.server) {
                    throw new ReceiverInconsistentStateError();
                }
                const { port: listeningPort } = this.server.address();
                this.logger.info(`Listening on port ${listeningPort.toString()}`);
                resolve(this.server);
            });
        });
    }
    stop() {
        if (!this.server) {
            throw new ReceiverInconsistentStateError();
        }
        return new Promise((resolve, reject) => {
            this.server?.close((err) => {
                if (err) {
                    this.logger.error(err.message);
                    reject(err);
                }
            });
            this.server = undefined;
            resolve();
        });
    }
    writeTemporaryRedirect(res, location, setCookie) {
        return new Promise((resolve) => {
            if (setCookie) {
                this.setResponseCookie(res, setCookie);
            }
            res.writeHead(exports.StatusCode.TEMPORARY_REDIRECT, { Location: location });
            res.end(() => {
                resolve();
            });
        });
    }
    writeResponse(res, statusCode, bodyContent, setCookie) {
        return new Promise((resolve) => {
            const mimeType = typeof bodyContent === "object" ? "application/json" : "text/html";
            bodyContent = typeof bodyContent === "object" ? JSON.stringify(bodyContent) : bodyContent;
            if (setCookie) {
                this.setResponseCookie(res, setCookie);
            }
            res.writeHead(statusCode, { "Content-Type": mimeType });
            res.end(bodyContent, () => {
                resolve();
            });
        });
    }
}

/** @internal */
const TWO_HOURS_IN_SECONDS = 60 * 60 * 2;
class JwtAuth extends Auth {
    async generateToken() {
        const encodedSecret = new TextEncoder().encode(this.clientSecret);
        const issuedTime = dayjs();
        const expirationTime = issuedTime.add(TWO_HOURS_IN_SECONDS, "seconds");
        return {
            token: await new jose.SignJWT()
                .setProtectedHeader({ alg: "HS256", typ: "JWT" })
                .setExpirationTime(expirationTime.toDate())
                .setIssuedAt(issuedTime.toDate())
                .setIssuer(this.clientId)
                .sign(encodedSecret),
            expirationTimeIso: expirationTime.toISOString()
        };
    }
    async getToken() {
        const { tokenStore } = this;
        const currentToken = await Promise.resolve(tokenStore.getLatestToken());
        if (currentToken && !this.isAlmostExpired(currentToken.expirationTimeIso)) {
            return currentToken.token;
        }
        const jwtToken = await this.generateToken();
        await Promise.resolve(tokenStore.storeToken(jwtToken));
        return jwtToken.token;
    }
}

// Utility functions for determining if client options include custom receiver, or, if not,
// a webhooks secret token, as one of those is required!
const hasExplicitReceiver = (obj) => typeof obj.receiver !== "undefined";
const hasWebhooksSecretToken = (obj) => typeof obj.webhooksSecretToken !== "undefined";
const isReceiverDisabled = (options) => typeof options.disableReceiver !== "undefined" && options.disableReceiver;
const DEFAULT_HTTP_RECEIVER_PORT = 8080;
const DEFAULT_LOGLEVEL = exports.LogLevel.ERROR;
class ProductClient {
    auth;
    endpoints;
    webEventConsumer;
    receiver;
    constructor(options) {
        this.auth = this.initAuth(options);
        this.endpoints = this.initEndpoints(this.auth, options);
        this.webEventConsumer = this.initEventProcessor(this.endpoints, options);
        // Only create an instance of `this.receiver` if the developer did not explicitly disable it.
        if (!isReceiverDisabled(options)) {
            // Throw error if receiver enabled, but no explicit receiver or a webhooks secret token provided.
            // This is mainly applicable for products where we expect webhooks to be used; in events where webhooks are not
            // expected, then it's perfectly fine for the developer to not provide a receiver of a webhooks secret token.
            if (this.webEventConsumer && !hasExplicitReceiver(options) && !hasWebhooksSecretToken(options)) {
                throw new ProductClientConstructionError("Options must include a custom receiver, or a webhooks secret token.");
            }
            this.receiver = (hasExplicitReceiver(options) ?
                options.receiver
                : this.initDefaultReceiver(options));
            this.receiver.init({
                eventEmitter: this.webEventConsumer,
                interactiveAuth: this.auth instanceof InteractiveAuth ? this.auth : undefined
            });
        }
    }
    initDefaultReceiver({ port, webhooksSecretToken, logLevel }) {
        return new HttpReceiver({
            port: port ?? DEFAULT_HTTP_RECEIVER_PORT,
            webhooksSecretToken,
            logLevel: logLevel ?? DEFAULT_LOGLEVEL
        });
    }
    async start() {
        if (!this.receiver) {
            throw new ReceiverInconsistentStateError("Receiver failed to construct. Was disableReceiver set to true?");
        }
        // Method call is wrapped in `await` and `Promise.resolve()`, as the call
        // may or may not return a promise. This is not required when implementing `Receiver`.
        return (await Promise.resolve(this.receiver.start()));
    }
}

const version = "0.4.0";
var packageJson = {
  version: version};

// eslint-disable-next-line no-control-regex
const ASCII_CONTROL_CHARACTERS_PATTERN = /[\x00-\x1F\x7F]/;
const NON_ASCII_CHARACTERS_PATTERN = /[^\x20-\x7E]/;
class WebEndpoints {
    /** @internal */
    static DEFAULT_BASE_URL = "https://api.zoom.us/v2";
    /** @internal */
    static DEFAULT_MIME_TYPE = "application/json";
    /** @internal */
    static DEFAULT_TIMEOUT = 0;
    /** @internal */
    static GENERIC_ERROR_MESSAGE = "Request was unsuccessful with no further context";
    /** @internal */
    static TRACKING_ID_HEADER = "x-zm-trackingid";
    /** @internal */
    options;
    constructor(options) {
        this.options = mergeDefaultOptions(options, {
            baseUrl: WebEndpoints.DEFAULT_BASE_URL,
            hasCustomBaseUrl: typeof options.baseUrl !== "undefined",
            timeout: WebEndpoints.DEFAULT_TIMEOUT
        });
    }
    buildEndpoint({ method, baseUrlOverride, urlPathBuilder, requestMimeType }) {
        // @ts-expect-error: Some arguments may not be present, but we pass them to makeRequest() anyway.
        // prettier-ignore
        // Next AST node is ignored by Prettier, even though it exceed maximum line length, because TypeScript
        // won't allow ts-expect-error directive on multiple lines (https://github.com/Microsoft/TypeScript/issues/19573).
        return (async ({ path, body, query }) => await this.makeRequest(method, baseUrlOverride, urlPathBuilder(path), requestMimeType ?? WebEndpoints.DEFAULT_MIME_TYPE, body, query)).bind(this);
    }
    buildUserAgent() {
        const customUserAgentName = this.getCustomUserAgentName();
        const userAgent = `rivet/${packageJson.version}${customUserAgentName ? ` (${customUserAgentName})` : ""}`;
        return (`${userAgent} ` +
            `${node_path.basename(process.title)}/${process.version.replace("v", "")} ` +
            `${os.platform()}/${os.release()}`);
    }
    getCustomUserAgentName() {
        const { userAgentName } = this.options;
        if (!userAgentName || typeof userAgentName !== "string") {
            return null;
        }
        return userAgentName
            .replace(new RegExp(ASCII_CONTROL_CHARACTERS_PATTERN, "g"), "")
            .replace(new RegExp(NON_ASCII_CHARACTERS_PATTERN, "g"), "")
            .trim()
            .slice(0, 100);
    }
    getHeaders(bearerToken, contentType) {
        return {
            Accept: "application/json",
            Authorization: `Bearer ${bearerToken}`,
            "Content-Type": contentType,
            "User-Agent": this.buildUserAgent()
        };
    }
    getRequestBody(args, mimeType) {
        if (mimeType === "multipart/form-data") {
            const formData = new FormData();
            Object.entries(args).forEach(([key, value]) => {
                formData.append(key, value);
            });
            return formData;
        }
        return args;
    }
    isOk(response) {
        return response.status >= 200 && response.status <= 299;
    }
    isZoomResponseError(obj) {
        return (typeof obj.code !== "undefined" &&
            typeof obj.message !== "undefined");
    }
    async makeRequest(method, baseUrlOverride, url, requestContentType, bodyArgs, queryArgs) {
        const { auth, baseUrl, doubleEncodeUrl, hasCustomBaseUrl, timeout } = this.options;
        const bearerToken = await Promise.resolve(auth.getToken());
        const urlToSend = doubleEncodeUrl ? encodeURIComponent(encodeURIComponent(url)) : url;
        const response = await axios({
            url: urlToSend,
            method,
            baseURL: hasCustomBaseUrl ? baseUrl : (baseUrlOverride ?? baseUrl),
            headers: this.getHeaders(bearerToken, requestContentType),
            params: queryArgs,
            data: bodyArgs && this.getRequestBody(bodyArgs, requestContentType),
            timeout: timeout,
            beforeRedirect: (options) => {
                options.headers = {
                    ...this.getHeaders(bearerToken, requestContentType),
                    ...options.headers
                };
            },
            validateStatus: () => true // All responses are valid, not just 2xx
        });
        if (!this.isOk(response)) {
            const { status: statusCode } = response;
            if (this.isZoomResponseError(response.data)) {
                const { code: errorCode, message: errorMessage } = response.data;
                throw new ApiResponseError(`[${statusCode.toString()}/${errorCode.toString()}]: "${errorMessage}"`);
            }
            throw new ApiResponseError(`[${statusCode.toString()}]: ${WebEndpoints.GENERIC_ERROR_MESSAGE}`);
        }
        return {
            data: response.data,
            statusCode: response.status,
            trackingId: response.headers[WebEndpoints.TRACKING_ID_HEADER]
        };
    }
}

class VideoSdkEndpoints extends WebEndpoints {
    byosStorage = {
        updateBringYourOwnStorageSettings: this.buildEndpoint({ method: "PATCH", urlPathBuilder: () => `/videosdk/settings/storage` }),
        listStorageLocation: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/videosdk/settings/storage/location`
        }),
        addStorageLocation: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/videosdk/settings/storage/location` }),
        storageLocationDetail: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ storageLocationId }) => `/videosdk/settings/storage/location/${storageLocationId}`
        }),
        deleteStorageLocationDetail: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ storageLocationId }) => `/videosdk/settings/storage/location/${storageLocationId}`
        }),
        changeStorageLocationDetail: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ storageLocationId }) => `/videosdk/settings/storage/location/${storageLocationId}`
        })
    };
    cloudRecording = {
        listRecordingsOfAccount: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/videosdk/recordings` }),
        listSessionsRecordings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/recordings` }),
        deleteSessionsRecordings: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/recordings` }),
        recoverSessionsRecordings: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/recordings/status` }),
        deleteSessionsRecordingFile: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ sessionId, recordingId }) => `/videosdk/sessions/${sessionId}/recordings/${recordingId}`
        }),
        recoverSingleRecording: this.buildEndpoint({
            method: "PUT",
            urlPathBuilder: ({ sessionId, recordingId }) => `/videosdk/sessions/${sessionId}/recordings/${recordingId}/status`
        })
    };
    sessions = {
        listSessions: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/videosdk/sessions` }),
        createSession: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/videosdk/sessions` }),
        getSessionDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}` }),
        deleteSession: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}`
        }),
        useInSessionEventsControls: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/events` }),
        getSessionLiveStreamDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/livestream` }),
        updateSessionLiveStream: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/livestream` }),
        updateSessionLivestreamStatus: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/livestream/status` }),
        getSessionSIPURIWithPasscode: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/sip_dialing` }),
        updateSessionStatus: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/status` }),
        listSessionStreamingIngestions: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/stream_ingestions` }),
        listSessionUsers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/users` }),
        listSessionUsersQoS: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/users/qos` }),
        getSharingRecordingDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/videosdk/sessions/${sessionId}/users/sharing` }),
        getSessionUserQoS: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ sessionId, userId }) => `/videosdk/sessions/${sessionId}/users/${userId}/qos`
        }),
        listStreamIngestions: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/videosdk/stream_ingestions` }),
        createStreamIngestion: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/videosdk/stream_ingestions` }),
        getStreamIngestion: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ streamId }) => `/videosdk/stream_ingestions/${streamId}` }),
        deleteStreamIngestion: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ streamId }) => `/videosdk/stream_ingestions/${streamId}`
        }),
        updateStreamIngestion: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ streamId }) => `/videosdk/stream_ingestions/${streamId}` })
    };
    videoSDKReports = {
        getCloudRecordingUsageReport: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/videosdk/report/cloud_recording` }),
        getDailyUsageReport: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/videosdk/report/daily` }),
        getOperationLogsReport: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/videosdk/report/operationlogs` }),
        getTelephoneReport: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/videosdk/report/telephone` })
    };
}

const ALL_EVENTS = [
    "session.user_phone_callout_ringing",
    "session.user_room_system_callout_ringing",
    "session.recording_started",
    "session.recording_resumed",
    "session.live_streaming_stopped",
    "session.stream_ingestion_stopped",
    "session.user_room_system_callout_rejected",
    "session.alert",
    "session.recording_summary_completed",
    "session.sharing_ended",
    "session.recording_paused",
    "session.ended",
    "session.started",
    "session.stream_ingestion_unbind",
    "session.live_streaming_started",
    "session.user_room_system_callout_missed",
    "session.user_phone_callout_accepted",
    "session.user_left",
    "session.sharing_started",
    "session.user_phone_callout_canceled",
    "session.recording_transcript_completed",
    "session.recording_deleted",
    "session.user_room_system_callout_failed",
    "session.recording_completed",
    "session.recording_transcript_failed",
    "session.recording_trashed",
    "session.user_joined",
    "session.stream_ingestion_started",
    "session.stream_ingestion_connected",
    "session.stream_ingestion_disconnected",
    "session.recording_recovered",
    "session.user_phone_callout_missed",
    "session.user_phone_callout_rejected",
    "session.user_room_system_callout_accepted",
    "session.recording_stopped"
];
class VideoSdkEventProcessor extends EventManager {
}

class VideoSdkClient extends ProductClient {
    initAuth({ clientId, clientSecret, tokenStore }) {
        return new JwtAuth({ clientId, clientSecret, tokenStore });
    }
    initEndpoints(auth, options) {
        return new VideoSdkEndpoints({ auth, doubleEncodeUrl: true, ...options });
    }
    initEventProcessor(endpoints) {
        return new VideoSdkEventProcessor(endpoints);
    }
}

exports.ALL_EVENTS = ALL_EVENTS;
exports.ApiResponseError = ApiResponseError;
exports.AwsLambdaReceiver = AwsLambdaReceiver;
exports.AwsReceiverRequestError = AwsReceiverRequestError;
exports.ClientCredentialsRawResponseError = ClientCredentialsRawResponseError;
exports.CommonHttpRequestError = CommonHttpRequestError;
exports.ConsoleLogger = ConsoleLogger;
exports.HTTPReceiverConstructionError = HTTPReceiverConstructionError;
exports.HTTPReceiverPortNotNumberError = HTTPReceiverPortNotNumberError;
exports.HTTPReceiverRequestError = HTTPReceiverRequestError;
exports.HttpReceiver = HttpReceiver;
exports.OAuthInstallerNotInitializedError = OAuthInstallerNotInitializedError;
exports.OAuthStateVerificationFailedError = OAuthStateVerificationFailedError;
exports.OAuthTokenDoesNotExistError = OAuthTokenDoesNotExistError;
exports.OAuthTokenFetchFailedError = OAuthTokenFetchFailedError;
exports.OAuthTokenRawResponseError = OAuthTokenRawResponseError;
exports.OAuthTokenRefreshFailedError = OAuthTokenRefreshFailedError;
exports.ProductClientConstructionError = ProductClientConstructionError;
exports.ReceiverInconsistentStateError = ReceiverInconsistentStateError;
exports.ReceiverOAuthFlowError = ReceiverOAuthFlowError;
exports.S2SRawResponseError = S2SRawResponseError;
exports.VideoSdkClient = VideoSdkClient;
exports.VideoSdkEndpoints = VideoSdkEndpoints;
exports.VideoSdkEventProcessor = VideoSdkEventProcessor;
exports.isCoreError = isCoreError;
exports.isStateStore = isStateStore;
