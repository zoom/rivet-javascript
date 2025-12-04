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
const hasInstallerOptions = (obj) => typeof obj.installerOptions.redirectUri !== "undefined" &&
    typeof obj.installerOptions.stateStore !== "undefined";
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

class PhoneEndpoints extends WebEndpoints {
    accounts = {
        listAccountsZoomPhoneSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/account_settings` }),
        listAccountsCustomizedOutboundCallerIDPhoneNumbers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/outbound_caller_id/customized_numbers` }),
        addPhoneNumbersForAccountsCustomizedOutboundCallerID: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/outbound_caller_id/customized_numbers` }),
        deletePhoneNumbersForAccountsCustomizedOutboundCallerID: this.buildEndpoint({ method: "DELETE", urlPathBuilder: () => `/phone/outbound_caller_id/customized_numbers` })
    };
    alerts = {
        listAlertSettingsWithPagingQuery: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/alert_settings` }),
        addAlertSetting: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/alert_settings` }),
        getAlertSettingDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ alertSettingId }) => `/phone/alert_settings/${alertSettingId}` }),
        deleteAlertSetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ alertSettingId }) => `/phone/alert_settings/${alertSettingId}`
        }),
        updateAlertSetting: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ alertSettingId }) => `/phone/alert_settings/${alertSettingId}` })
    };
    audioLibrary = {
        getAudioItem: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ audioId }) => `/phone/audios/${audioId}` }),
        deleteAudioItem: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ audioId }) => `/phone/audios/${audioId}`
        }),
        updateAudioItem: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ audioId }) => `/phone/audios/${audioId}` }),
        listAudioItems: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/audios` }),
        addAudioItemForTextToSpeechConversion: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/audios` }),
        addAudioItems: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/audios/batch` })
    };
    autoReceptionists = {
        listAutoReceptionists: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/auto_receptionists` }),
        addAutoReceptionist: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/auto_receptionists` }),
        getAutoReceptionist: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}` }),
        deleteNonPrimaryAutoReceptionist: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}`
        }),
        updateAutoReceptionist: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}`
        }),
        assignPhoneNumbers: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}/phone_numbers`
        }),
        unassignAllPhoneNumbers: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}/phone_numbers`
        }),
        unassignPhoneNumber: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ autoReceptionistId, phoneNumberId }) => `/phone/auto_receptionists/${autoReceptionistId}/phone_numbers/${phoneNumberId}`
        }),
        getAutoReceptionistPolicy: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}/policies`
        }),
        updateAutoReceptionistPolicy: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}/policies`
        }),
        addPolicySubsetting: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ autoReceptionistId, policyType }) => `/phone/auto_receptionists/${autoReceptionistId}/policies/${policyType}`
        }),
        deletePolicySubsetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ autoReceptionistId, policyType }) => `/phone/auto_receptionists/${autoReceptionistId}/policies/${policyType}`
        }),
        updatePolicySubsetting: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ autoReceptionistId, policyType }) => `/phone/auto_receptionists/${autoReceptionistId}/policies/${policyType}`
        })
    };
    billingAccount = {
        listBillingAccounts: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/billing_accounts` }),
        getBillingAccountDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ billingAccountId }) => `/phone/billing_accounts/${billingAccountId}` })
    };
    blockedList = {
        listBlockedLists: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/blocked_list` }),
        createBlockedList: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/blocked_list` }),
        getBlockedListDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ blockedListId }) => `/phone/blocked_list/${blockedListId}` }),
        deleteBlockedList: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ blockedListId }) => `/phone/blocked_list/${blockedListId}`
        }),
        updateBlockedList: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ blockedListId }) => `/phone/blocked_list/${blockedListId}` })
    };
    callHandling = {
        getCallHandlingSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ extensionId }) => `/phone/extension/${extensionId}/call_handling/settings` }),
        addCallHandlingSetting: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ extensionId, settingType }) => `/phone/extension/${extensionId}/call_handling/settings/${settingType}`
        }),
        deleteCallHandlingSetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ extensionId, settingType }) => `/phone/extension/${extensionId}/call_handling/settings/${settingType}`
        }),
        updateCallHandlingSetting: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ extensionId, settingType }) => `/phone/extension/${extensionId}/call_handling/settings/${settingType}`
        })
    };
    callLogs = {
        getAccountsCallHistory: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/call_history` }),
        getCallPath: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ callLogId }) => `/phone/call_history/${callLogId}`
        }),
        addClientCodeToCallHistory: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ callLogId }) => `/phone/call_history/${callLogId}/client_code` }),
        getCallHistoryDetail: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ callHistoryId }) => `/phone/call_history_detail/${callHistoryId}` }),
        getAccountsCallLogs: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/call_logs` }),
        getCallLogDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ callLogId }) => `/phone/call_logs/${callLogId}` }),
        addClientCodeToCallLog: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ callLogId }) => `/phone/call_logs/${callLogId}/client_code` }),
        getUserAICallSummaryDetail: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ userId, aiCallSummaryId }) => `/phone/user/${userId}/ai_call_summary/${aiCallSummaryId}`
        }),
        getUsersCallHistory: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/call_history` }),
        syncUsersCallHistory: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/call_history/sync` }),
        deleteUsersCallHistory: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, callLogId }) => `/phone/users/${userId}/call_history/${callLogId}`
        }),
        getUsersCallLogs: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/call_logs` }),
        syncUsersCallLogs: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/call_logs/sync` }),
        deleteUsersCallLog: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, callLogId }) => `/phone/users/${userId}/call_logs/${callLogId}`
        })
    };
    callQueues = {
        listCallQueueAnalytics: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/call_queue_analytics` }),
        listCallQueues: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/call_queues` }),
        createCallQueue: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/call_queues` }),
        getCallQueueDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}` }),
        deleteCallQueue: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}`
        }),
        updateCallQueueDetails: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}` }),
        listCallQueueMembers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}/members` }),
        addMembersToCallQueue: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}/members` }),
        unassignAllMembers: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}/members`
        }),
        unassignMember: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ callQueueId, memberId }) => `/phone/call_queues/${callQueueId}/members/${memberId}`
        }),
        assignNumbersToCallQueue: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}/phone_numbers` }),
        unassignAllPhoneNumbers: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}/phone_numbers`
        }),
        unassignPhoneNumber: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ callQueueId, phoneNumberId }) => `/phone/call_queues/${callQueueId}/phone_numbers/${phoneNumberId}`
        }),
        addPolicySubsettingToCallQueue: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ callQueueId, policyType }) => `/phone/call_queues/${callQueueId}/policies/${policyType}`
        }),
        deleteCQPolicySetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ callQueueId, policyType }) => `/phone/call_queues/${callQueueId}/policies/${policyType}`
        }),
        updateCallQueuesPolicySubsetting: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ callQueueId, policyType }) => `/phone/call_queues/${callQueueId}/policies/${policyType}`
        }),
        getCallQueueRecordings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ callQueueId }) => `/phone/call_queues/${callQueueId}/recordings` })
    };
    carrierReseller = {
        listPhoneNumbers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/carrier_reseller/numbers` }),
        createPhoneNumbers: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/phone/carrier_reseller/numbers`
        }),
        activatePhoneNumbers: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: () => `/phone/carrier_reseller/numbers`
        }),
        deletePhoneNumber: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ number }) => `/phone/carrier_reseller/numbers/${number}`
        })
    };
    commonAreas = {
        listCommonAreas: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/common_areas` }),
        addCommonArea: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/common_areas` }),
        generateActivationCodesForCommonAreas: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/common_areas/activation_code` }),
        listActivationCodes: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/common_areas/activation_codes` }),
        applyTemplateToCommonAreas: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ templateId }) => `/phone/common_areas/template_id/${templateId}` }),
        getCommonAreaDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}` }),
        deleteCommonArea: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}`
        }),
        updateCommonArea: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}` }),
        assignCallingPlansToCommonArea: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/calling_plans` }),
        unassignCallingPlanFromCommonArea: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ commonAreaId, type }) => `/phone/common_areas/${commonAreaId}/calling_plans/${type}`
        }),
        assignPhoneNumbersToCommonArea: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/phone_numbers` }),
        unassignPhoneNumbersFromCommonArea: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ commonAreaId, phoneNumberId }) => `/phone/common_areas/${commonAreaId}/phone_numbers/${phoneNumberId}`
        }),
        updateCommonAreaPinCode: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/pin_code` }),
        getCommonAreaSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/settings` }),
        addCommonAreaSetting: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ commonAreaId, settingType }) => `/phone/common_areas/${commonAreaId}/settings/${settingType}`
        }),
        deleteCommonAreaSetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ commonAreaId, settingType }) => `/phone/common_areas/${commonAreaId}/settings/${settingType}`
        }),
        updateCommonAreaSetting: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ commonAreaId, settingType }) => `/phone/common_areas/${commonAreaId}/settings/${settingType}`
        })
    };
    dashboard = {
        listCallLogs: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/call_logs` }),
        getCallQoS: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ callId }) => `/phone/metrics/call_logs/${callId}/qos`
        }),
        getCallDetailsFromCallLog: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ call_id }) => `/phone/metrics/call_logs/${call_id}` }),
        listDefaultEmergencyAddressUsers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/emergency_services/default_emergency_address/users` }),
        listDetectablePersonalLocationUsers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/emergency_services/detectable_personal_location/users` }),
        listUsersPermissionForLocationSharing: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/emergency_services/location_sharing_permission/users` }),
        listNomadicEmergencyServicesUsers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/emergency_services/nomadic_emergency_services/users` }),
        listRealTimeLocationForIPPhones: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/emergency_services/realtime_location/devices` }),
        listRealTimeLocationForUsers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/emergency_services/realtime_location/users` }),
        listTrackedLocations: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/location_tracking` }),
        listPastCallMetrics: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/metrics/past_calls` })
    };
    deviceLineKeys = {
        getDeviceLineKeysInformation: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}/line_keys` }),
        batchUpdateDeviceLineKeyPosition: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}/line_keys` })
    };
    dialByNameDirectory = {
        listUsersInDirectory: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/dial_by_name_directory/extensions` }),
        addUsersToDirectory: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/phone/dial_by_name_directory/extensions`
        }),
        deleteUsersFromDirectory: this.buildEndpoint({ method: "DELETE", urlPathBuilder: () => `/phone/dial_by_name_directory/extensions` }),
        listUsersInDirectoryBySite: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/dial_by_name_directory/extensions` }),
        addUsersToDirectoryOfSite: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/dial_by_name_directory/extensions` }),
        deleteUsersFromDirectoryOfSite: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/dial_by_name_directory/extensions` })
    };
    emergencyAddresses = {
        listEmergencyAddresses: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/emergency_addresses` }),
        addEmergencyAddress: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/emergency_addresses` }),
        getEmergencyAddressDetails: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ emergencyAddressId }) => `/phone/emergency_addresses/${emergencyAddressId}`
        }),
        deleteEmergencyAddress: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ emergencyAddressId }) => `/phone/emergency_addresses/${emergencyAddressId}`
        }),
        updateEmergencyAddress: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ emergencyAddressId }) => `/phone/emergency_addresses/${emergencyAddressId}`
        })
    };
    emergencyServiceLocations = {
        batchAddEmergencyServiceLocations: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/batch_locations` }),
        listEmergencyServiceLocations: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/locations` }),
        addEmergencyServiceLocation: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/locations` }),
        getEmergencyServiceLocationDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ locationId }) => `/phone/locations/${locationId}` }),
        deleteEmergencyLocation: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ locationId }) => `/phone/locations/${locationId}` }),
        updateEmergencyServiceLocation: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ locationId }) => `/phone/locations/${locationId}` })
    };
    externalContacts = {
        listExternalContacts: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/external_contacts` }),
        addExternalContact: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/external_contacts` }),
        getExternalContactDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ externalContactId }) => `/phone/external_contacts/${externalContactId}` }),
        deleteExternalContact: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ externalContactId }) => `/phone/external_contacts/${externalContactId}`
        }),
        updateExternalContact: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ externalContactId }) => `/phone/external_contacts/${externalContactId}` })
    };
    firmwareUpdateRules = {
        listFirmwareUpdateRules: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/firmware_update_rules` }),
        addFirmwareUpdateRule: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/firmware_update_rules` }),
        getFirmwareUpdateRuleInformation: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ ruleId }) => `/phone/firmware_update_rules/${ruleId}` }),
        deleteFirmwareUpdateRule: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ ruleId }) => `/phone/firmware_update_rules/${ruleId}` }),
        updateFirmwareUpdateRule: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ ruleId }) => `/phone/firmware_update_rules/${ruleId}` }),
        listUpdatableFirmwares: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/firmwares` })
    };
    groupCallPickup = {
        listGroupCallPickupObjects: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/group_call_pickup` }),
        addGroupCallPickupObject: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/group_call_pickup` }),
        getCallPickupGroupByID: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/phone/group_call_pickup/${groupId}` }),
        deleteGroupCallPickupObjects: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ groupId }) => `/phone/group_call_pickup/${groupId}` }),
        updateGroupCallPickupInformation: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ groupId }) => `/phone/group_call_pickup/${groupId}` }),
        listCallPickupGroupMembers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/phone/group_call_pickup/${groupId}/members` }),
        addMembersToCallPickupGroup: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ groupId }) => `/phone/group_call_pickup/${groupId}/members` }),
        removeMembersFromCallPickupGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ groupId, extensionId }) => `/phone/group_call_pickup/${groupId}/members/${extensionId}`
        })
    };
    groups = {
        getGroupPolicyDetails: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ groupId, policyType }) => `/phone/groups/${groupId}/policies/${policyType}`
        }),
        updateGroupPolicy: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ groupId, policyType }) => `/phone/groups/${groupId}/policies/${policyType}`
        }),
        getGroupPhoneSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/phone/groups/${groupId}/settings` })
    };
    iVR = {
        getAutoReceptionistIVR: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}/ivr`
        }),
        updateAutoReceptionistIVR: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ autoReceptionistId }) => `/phone/auto_receptionists/${autoReceptionistId}/ivr`
        })
    };
    inboundBlockedList = {
        listExtensionsInboundBlockRules: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ extensionId }) => `/phone/extension/${extensionId}/inbound_blocked/rules` }),
        addExtensionsInboundBlockRule: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ extensionId }) => `/phone/extension/${extensionId}/inbound_blocked/rules` }),
        deleteExtensionsInboundBlockRule: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ extensionId }) => `/phone/extension/${extensionId}/inbound_blocked/rules`
        }),
        listAccountsInboundBlockedStatistics: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/inbound_blocked/extension_rules/statistics` }),
        deleteAccountsInboundBlockedStatistics: this.buildEndpoint({ method: "DELETE", urlPathBuilder: () => `/phone/inbound_blocked/extension_rules/statistics` }),
        markPhoneNumberAsBlockedForAllExtensions: this.buildEndpoint({ method: "PATCH", urlPathBuilder: () => `/phone/inbound_blocked/extension_rules/statistics/blocked_for_all` }),
        listAccountsInboundBlockRules: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/inbound_blocked/rules` }),
        addAccountsInboundBlockRule: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/inbound_blocked/rules` }),
        deleteAccountsInboundBlockRule: this.buildEndpoint({ method: "DELETE", urlPathBuilder: () => `/phone/inbound_blocked/rules` }),
        updateAccountsInboundBlockRule: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ blockedRuleId }) => `/phone/inbound_blocked/rules/${blockedRuleId}` })
    };
    lineKeys = {
        getLineKeyPositionAndSettingsInformation: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ extensionId }) => `/phone/extension/${extensionId}/line_keys` }),
        batchUpdateLineKeyPositionAndSettingsInformation: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ extensionId }) => `/phone/extension/${extensionId}/line_keys` }),
        deleteLineKeySetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ extensionId, lineKeyId }) => `/phone/extension/${extensionId}/line_keys/${lineKeyId}`
        })
    };
    monitoringGroups = {
        getListOfMonitoringGroupsOnAccount: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/monitoring_groups` }),
        createMonitoringGroup: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/monitoring_groups` }),
        getMonitoringGroupByID: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ monitoringGroupId }) => `/phone/monitoring_groups/${monitoringGroupId}` }),
        deleteMonitoringGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ monitoringGroupId }) => `/phone/monitoring_groups/${monitoringGroupId}`
        }),
        updateMonitoringGroup: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ monitoringGroupId }) => `/phone/monitoring_groups/${monitoringGroupId}` }),
        getMembersOfMonitoringGroup: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ monitoringGroupId }) => `/phone/monitoring_groups/${monitoringGroupId}/monitor_members`
        }),
        addMembersToMonitoringGroup: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ monitoringGroupId }) => `/phone/monitoring_groups/${monitoringGroupId}/monitor_members`
        }),
        removeAllMonitorsOrMonitoredMembersFromMonitoringGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ monitoringGroupId }) => `/phone/monitoring_groups/${monitoringGroupId}/monitor_members`
        }),
        removeMemberFromMonitoringGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ monitoringGroupId, memberExtensionId }) => `/phone/monitoring_groups/${monitoringGroupId}/monitor_members/${memberExtensionId}`
        })
    };
    outboundCalling = {
        getCommonAreaLevelOutboundCallingCountriesAndRegions: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/outbound_calling/countries_regions`
        }),
        updateCommonAreaLevelOutboundCallingCountriesOrRegions: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/outbound_calling/countries_regions`
        }),
        listCommonAreaLevelOutboundCallingExceptionRules: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/outbound_calling/exception_rules`
        }),
        addCommonAreaLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ commonAreaId }) => `/phone/common_areas/${commonAreaId}/outbound_calling/exception_rules`
        }),
        deleteCommonAreaLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ commonAreaId, exceptionRuleId }) => `/phone/common_areas/${commonAreaId}/outbound_calling/exception_rules/${exceptionRuleId}`
        }),
        updateCommonAreaLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ commonAreaId, exceptionRuleId }) => `/phone/common_areas/${commonAreaId}/outbound_calling/exception_rules/${exceptionRuleId}`
        }),
        getAccountLevelOutboundCallingCountriesAndRegions: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/outbound_calling/countries_regions` }),
        updateAccountLevelOutboundCallingCountriesOrRegions: this.buildEndpoint({ method: "PATCH", urlPathBuilder: () => `/phone/outbound_calling/countries_regions` }),
        listAccountLevelOutboundCallingExceptionRules: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/outbound_calling/exception_rules` }),
        addAccountLevelOutboundCallingExceptionRule: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/outbound_calling/exception_rules` }),
        deleteAccountLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ exceptionRuleId }) => `/phone/outbound_calling/exception_rules/${exceptionRuleId}`
        }),
        updateAccountLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ exceptionRuleId }) => `/phone/outbound_calling/exception_rules/${exceptionRuleId}`
        }),
        getSiteLevelOutboundCallingCountriesAndRegions: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/outbound_calling/countries_regions` }),
        updateSiteLevelOutboundCallingCountriesOrRegions: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/outbound_calling/countries_regions` }),
        listSiteLevelOutboundCallingExceptionRules: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/outbound_calling/exception_rules` }),
        addSiteLevelOutboundCallingExceptionRule: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/outbound_calling/exception_rules` }),
        deleteSiteLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ siteId, exceptionRuleId }) => `/phone/sites/${siteId}/outbound_calling/exception_rules/${exceptionRuleId}`
        }),
        updateSiteLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ siteId, exceptionRuleId }) => `/phone/sites/${siteId}/outbound_calling/exception_rules/${exceptionRuleId}`
        }),
        getUserLevelOutboundCallingCountriesAndRegions: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/outbound_calling/countries_regions` }),
        updateUserLevelOutboundCallingCountriesOrRegions: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/outbound_calling/countries_regions` }),
        listUserLevelOutboundCallingExceptionRules: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/outbound_calling/exception_rules` }),
        addUserLevelOutboundCallingExceptionRule: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/outbound_calling/exception_rules` }),
        deleteUserLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, exceptionRuleId }) => `/phone/users/${userId}/outbound_calling/exception_rules/${exceptionRuleId}`
        }),
        updateUserLevelOutboundCallingExceptionRule: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ userId, exceptionRuleId }) => `/phone/users/${userId}/outbound_calling/exception_rules/${exceptionRuleId}`
        })
    };
    phoneDevices = {
        listDevices: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/devices` }),
        addDevice: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/phone/devices`
        }),
        syncDeskphones: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/phone/devices/sync`
        }),
        getDeviceDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}` }),
        deleteDevice: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}`
        }),
        updateDevice: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}` }),
        assignEntityToDevice: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}/extensions` }),
        unassignEntityFromDevice: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ deviceId, extensionId }) => `/phone/devices/${deviceId}/extensions/${extensionId}`
        }),
        updateProvisionTemplateOfDevice: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}/provision_templates` }),
        rebootDeskPhone: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ deviceId }) => `/phone/devices/${deviceId}/reboot`
        }),
        listSmartphones: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/smartphones` })
    };
    phoneNumbers = {
        addBYOCPhoneNumbers: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/byoc_numbers` }),
        listPhoneNumbers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/numbers` }),
        deleteUnassignedPhoneNumbers: this.buildEndpoint({ method: "DELETE", urlPathBuilder: () => `/phone/numbers` }),
        updateSitesUnassignedPhoneNumbers: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ siteId }) => `/phone/numbers/sites/${siteId}` }),
        getPhoneNumber: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ phoneNumberId }) => `/phone/numbers/${phoneNumberId}` }),
        updatePhoneNumber: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ phoneNumberId }) => `/phone/numbers/${phoneNumberId}` }),
        assignPhoneNumberToUser: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/phone_numbers` }),
        unassignPhoneNumber: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, phoneNumberId }) => `/phone/users/${userId}/phone_numbers/${phoneNumberId}`
        })
    };
    phonePlans = {
        listCallingPlans: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/phone/calling_plans`
        }),
        listPlanInformation: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/phone/plans`
        })
    };
    phoneRoles = {
        listPhoneRoles: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/phone/roles`
        }),
        duplicatePhoneRole: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/roles` }),
        getRoleInformation: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}` }),
        deletePhoneRole: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}`
        }),
        updatePhoneRole: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}` }),
        listMembersInRole: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}/members` }),
        addMembersToRoles: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}/members` }),
        deleteMembersInRole: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}/members` }),
        listPhoneRoleTargets: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}/targets` }),
        addPhoneRoleTargets: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}/targets` }),
        deletePhoneRoleTargets: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ roleId }) => `/phone/roles/${roleId}/targets` })
    };
    privateDirectory = {
        listPrivateDirectoryMembers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/private_directory/members` }),
        addMembersToPrivateDirectory: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/private_directory/members` }),
        removeMemberFromPrivateDirectory: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ extensionId }) => `/phone/private_directory/members/${extensionId}` }),
        updatePrivateDirectoryMember: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ extensionId }) => `/phone/private_directory/members/${extensionId}` })
    };
    providerExchange = {
        listCarrierPeeringPhoneNumbers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/carrier_peering/numbers` }),
        listPeeringPhoneNumbers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/peering/numbers` }),
        addPeeringPhoneNumbers: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/peering/numbers` }),
        removePeeringPhoneNumbers: this.buildEndpoint({ method: "DELETE", urlPathBuilder: () => `/phone/peering/numbers` }),
        updatePeeringPhoneNumbers: this.buildEndpoint({ method: "PATCH", urlPathBuilder: () => `/phone/peering/numbers` })
    };
    provisionTemplates = {
        listProvisionTemplates: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/provision_templates` }),
        addProvisionTemplate: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/provision_templates` }),
        getProvisionTemplate: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ templateId }) => `/phone/provision_templates/${templateId}` }),
        deleteProvisionTemplate: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ templateId }) => `/phone/provision_templates/${templateId}` }),
        updateProvisionTemplate: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ templateId }) => `/phone/provision_templates/${templateId}` })
    };
    recordings = {
        getRecordingByCallID: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ id }) => `/phone/call_logs/${id}/recordings` }),
        downloadPhoneRecording: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ fileId }) => `/phone/recording/download/${fileId}`
        }),
        downloadPhoneRecordingTranscript: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ recordingId }) => `/phone/recording_transcript/download/${recordingId}` }),
        getCallRecordings: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/recordings` }),
        deleteCallRecording: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ recordingId }) => `/phone/recordings/${recordingId}`
        }),
        updateAutoDeleteField: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ recordingId }) => `/phone/recordings/${recordingId}` }),
        updateRecordingStatus: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ recordingId }) => `/phone/recordings/${recordingId}/status` }),
        getUsersRecordings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/recordings` })
    };
    reports = {
        getCallChargesUsageReport: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/reports/call_charges` }),
        getOperationLogsReport: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/reports/operationlogs` }),
        getSMSMMSChargesUsageReport: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/reports/sms_charges` })
    };
    routingRules = {
        listDirectoryBackupRoutingRules: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/routing_rules` }),
        addDirectoryBackupRoutingRule: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/routing_rules` }),
        getDirectoryBackupRoutingRule: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ routingRuleId }) => `/phone/routing_rules/${routingRuleId}` }),
        deleteDirectoryBackupRoutingRule: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ routingRuleId }) => `/phone/routing_rules/${routingRuleId}` }),
        updateDirectoryBackupRoutingRule: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ routingRuleId }) => `/phone/routing_rules/${routingRuleId}` })
    };
    sMS = {
        postSMSMessage: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/phone/sms/messages`
        }),
        getAccountsSMSSessions: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/sms/sessions` }),
        getSMSSessionDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/phone/sms/sessions/${sessionId}` }),
        getSMSByMessageID: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ sessionId, messageId }) => `/phone/sms/sessions/${sessionId}/messages/${messageId}`
        }),
        syncSMSBySessionID: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sessionId }) => `/phone/sms/sessions/${sessionId}/sync` }),
        getUsersSMSSessions: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/sms/sessions` }),
        listUsersSMSSessionsInDescendingOrder: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/sms/sessions/sync` })
    };
    sMSCampaign = {
        listSMSCampaigns: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/sms_campaigns` }),
        getSMSCampaign: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ smsCampaignId }) => `/phone/sms_campaigns/${smsCampaignId}` }),
        assignPhoneNumberToSMSCampaign: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ smsCampaignId }) => `/phone/sms_campaigns/${smsCampaignId}/phone_numbers` }),
        listOptStatusesOfPhoneNumbersAssignedToSMSCampaign: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ smsCampaignId }) => `/phone/sms_campaigns/${smsCampaignId}/phone_numbers/opt_status`
        }),
        updateOptStatusesOfPhoneNumbersAssignedToSMSCampaign: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ smsCampaignId }) => `/phone/sms_campaigns/${smsCampaignId}/phone_numbers/opt_status`
        }),
        unassignPhoneNumber: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ smsCampaignId, phoneNumberId }) => `/phone/sms_campaigns/${smsCampaignId}/phone_numbers/${phoneNumberId}`
        }),
        listUsersOptStatusesOfPhoneNumbers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/user/${userId}/sms_campaigns/phone_numbers/opt_status` })
    };
    settingTemplates = {
        listSettingTemplates: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/setting_templates` }),
        addSettingTemplate: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/setting_templates` }),
        getSettingTemplateDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ templateId }) => `/phone/setting_templates/${templateId}` }),
        updateSettingTemplate: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ templateId }) => `/phone/setting_templates/${templateId}` })
    };
    settings = {
        getAccountPolicyDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ policyType }) => `/phone/policies/${policyType}` }),
        updateAccountPolicy: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ policyType }) => `/phone/policies/${policyType}` }),
        listPortedNumbers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/ported_numbers/orders` }),
        getPortedNumberDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ orderId }) => `/phone/ported_numbers/orders/${orderId}` }),
        getPhoneAccountSettings: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/phone/settings`
        }),
        updatePhoneAccountSettings: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: () => `/phone/settings`
        }),
        listSIPGroups: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/sip_groups` }),
        listBYOCSIPTrunks: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/sip_trunk/trunks` })
    };
    sharedLineAppearance = {
        listSharedLineAppearances: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/shared_line_appearances` })
    };
    sharedLineGroup = {
        listSharedLineGroups: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/shared_line_groups` }),
        createSharedLineGroup: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/shared_line_groups` }),
        getSharedLineGroup: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ sharedLineGroupId }) => `/phone/shared_line_groups/${sharedLineGroupId}` }),
        getSharedLineGroupPolicy: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ sharedLineGroupId }) => `/phone/shared_line_groups/${sharedLineGroupId}/policies`
        }),
        updateSharedLineGroupPolicy: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ sharedLineGroupId }) => `/phone/shared_line_groups/${sharedLineGroupId}/policies`
        }),
        deleteSharedLineGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ slgId }) => `/phone/shared_line_groups/${slgId}`
        }),
        updateSharedLineGroup: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ slgId }) => `/phone/shared_line_groups/${slgId}` }),
        addMembersToSharedLineGroup: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ slgId }) => `/phone/shared_line_groups/${slgId}/members` }),
        unassignMembersFromSharedLineGroup: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ slgId }) => `/phone/shared_line_groups/${slgId}/members` }),
        unassignMemberFromSharedLineGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ slgId, memberId }) => `/phone/shared_line_groups/${slgId}/members/${memberId}`
        }),
        assignPhoneNumbers: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ slgId }) => `/phone/shared_line_groups/${slgId}/phone_numbers` }),
        unassignAllPhoneNumbers: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ slgId }) => `/phone/shared_line_groups/${slgId}/phone_numbers`
        }),
        unassignPhoneNumber: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ slgId, phoneNumberId }) => `/phone/shared_line_groups/${slgId}/phone_numbers/${phoneNumberId}`
        }),
        addPolicySettingToSharedLineGroup: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ slgId, policyType }) => `/phone/shared_line_groups/${slgId}/policies/${policyType}`
        }),
        deleteSLGPolicySetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ slgId, policyType }) => `/phone/shared_line_groups/${slgId}/policies/${policyType}`
        }),
        updateSLGPolicySetting: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ slgId, policyType }) => `/phone/shared_line_groups/${slgId}/policies/${policyType}`
        })
    };
    sites = {
        listPhoneSites: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/sites` }),
        createPhoneSite: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/phone/sites` }),
        getPhoneSiteDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}` }),
        deletePhoneSite: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}`
        }),
        updatePhoneSiteDetails: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}` }),
        listCustomizedOutboundCallerIDPhoneNumbers: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/outbound_caller_id/customized_numbers`
        }),
        addCustomizedOutboundCallerIDPhoneNumbers: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/outbound_caller_id/customized_numbers`
        }),
        removeCustomizedOutboundCallerIDPhoneNumbers: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ siteId }) => `/phone/sites/${siteId}/outbound_caller_id/customized_numbers`
        }),
        getPhoneSiteSetting: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ siteId, settingType }) => `/phone/sites/${siteId}/settings/${settingType}` }),
        addSiteSetting: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ siteId, settingType }) => `/phone/sites/${siteId}/settings/${settingType}`
        }),
        deleteSiteSetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ siteId, settingType }) => `/phone/sites/${siteId}/settings/${settingType}`
        }),
        updateSiteSetting: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ siteId, settingType }) => `/phone/sites/${siteId}/settings/${settingType}`
        })
    };
    users = {
        listPhoneUsers: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/users` }),
        updateMultipleUsersPropertiesInBatch: this.buildEndpoint({ method: "PUT", urlPathBuilder: () => `/phone/users/batch` }),
        batchAddUsers: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/phone/users/batch`
        }),
        getUsersProfile: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}` }),
        updateUsersProfile: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ userId }) => `/phone/users/${userId}` }),
        updateUsersCallingPlan: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/calling_plans` }),
        assignCallingPlanToUser: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/calling_plans` }),
        unassignUsersCallingPlan: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, planType }) => `/phone/users/${userId}/calling_plans/${planType}`
        }),
        listUsersPhoneNumbersForCustomizedOutboundCallerID: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ userId }) => `/phone/users/${userId}/outbound_caller_id/customized_numbers`
        }),
        addPhoneNumbersForUsersCustomizedOutboundCallerID: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ userId }) => `/phone/users/${userId}/outbound_caller_id/customized_numbers`
        }),
        removeUsersCustomizedOutboundCallerIDPhoneNumbers: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId }) => `/phone/users/${userId}/outbound_caller_id/customized_numbers`
        }),
        getUserPolicyDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId, policyType }) => `/phone/users/${userId}/policies/${policyType}` }),
        updateUserPolicy: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ userId, policyType }) => `/phone/users/${userId}/policies/${policyType}`
        }),
        getUsersProfileSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/settings` }),
        updateUsersProfileSettings: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/settings` }),
        addUsersSharedAccessSetting: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ userId, settingType }) => `/phone/users/${userId}/settings/${settingType}`
        }),
        deleteUsersSharedAccessSetting: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, settingType }) => `/phone/users/${userId}/settings/${settingType}`
        }),
        updateUsersSharedAccessSetting: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ settingType, userId }) => `/phone/users/${userId}/settings/${settingType}`
        })
    };
    voicemails = {
        getUserVoicemailDetailsFromCallLog: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId, id }) => `/phone/users/${userId}/call_logs/${id}/voice_mail` }),
        getUsersVoicemails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/phone/users/${userId}/voice_mails` }),
        getAccountVoicemails: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/voice_mails` }),
        downloadPhoneVoicemail: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ fileId }) => `/phone/voice_mails/download/${fileId}`
        }),
        getVoicemailDetails: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ voicemailId }) => `/phone/voice_mails/${voicemailId}` }),
        deleteVoicemail: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ voicemailId }) => `/phone/voice_mails/${voicemailId}`
        }),
        updateVoicemailReadStatus: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ voicemailId }) => `/phone/voice_mails/${voicemailId}` })
    };
    zoomRooms = {
        listZoomRoomsUnderZoomPhoneLicense: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/rooms` }),
        addZoomRoomToZoomPhone: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/phone/rooms`
        }),
        listZoomRoomsWithoutZoomPhoneAssignment: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/phone/rooms/unassigned` }),
        getZoomRoomUnderZoomPhoneLicense: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ roomId }) => `/phone/rooms/${roomId}` }),
        removeZoomRoomFromZPAccount: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ roomId }) => `/phone/rooms/${roomId}` }),
        updateZoomRoomUnderZoomPhoneLicense: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ roomId }) => `/phone/rooms/${roomId}` }),
        assignCallingPlansToZoomRoom: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ roomId }) => `/phone/rooms/${roomId}/calling_plans` }),
        removeCallingPlanFromZoomRoom: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ roomId, type }) => `/phone/rooms/${roomId}/calling_plans/${type}` }),
        assignPhoneNumbersToZoomRoom: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ roomId }) => `/phone/rooms/${roomId}/phone_numbers` }),
        removePhoneNumberFromZoomRoom: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ roomId, phoneNumberId }) => `/phone/rooms/${roomId}/phone_numbers/${phoneNumberId}`
        })
    };
}

class PhoneEventProcessor extends EventManager {
}

class OAuth extends InteractiveAuth {
    assertResponseAccessToken(data) {
        if (typeof data.access_token !== "string" ||
            typeof data.refresh_token !== "string" ||
            typeof data.expires_in !== "number" ||
            typeof data.scope !== "string") {
            throw new OAuthTokenRawResponseError(`Failed to match raw response (${JSON.stringify(data)}) to expected shape.`);
        }
    }
    async fetchAccessToken(code) {
        try {
            const response = await this.makeOAuthTokenRequest("authorization_code", {
                code,
                redirect_uri: this.getFullRedirectUri()
            });
            this.assertResponseAccessToken(response.data);
            return this.mapOAuthToken(response.data);
        }
        catch (err) {
            throw new OAuthTokenFetchFailedError("Failed to fetch OAuth token.", { cause: err });
        }
    }
    async getToken() {
        const { tokenStore } = this;
        const currentToken = await Promise.resolve(tokenStore.getLatestToken());
        // If we have no OAuth token, app most likely has not been previously authorized.
        if (!currentToken) {
            throw new OAuthTokenDoesNotExistError("Failed to find OAuth token. Authorize this app first.");
        }
        // If the OAuth token hasn't already expired (and isn't within the delta), return it.
        if (!this.isAlmostExpired(currentToken.expirationTimeIso)) {
            return currentToken.accessToken;
        }
        // Since the token has expired, refresh, store, and return it.
        const refreshedToken = await this.refreshAccessToken(currentToken.refreshToken);
        await Promise.resolve(tokenStore.storeToken(refreshedToken));
        return refreshedToken.accessToken;
    }
    async initRedirectCode(code) {
        const { tokenStore } = this;
        const accessToken = await this.fetchAccessToken(code);
        await Promise.resolve(tokenStore.storeToken(accessToken));
    }
    mapOAuthToken({ access_token, expires_in, refresh_token, scope }) {
        return {
            accessToken: access_token,
            expirationTimeIso: dayjs().add(expires_in, "seconds").toISOString(),
            refreshToken: refresh_token,
            scopes: scope.includes(" ") ? scope.split(" ") : [scope]
        };
    }
    async refreshAccessToken(refreshToken) {
        try {
            const response = await this.makeOAuthTokenRequest("refresh_token", {
                refresh_token: refreshToken
            });
            this.assertResponseAccessToken(response.data);
            return this.mapOAuthToken(response.data);
        }
        catch (err) {
            throw new OAuthTokenRefreshFailedError("Failed to refresh OAuth token.", { cause: err });
        }
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

class PhoneOAuthClient extends ProductClient {
    initAuth({ clientId, clientSecret, tokenStore, ...restOptions }) {
        const oAuth = new OAuth({ clientId, clientSecret, tokenStore });
        if (hasInstallerOptions(restOptions)) {
            oAuth.setInstallerOptions(restOptions.installerOptions);
        }
        return oAuth;
    }
    initEndpoints(auth, options) {
        return new PhoneEndpoints({ auth, ...options });
    }
    initEventProcessor(endpoints) {
        return new PhoneEventProcessor(endpoints);
    }
}

class S2SAuth extends Auth {
    accountId;
    constructor({ accountId, ...restOptions }) {
        super(restOptions);
        this.accountId = accountId;
    }
    assertRawToken(obj) {
        if (typeof obj.access_token !== "string" ||
            typeof obj.expires_in !== "number" ||
            typeof obj.scope !== "string") {
            throw new S2SRawResponseError(`Failed to match raw response ${JSON.stringify(obj)} to expected shape.`);
        }
    }
    async fetchAccessToken() {
        const response = await this.makeOAuthTokenRequest("account_credentials", {
            account_id: this.accountId
        });
        this.assertRawToken(response.data);
        return this.mapAccessToken(response.data);
    }
    async getToken() {
        const { tokenStore } = this;
        const currentToken = await Promise.resolve(tokenStore.getLatestToken());
        if (currentToken && !this.isAlmostExpired(currentToken.expirationTimeIso)) {
            return currentToken.accessToken;
        }
        const token = await this.fetchAccessToken();
        await Promise.resolve(tokenStore.storeToken(token));
        return token.accessToken;
    }
    mapAccessToken({ access_token, expires_in, scope }) {
        return {
            accessToken: access_token,
            expirationTimeIso: dayjs().add(expires_in, "seconds").toISOString(),
            scopes: scope.includes(" ") ? scope.split(" ") : [scope]
        };
    }
}

class PhoneS2SAuthClient extends ProductClient {
    initAuth({ clientId, clientSecret, tokenStore, accountId }) {
        return new S2SAuth({ clientId, clientSecret, tokenStore, accountId });
    }
    initEndpoints(auth, options) {
        return new PhoneEndpoints({ auth, ...options });
    }
    initEventProcessor(endpoints) {
        return new PhoneEventProcessor(endpoints);
    }
}

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
exports.PhoneEndpoints = PhoneEndpoints;
exports.PhoneEventProcessor = PhoneEventProcessor;
exports.PhoneOAuthClient = PhoneOAuthClient;
exports.PhoneS2SAuthClient = PhoneS2SAuthClient;
exports.ProductClientConstructionError = ProductClientConstructionError;
exports.ReceiverInconsistentStateError = ReceiverInconsistentStateError;
exports.ReceiverOAuthFlowError = ReceiverOAuthFlowError;
exports.S2SRawResponseError = S2SRawResponseError;
exports.isCoreError = isCoreError;
exports.isStateStore = isStateStore;
