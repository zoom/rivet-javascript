import { createHmac, randomBytes } from 'node:crypto';
import { createServer as createServer$1 } from 'node:http';
import { createServer } from 'node:https';
import axios from 'axios';
import dayjs from 'dayjs';
import { Buffer as Buffer$1 } from 'node:buffer';
import { SignJWT, jwtVerify } from 'jose';
import FormData from 'form-data';
import os from 'node:os';
import { basename } from 'node:path';

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

var LogLevel;
(function (LogLevel) {
    LogLevel["ERROR"] = "error";
    LogLevel["WARN"] = "warn";
    LogLevel["INFO"] = "info";
    LogLevel["DEBUG"] = "debug";
})(LogLevel || (LogLevel = {}));
class ConsoleLogger {
    level;
    name;
    static labels = (() => {
        const entries = Object.entries(LogLevel);
        const map = entries.map(([key, value]) => [value, `[${key}] `]);
        return new Map(map);
    })();
    static severity = {
        [LogLevel.ERROR]: 400,
        [LogLevel.WARN]: 300,
        [LogLevel.INFO]: 200,
        [LogLevel.DEBUG]: 100
    };
    constructor() {
        this.level = LogLevel.INFO;
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
        if (ConsoleLogger.isMoreOrEqualSevere(LogLevel.DEBUG, this.level)) {
            console.debug(ConsoleLogger.labels.get(LogLevel.DEBUG), this.name, ...msg);
        }
    }
    info(...msg) {
        if (ConsoleLogger.isMoreOrEqualSevere(LogLevel.INFO, this.level)) {
            console.info(ConsoleLogger.labels.get(LogLevel.INFO), this.name, ...msg);
        }
    }
    warn(...msg) {
        if (ConsoleLogger.isMoreOrEqualSevere(LogLevel.WARN, this.level)) {
            console.warn(ConsoleLogger.labels.get(LogLevel.WARN), this.name, ...msg);
        }
    }
    error(...msg) {
        if (ConsoleLogger.isMoreOrEqualSevere(LogLevel.ERROR, this.level)) {
            console.error(ConsoleLogger.labels.get(LogLevel.ERROR), this.name, ...msg);
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
    encryptedToken: createHmac("sha256", webhooksSecretToken).update(plainToken).digest("hex"),
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
        const hashToVerify = createHmac("sha256", this.webhooksSecretToken).update(messageToVerify).digest("hex");
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

var StatusCode;
(function (StatusCode) {
    StatusCode[StatusCode["OK"] = 200] = "OK";
    StatusCode[StatusCode["TEMPORARY_REDIRECT"] = 302] = "TEMPORARY_REDIRECT";
    StatusCode[StatusCode["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    StatusCode[StatusCode["NOT_FOUND"] = 404] = "NOT_FOUND";
    StatusCode[StatusCode["METHOD_NOT_ALLOWED"] = 405] = "METHOD_NOT_ALLOWED";
    StatusCode[StatusCode["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
})(StatusCode || (StatusCode = {}));

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
                    return this.buildResponse(StatusCode.OK, processedEvent);
                }
                else {
                    await this.eventEmitter?.emit(processedEvent.event, processedEvent);
                    return this.buildResponse(StatusCode.OK, { message: "Zoom event processed successfully." });
                }
            }
            catch (err) {
                if (isCoreError(err, "CommonHttpRequestError")) {
                    return this.buildResponse(StatusCode.BAD_REQUEST, { error: err.message });
                }
                else {
                    console.error(err);
                    return this.buildResponse(StatusCode.INTERNAL_SERVER_ERROR, {
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
        return Buffer$1.from(clientCredentials).toString("base64");
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
        return await new SignJWT({ random: randomBytes(8).toString("hex") })
            .setProtectedHeader({ alg: "HS256", typ: "JWT" })
            .setExpirationTime(expirationTime.toDate())
            .setIssuedAt(issuedTime.toDate())
            .setIssuer(ISSUER_URN)
            .sign(this.encodedSecret);
    }
    async verifyState(state) {
        try {
            await jwtVerify(state, this.encodedSecret, {
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
                    defaultLogger.setLevel(options.logLevel ?? LogLevel.ERROR);
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
        return this.hasSecureOptions() ? createServer : createServer$1;
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
                            : this.writeResponse(res, StatusCode.OK, defaultInstallTemplate(fullUrl), stateCookie));
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
                            await this.writeResponse(res, StatusCode.OK, defaultCallbackSuccessTemplate(), deletionStateCookie);
                            return;
                        }
                        catch (err) {
                            const htmlTemplate = isCoreError(err) ?
                                defaultCallbackKnownErrorTemplate(err.name, err.message)
                                : defaultCallbackUnknownErrorTemplate();
                            const deletionStateCookie = this.buildDeletedStateCookieHeader(installerOptions.stateCookieName);
                            await this.writeResponse(res, StatusCode.INTERNAL_SERVER_ERROR, htmlTemplate, deletionStateCookie);
                            return;
                        }
                    }
                }
                // This section is only applicable if we have a webhooks secret token—if we don't, then this
                // receiver is, in effect, just for OAuth usage, meaning installing and validating.
                if (this.options.webhooksSecretToken) {
                    // We currently only support a single endpoint, though this will change in the future.
                    if (!this.hasEndpoint(pathname)) {
                        await this.writeResponse(res, StatusCode.NOT_FOUND);
                        return;
                    }
                    // We currently only support POST requests, as that's what Zoom sends.
                    if (req.method !== "post" && req.method !== "POST") {
                        await this.writeResponse(res, StatusCode.METHOD_NOT_ALLOWED);
                        return;
                    }
                    try {
                        const { webhooksSecretToken } = this.options;
                        const request = await CommonHttpRequest.buildFromIncomingMessage(req, webhooksSecretToken);
                        const processedEvent = request.processEvent();
                        if (isHashedUrlValidation(processedEvent)) {
                            await this.writeResponse(res, StatusCode.OK, processedEvent);
                        }
                        else {
                            await this.eventEmitter?.emit(processedEvent.event, processedEvent);
                            await this.writeResponse(res, StatusCode.OK, { message: "Zoom event processed successfully." });
                        }
                    }
                    catch (err) {
                        if (isCoreError(err, "CommonHttpRequestError")) {
                            await this.writeResponse(res, StatusCode.BAD_REQUEST, { error: err.message });
                        }
                        else {
                            console.error(err);
                            await this.writeResponse(res, StatusCode.INTERNAL_SERVER_ERROR, {
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
            res.writeHead(StatusCode.TEMPORARY_REDIRECT, { Location: location });
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
            `${basename(process.title)}/${process.version.replace("v", "")} ` +
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

class UsersEndpoints extends WebEndpoints {
    contactGroups = {
        listContactGroups: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/contacts/groups` }),
        createContactGroup: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/contacts/groups` }),
        getContactGroup: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/contacts/groups/${groupId}` }),
        deleteContactGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ groupId }) => `/contacts/groups/${groupId}`
        }),
        updateContactGroup: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ groupId }) => `/contacts/groups/${groupId}` }),
        listContactGroupMembers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/contacts/groups/${groupId}/members` }),
        addContactGroupMembers: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ groupId }) => `/contacts/groups/${groupId}/members` }),
        removeMembersInContactGroup: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ groupId }) => `/contacts/groups/${groupId}/members` })
    };
    divisions = {
        listDivisions: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/divisions` }),
        createDivision: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/divisions` }),
        getDivision: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ divisionId }) => `/divisions/${divisionId}`
        }),
        deleteDivision: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ divisionId }) => `/divisions/${divisionId}`
        }),
        updateDivision: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ divisionId }) => `/divisions/${divisionId}` }),
        listDivisionMembers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ divisionId }) => `/divisions/${divisionId}/users` }),
        assignDivision: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ divisionId }) => `/divisions/${divisionId}/users` })
    };
    groups = {
        listGroups: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/groups`
        }),
        createGroup: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/groups`
        }),
        getGroup: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ groupId }) => `/groups/${groupId}`
        }),
        deleteGroup: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ groupId }) => `/groups/${groupId}`
        }),
        updateGroup: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ groupId }) => `/groups/${groupId}`
        }),
        listGroupAdmins: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/admins` }),
        addGroupAdmins: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/admins` }),
        deleteGroupAdmin: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ groupId, userId }) => `/groups/${groupId}/admins/${userId}`
        }),
        listGroupChannels: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/channels` }),
        getLockedSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/lock_settings` }),
        updateLockedSettings: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/lock_settings` }),
        listGroupMembers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/members` }),
        addGroupMembers: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/members` }),
        deleteGroupMember: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ groupId, memberId }) => `/groups/${groupId}/members/${memberId}`
        }),
        updateGroupMember: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ groupId, memberId }) => `/groups/${groupId}/members/${memberId}` }),
        getGroupsSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/settings` }),
        updateGroupsSettings: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/settings` }),
        getGroupsWebinarRegistrationSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/settings/registration` }),
        updateGroupsWebinarRegistrationSettings: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/settings/registration` }),
        uploadVirtualBackgroundFiles: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ groupId }) => `/groups/${groupId}/settings/virtual_backgrounds`,
            requestMimeType: "multipart/form-data"
        }),
        deleteVirtualBackgroundFiles: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ groupId }) => `/groups/${groupId}/settings/virtual_backgrounds` })
    };
    users = {
        listUsers: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/users`
        }),
        createUsers: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: () => `/users`
        }),
        checkUserEmail: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/users/email` }),
        bulkUpdateFeaturesForUsers: this.buildEndpoint({ method: "POST", urlPathBuilder: () => `/users/features` }),
        getUsersZAK: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/users/me/zak`
        }),
        getUserSummary: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: () => `/users/summary`
        }),
        checkUsersPMRoom: this.buildEndpoint({ method: "GET", urlPathBuilder: () => `/users/vanity_name` }),
        getUser: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ userId }) => `/users/${userId}`
        }),
        deleteUser: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId }) => `/users/${userId}`
        }),
        updateUser: this.buildEndpoint({
            method: "PATCH",
            urlPathBuilder: ({ userId }) => `/users/${userId}`
        }),
        listUserAssistants: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/users/${userId}/assistants` }),
        addAssistants: this.buildEndpoint({ method: "POST", urlPathBuilder: ({ userId }) => `/users/${userId}/assistants` }),
        deleteUserAssistants: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId }) => `/users/${userId}/assistants`
        }),
        deleteUserAssistant: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, assistantId }) => `/users/${userId}/assistants/${assistantId}`
        }),
        listUsersCollaborationDevices: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/users/${userId}/collaboration_devices` }),
        getCollaborationDeviceDetail: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ userId, collaborationDeviceId }) => `/users/${userId}/collaboration_devices/${collaborationDeviceId}`
        }),
        updateUsersEmail: this.buildEndpoint({
            method: "PUT",
            urlPathBuilder: ({ userId }) => `/users/${userId}/email`
        }),
        getMeetingTemplateDetail: this.buildEndpoint({
            method: "GET",
            urlPathBuilder: ({ userId, meetingTemplateId }) => `/users/${userId}/meeting_templates/${meetingTemplateId}`
        }),
        updateUsersPassword: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ userId }) => `/users/${userId}/password` }),
        getUserPermissions: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/users/${userId}/permissions` }),
        uploadUsersProfilePicture: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ userId }) => `/users/${userId}/picture`,
            requestMimeType: "multipart/form-data"
        }),
        deleteUsersProfilePicture: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId }) => `/users/${userId}/picture`
        }),
        getUserPresenceStatus: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/users/${userId}/presence_status` }),
        updateUsersPresenceStatus: this.buildEndpoint({ method: "PUT", urlPathBuilder: ({ userId }) => `/users/${userId}/presence_status` }),
        listUserSchedulers: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/users/${userId}/schedulers` }),
        deleteUserSchedulers: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId }) => `/users/${userId}/schedulers`
        }),
        deleteScheduler: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId, schedulerId }) => `/users/${userId}/schedulers/${schedulerId}`
        }),
        getUserSettings: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/users/${userId}/settings` }),
        updateUserSettings: this.buildEndpoint({ method: "PATCH", urlPathBuilder: ({ userId }) => `/users/${userId}/settings` }),
        uploadVirtualBackgroundFiles: this.buildEndpoint({
            method: "POST",
            urlPathBuilder: ({ userId }) => `/users/${userId}/settings/virtual_backgrounds`,
            requestMimeType: "multipart/form-data"
        }),
        deleteVirtualBackgroundFiles: this.buildEndpoint({ method: "DELETE", urlPathBuilder: ({ userId }) => `/users/${userId}/settings/virtual_backgrounds` }),
        updateUserStatus: this.buildEndpoint({
            method: "PUT",
            urlPathBuilder: ({ userId }) => `/users/${userId}/status`
        }),
        getUsersToken: this.buildEndpoint({ method: "GET", urlPathBuilder: ({ userId }) => `/users/${userId}/token` }),
        revokeUsersSSOToken: this.buildEndpoint({
            method: "DELETE",
            urlPathBuilder: ({ userId }) => `/users/${userId}/token`
        })
    };
}

class UsersEventProcessor extends EventManager {
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
const DEFAULT_LOGLEVEL = LogLevel.ERROR;
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

class UsersOAuthClient extends ProductClient {
    initAuth({ clientId, clientSecret, tokenStore, ...restOptions }) {
        const oAuth = new OAuth({ clientId, clientSecret, tokenStore });
        if (hasInstallerOptions(restOptions)) {
            oAuth.setInstallerOptions(restOptions.installerOptions);
        }
        return oAuth;
    }
    initEndpoints(auth, options) {
        return new UsersEndpoints({ auth, ...options });
    }
    initEventProcessor(endpoints) {
        return new UsersEventProcessor(endpoints);
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

class UsersS2SAuthClient extends ProductClient {
    initAuth({ clientId, clientSecret, tokenStore, accountId }) {
        return new S2SAuth({ clientId, clientSecret, tokenStore, accountId });
    }
    initEndpoints(auth, options) {
        return new UsersEndpoints({ auth, ...options });
    }
    initEventProcessor(endpoints) {
        return new UsersEventProcessor(endpoints);
    }
}

export { ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, CommonHttpRequestError, ConsoleLogger, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, LogLevel, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, ReceiverInconsistentStateError, ReceiverOAuthFlowError, S2SRawResponseError, StatusCode, UsersEndpoints, UsersEventProcessor, UsersOAuthClient, UsersS2SAuthClient, isCoreError, isStateStore };
