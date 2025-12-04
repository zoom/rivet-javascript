import { AxiosResponse } from 'axios';
import { LambdaFunctionURLResult, LambdaFunctionURLHandler } from 'aws-lambda';
import { Server } from 'node:http';
import { ServerOptions } from 'node:https';

declare enum LogLevel {
    ERROR = "error",
    WARN = "warn",
    INFO = "info",
    DEBUG = "debug"
}
interface Logger {
    /**
     * Output debug message
     * @param msg any data to be logged
     */
    debug(...msg: unknown[]): void;
    /**
     * Output info message
     * @param msg any data to be logged
     */
    info(...msg: unknown[]): void;
    /**
     * Output warn message
     * @param msg any data to be logged
     */
    warn(...msg: unknown[]): void;
    /**
     * Output error message
     * @param msg any data to be logged
     */
    error(...msg: unknown[]): void;
    /**
     * Disables all logging below the given level
     * @param level as a string, 'error' | 'warn' | 'info' | 'debug'
     */
    setLevel(level: LogLevel): void;
    /**
     * Return the current LogLevel.
     */
    getLevel(): LogLevel;
    /**
     * Name the instance so that it can be filtered when many loggers are sending output
     * to the same destination.
     * @param name as a string
     */
    setName(name: string): void;
}
declare class ConsoleLogger implements Logger {
    private level;
    private name;
    private static labels;
    private static severity;
    constructor();
    getLevel(): LogLevel;
    setLevel(level: LogLevel): void;
    setName(name: string): void;
    debug(...msg: unknown[]): void;
    info(...msg: unknown[]): void;
    warn(...msg: unknown[]): void;
    error(...msg: unknown[]): void;
    private static isMoreOrEqualSevere;
}

type AllPropsOptional<T, True, False> = Exclude<{
    [P in keyof T]: undefined extends T[P] ? True : False;
}[keyof T], undefined> extends True ? True : False;
type Constructor<T> = new (...args: any[]) => T;
type MaybeArray<T> = T | T[];
type MaybePromise<T> = T | Promise<T>;
type StringIndexed<V = any> = Record<string, V>;

interface TokenStore<Token> {
    getLatestToken(): MaybePromise<Token | null | undefined>;
    storeToken(token: Token): MaybePromise<void>;
}

interface AuthOptions<Token> {
    clientId: string;
    clientSecret: string;
    tokenStore?: TokenStore<Token> | undefined;
    logger?: Logger;
}
type OAuthGrantType = "authorization_code" | "client_credentials" | "refresh_token" | "account_credentials";
interface BaseOAuthRequest {
    grant_type: OAuthGrantType;
}
interface OAuthAuthorizationCodeRequest extends BaseOAuthRequest {
    code: string;
    grant_type: "authorization_code";
    redirect_uri?: string;
}
interface OAuthRefreshTokenRequest extends BaseOAuthRequest {
    grant_type: "refresh_token";
    refresh_token: string;
}
interface S2SAuthTokenRequest extends BaseOAuthRequest {
    grant_type: "account_credentials";
    account_id: string;
}
type OAuthRequest = OAuthAuthorizationCodeRequest | OAuthRefreshTokenRequest | S2SAuthTokenRequest;
/**
 * {@link Auth} is the base implementation of authentication for Zoom's APIs.
 *
 * It only requires a `clientId` and `tokenStore`, as these options are shared across
 * all authentication implementations, namely OAuth and server-to-server auth (client
 * credentials, JWT, and server-to-server OAuth.)
 */
declare abstract class Auth<Token = unknown> {
    protected readonly clientId: string;
    protected readonly clientSecret: string;
    protected readonly tokenStore: TokenStore<Token>;
    protected readonly logger: Logger | undefined;
    constructor({ clientId, clientSecret, tokenStore, logger }: AuthOptions<Token>);
    protected getBasicAuthorization(): string;
    abstract getToken(): MaybePromise<string>;
    protected isAlmostExpired(isoTime: string): boolean;
    protected makeOAuthTokenRequest<T extends OAuthGrantType>(grantType: T, payload?: Omit<Extract<OAuthRequest, {
        grant_type: T;
    }>, "grant_type">): Promise<AxiosResponse>;
}

interface ClientCredentialsToken {
    accessToken: string;
    expirationTimeIso: string;
    scopes: string[];
}

interface JwtToken {
    token: string;
    expirationTimeIso: string;
}

interface S2SAuthToken {
    accessToken: string;
    expirationTimeIso: string;
    scopes: string[];
}
interface S2SAuthOptions {
    accountId: string;
}
declare class S2SAuth extends Auth<S2SAuthToken> {
    private accountId;
    constructor({ accountId, ...restOptions }: AuthOptions<S2SAuthToken> & S2SAuthOptions);
    private assertRawToken;
    private fetchAccessToken;
    getToken(): Promise<string>;
    private mapAccessToken;
}

interface Event<Type extends string> {
    event: Type;
}
type EventKeys<T> = T extends Event<infer U> ? U : never;
type EventPayload<T, K> = Extract<T, {
    event: K;
}>;
type EventListenerFn<Events, EventName extends EventKeys<Events>, ReturnType = MaybePromise<void>> = (payload: EventPayload<Events, EventName>) => ReturnType;
type EventListenerPredicateFn<Events, EventName extends EventKeys<Events>> = EventListenerFn<Events, EventName, MaybePromise<boolean>>;
type ContextListener<Events, EventName extends EventKeys<Events>, Context> = (_: EventPayload<Events, EventName> & Context) => MaybePromise<void>;
type GenericEventManager = EventManager<any, any>;
declare class EventManager<Endpoints, Events> {
    protected endpoints: Endpoints;
    constructor(endpoints: Endpoints);
    private appendListener;
    filteredEvent<EventName extends EventKeys<Events>>(eventName: EventName, predicate: EventListenerPredicateFn<Events, EventName>, listener: EventListenerFn<Events, EventName>): void;
    emit<EventName extends EventKeys<Events>>(eventName: EventName, payload: EventPayload<Events, EventName>): Promise<void>;
    event<EventName extends EventKeys<Events>>(eventName: EventName, listener: EventListenerFn<Events, EventName>): void;
    protected withContext<EventName extends EventKeys<Events>, Context>(): ContextListener<Events, EventName, Context>;
}

declare enum StatusCode {
    OK = 200,
    TEMPORARY_REDIRECT = 302,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    INTERNAL_SERVER_ERROR = 500
}
interface ReceiverInitOptions {
    eventEmitter?: GenericEventManager | undefined;
    interactiveAuth?: InteractiveAuth | undefined;
}
interface Receiver {
    canInstall(): true | false;
    init(options: ReceiverInitOptions): void;
    start(...args: any[]): MaybePromise<unknown>;
    stop(...args: any[]): MaybePromise<unknown>;
}

interface HttpReceiverOptions extends Partial<SecureServerOptions> {
    endpoints?: MaybeArray<string> | undefined;
    logger?: Logger | undefined;
    logLevel?: LogLevel | undefined;
    port?: number | string | undefined;
    webhooksSecretToken?: string | undefined;
}
type SecureServerOptions = {
    [K in (typeof secureServerOptionKeys)[number]]: ServerOptions[K];
};
declare const secureServerOptionKeys: (keyof ServerOptions)[];
declare class HttpReceiver implements Receiver {
    private eventEmitter?;
    private interactiveAuth?;
    private server?;
    private logger;
    constructor(options: HttpReceiverOptions);
    canInstall(): true;
    private buildDeletedStateCookieHeader;
    private buildStateCookieHeader;
    private getRequestCookie;
    private getServerCreator;
    private hasEndpoint;
    private hasSecureOptions;
    init({ eventEmitter, interactiveAuth }: ReceiverInitOptions): void;
    private setResponseCookie;
    private areNormalizedUrlsEqual;
    start(port?: number | string): Promise<Server>;
    stop(): Promise<void>;
    private writeTemporaryRedirect;
    private writeResponse;
}

interface BaseResponse<Data = unknown> {
    data?: Data | undefined;
    statusCode: number;
    trackingId?: string | undefined;
}
interface BuildEndpointOptions<PathSchema> {
    method: HttpMethod;
    baseUrlOverride?: string | undefined;
    urlPathBuilder: (params: PathSchema) => string;
    requestMimeType?: RequestMimeType;
}
interface WebEndpointOptions {
    auth: Auth;
    baseUrl?: string | undefined;
    doubleEncodeUrl?: boolean | undefined;
    timeout?: number | undefined;
    userAgentName?: string | undefined;
}
type EndpointArguments<PathSchema extends StringIndexed | NoParams, BodySchema extends StringIndexed | NoParams, QuerySchema extends StringIndexed | NoParams> = (PathSchema extends NoParams ? object : AllPropsOptional<PathSchema, "t", "f"> extends "t" ? {
    path?: PathSchema;
} : {
    path: PathSchema;
}) & (BodySchema extends NoParams ? object : AllPropsOptional<BodySchema, "t", "f"> extends "t" ? {
    body?: BodySchema;
} : {
    body: BodySchema;
}) & (QuerySchema extends NoParams ? object : AllPropsOptional<QuerySchema, "t", "f"> extends "t" ? {
    query?: QuerySchema;
} : {
    query: QuerySchema;
});
type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
type NoParams = "_NO_PARAMS_";
type RequestMimeType = "application/json" | "multipart/form-data";
declare class WebEndpoints {
    constructor(options: WebEndpointOptions);
    protected buildEndpoint<PathSchema extends StringIndexed | NoParams, BodySchema extends StringIndexed | NoParams, QuerySchema extends StringIndexed | NoParams, ResponseData = unknown>({ method, baseUrlOverride, urlPathBuilder, requestMimeType }: BuildEndpointOptions<PathSchema>): (_: EndpointArguments<PathSchema, BodySchema, QuerySchema>) => Promise<BaseResponse<ResponseData>>;
    private buildUserAgent;
    private getCustomUserAgentName;
    private getHeaders;
    private getRequestBody;
    private isOk;
    private isZoomResponseError;
    private makeRequest;
}

type CommonClientOptions<A extends Auth, R extends Receiver> = GetAuthOptions<A> & ExtractInstallerOptions<A, R> & Pick<WebEndpointOptions, "userAgentName"> & {
    disableReceiver?: boolean | undefined;
    logger?: Logger | undefined;
    logLevel?: LogLevel | undefined;
};
interface ClientReceiverOptions<R extends Receiver> {
    receiver: R;
}
type ClientConstructorOptions<A extends Auth, O extends CommonClientOptions<A, R>, R extends Receiver> = (O & {
    disableReceiver: true;
}) | (O & (ClientReceiverOptions<R> | HttpReceiverOptions));
type ExtractInstallerOptions<A extends Auth, R extends Receiver> = A extends InteractiveAuth ? [
    ReturnType<R["canInstall"]>
] extends [true] ? WideInstallerOptions : object : object;
type ExtractAuthTokenType<A> = A extends Auth<infer T> ? T : never;
type GetAuthOptions<A extends Auth> = AuthOptions<ExtractAuthTokenType<A>> & (A extends S2SAuth ? S2SAuthOptions : object);
type WideInstallerOptions = {
    installerOptions: InstallerOptions;
};
declare abstract class ProductClient<AuthType extends Auth, EndpointsType extends WebEndpoints, EventProcessorType extends GenericEventManager, OptionsType extends CommonClientOptions<AuthType, ReceiverType>, ReceiverType extends Receiver> {
    private readonly auth;
    readonly endpoints: EndpointsType;
    readonly webEventConsumer?: EventProcessorType | undefined;
    private readonly receiver?;
    constructor(options: ClientConstructorOptions<AuthType, OptionsType, ReceiverType>);
    protected abstract initAuth(options: OptionsType): AuthType;
    protected abstract initEndpoints(auth: AuthType, options: OptionsType): EndpointsType;
    protected abstract initEventProcessor(endpoints: EndpointsType, options: OptionsType): EventProcessorType | undefined;
    private initDefaultReceiver;
    start(): Promise<ReturnType<ReceiverType["start"]>>;
}

/**
 * {@link StateStore} defines methods for generating and verifying OAuth state.
 *
 * This interface is implemented internally for the default state store; however,
 * it can also be implemented and passed to an OAuth client as well.
 */
interface StateStore {
    /**
     * Generate a new state string, which is directly appended to the OAuth `state` parameter.
     */
    generateState(): MaybePromise<string>;
    /**
     * Verify that the state received during OAuth callback is valid and not forged.
     *
     * If state verification fails, {@link OAuthStateVerificationFailedError} should be thrown.
     *
     * @param state The state parameter that was received during OAuth callback
     */
    verifyState(state: string): MaybePromise<void>;
}
/**
 * Guard if an object implements the {@link StateStore} interface — most notably,
 * `generateState()` and `verifyState(state: string)`.
 */
declare const isStateStore: (obj: unknown) => obj is StateStore;

interface AuthorizationUrlResult {
    fullUrl: string;
    generatedState: string;
}
interface InstallerOptions {
    directInstall?: boolean | undefined;
    installPath?: string | undefined;
    redirectUri: string;
    redirectUriPath?: string | undefined;
    stateStore: StateStore | string;
    stateCookieName?: string | undefined;
    stateCookieMaxAge?: number | undefined;
}
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
declare abstract class InteractiveAuth<Token = unknown> extends Auth<Token> {
    installerOptions?: ReturnType<typeof this.setInstallerOptions>;
    getAuthorizationUrl(): Promise<AuthorizationUrlResult>;
    getFullRedirectUri(): string;
    setInstallerOptions({ directInstall, installPath, redirectUri, redirectUriPath, stateStore, stateCookieName, stateCookieMaxAge }: InstallerOptions): {
        directInstall: boolean;
        installPath: string;
        redirectUri: string;
        redirectUriPath: string;
        stateStore: StateStore;
        stateCookieName: string;
        stateCookieMaxAge: number;
    };
}

/**
 * Credentials for access token & refresh token, which are used to access Zoom's APIs.
 *
 * As access token is short-lived (usually a single hour), its expiration time is checked
 * first. If it's possible to use the access token, it's used; however, if it has expired
 * or is close to expiring, the refresh token should be used to generate a new access token
 * before the API call is made. Refresh tokens are generally valid for 90 days.
 *
 * If neither the access token nor the refresh token is available, {@link OAuthTokenRefreshFailedError}
 * shall be thrown, informing the developer that neither value can be used, and the user must re-authorize.
 * It's likely that this error will be rare, but it _can_ be thrown.
 */
interface OAuthToken {
    accessToken: string;
    expirationTimeIso: string;
    refreshToken: string;
    scopes: string[];
}
declare class OAuth extends InteractiveAuth<OAuthToken> {
    private assertResponseAccessToken;
    private fetchAccessToken;
    getToken(): Promise<string>;
    initRedirectCode(code: string): Promise<void>;
    private mapOAuthToken;
    private refreshAccessToken;
}

interface RivetError<ErrorCode extends string = string> extends Error {
    readonly errorCode: ErrorCode;
}

declare const isCoreError: <K extends "ApiResponseError" | "AwsReceiverRequestError" | "ClientCredentialsRawResponseError" | "S2SRawResponseError" | "CommonHttpRequestError" | "ReceiverInconsistentStateError" | "ReceiverOAuthFlowError" | "HTTPReceiverConstructionError" | "HTTPReceiverPortNotNumberError" | "HTTPReceiverRequestError" | "OAuthInstallerNotInitializedError" | "OAuthTokenDoesNotExistError" | "OAuthTokenFetchFailedError" | "OAuthTokenRawResponseError" | "OAuthTokenRefreshFailedError" | "OAuthStateVerificationFailedError" | "ProductClientConstructionError">(obj: unknown, key?: K | undefined) => obj is RivetError<{
    readonly ApiResponseError: "zoom_rivet_api_response_error";
    readonly AwsReceiverRequestError: "zoom_rivet_aws_receiver_request_error";
    readonly ClientCredentialsRawResponseError: "zoom_rivet_client_credentials_raw_response_error";
    readonly S2SRawResponseError: "zoom_rivet_s2s_raw_response_error";
    readonly CommonHttpRequestError: "zoom_rivet_common_http_request_error";
    readonly ReceiverInconsistentStateError: "zoom_rivet_receiver_inconsistent_state_error";
    readonly ReceiverOAuthFlowError: "zoom_rivet_receiver_oauth_flow_error";
    readonly HTTPReceiverConstructionError: "zoom_rivet_http_receiver_construction_error";
    readonly HTTPReceiverPortNotNumberError: "zoom_rivet_http_receiver_port_not_number_error";
    readonly HTTPReceiverRequestError: "zoom_rivet_http_receiver_request_error";
    readonly OAuthInstallerNotInitializedError: "zoom_rivet_oauth_installer_not_initialized_error";
    readonly OAuthTokenDoesNotExistError: "zoom_rivet_oauth_does_not_exist_error";
    readonly OAuthTokenFetchFailedError: "zoom_rivet_oauth_token_fetch_failed_error";
    readonly OAuthTokenRawResponseError: "zoom_rivet_oauth_token_raw_response_error";
    readonly OAuthTokenRefreshFailedError: "zoom_rivet_oauth_token_refresh_failed_error";
    readonly OAuthStateVerificationFailedError: "zoom_rivet_oauth_state_verification_failed_error";
    readonly ProductClientConstructionError: "zoom_rivet_product_client_construction_error";
}[K]>;
declare const ApiResponseError: Constructor<Error>;
declare const AwsReceiverRequestError: Constructor<Error>;
declare const ClientCredentialsRawResponseError: Constructor<Error>;
declare const S2SRawResponseError: Constructor<Error>;
declare const CommonHttpRequestError: Constructor<Error>;
declare const ReceiverInconsistentStateError: Constructor<Error>;
declare const ReceiverOAuthFlowError: Constructor<Error>;
declare const HTTPReceiverConstructionError: Constructor<Error>;
declare const HTTPReceiverPortNotNumberError: Constructor<Error>;
declare const HTTPReceiverRequestError: Constructor<Error>;
declare const OAuthInstallerNotInitializedError: Constructor<Error>;
declare const OAuthTokenDoesNotExistError: Constructor<Error>;
declare const OAuthTokenFetchFailedError: Constructor<Error>;
declare const OAuthTokenRawResponseError: Constructor<Error>;
declare const OAuthTokenRefreshFailedError: Constructor<Error>;
declare const OAuthStateVerificationFailedError: Constructor<Error>;
declare const ProductClientConstructionError: Constructor<Error>;

interface AwsLambdaReceiverOptions {
    webhooksSecretToken: string;
}
declare class AwsLambdaReceiver implements Receiver {
    private eventEmitter?;
    private readonly webhooksSecretToken;
    constructor({ webhooksSecretToken }: AwsLambdaReceiverOptions);
    buildResponse(statusCode: StatusCode, body: object): LambdaFunctionURLResult;
    canInstall(): false;
    init({ eventEmitter }: ReceiverInitOptions): void;
    start(): LambdaFunctionURLHandler;
    stop(): Promise<void>;
}

type AppSendAppNotificationsRequestBody = {
    notification_id?: string;
    message?: {
        text?: string;
    };
    user_id?: string;
};
type AppGetUserOrAccountEventSubscriptionQueryParams = {
    page_size?: number;
    next_page_token?: string;
    user_id: string;
    subscription_scope?: "user" | "account" | "master_account";
    account_id: string;
};
type AppGetUserOrAccountEventSubscriptionResponse = {
    next_page_token?: string;
    page_size?: number;
} & {
    event_subscriptions?: {
        event_subscription_id?: string;
        events?: string[];
        event_subscription_name?: string;
        event_webhook_url?: string;
        subscription_scope?: "user" | "account" | "master_account";
        created_source?: "default" | "openapi";
        subscriber_id?: string;
    }[];
};
type AppCreateEventSubscriptionRequestBody = {
    events: string[];
    event_subscription_name?: string;
    event_webhook_url: string;
    user_ids?: string[];
    subscription_scope: "user" | "account" | "master_account";
    account_id?: string;
};
type AppCreateEventSubscriptionResponse = {
    event_subscription_id?: string;
};
type AppUnsubscribeAppEventSubscriptionQueryParams = {
    event_subscription_id: string;
    user_ids?: string;
    account_id: string;
};
type AppDeleteEventSubscriptionPathParams = {
    eventSubscriptionId: string;
};
type AppSubscribeEventSubscriptionPathParams = {
    eventSubscriptionId: string;
};
type AppSubscribeEventSubscriptionRequestBody = {
    user_ids?: string[];
    account_id: string;
};
type AppListAppsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    type?: "active_requests" | "past_requests" | "public" | "account_created" | "approved_apps" | "restricted_apps" | "account_added";
};
type AppListAppsResponse = {
    next_page_token?: string;
    page_size?: number;
} & {
    apps?: {
        app_id?: string;
        app_name?: string;
        app_type?: "ZoomApp" | "ChatBotApp" | "OAuthApp" | "GeneralApp";
        app_usage?: 1 | 2;
        app_status?: "PUBLISHED" | "UNPUBLISHED" | "SHARABLE";
        request_id?: string;
        request_total_number?: number;
        request_pending_number?: number;
        request_approved_number?: number;
        request_declined_number?: number;
        latest_request_date_time?: string;
        reviewer_name?: string;
        review_date_time?: string;
        app_developer_type?: "THIRD_PARTY" | "ZOOM" | "INTERNAL";
        app_description?: string;
        app_icon?: string;
        scopes?: {
            scope_name?: string;
            scope_description?: string;
        }[];
        app_privacy_policy_url?: string;
        app_directory_url?: string;
        app_help_url?: string;
        restricted_time?: string;
        approval_info?: {
            approved_type?: "forAllUser" | "forSpecificUser";
            approver_id?: string;
            approved_time?: string;
            app_approval_closed?: boolean;
        };
    }[];
};
type AppCreateAppsRequestBody = {
    app_type: "s2s_oauth" | "meeting_sdk" | "general";
    app_name: string;
    scopes?: string[];
    contact_name: string;
    contact_email: string;
    company_name: string;
    active?: boolean;
    publish?: boolean;
    manifest?: object;
};
type AppCreateAppsResponse = {
    created_at?: string;
    app_id?: string;
    app_name?: string;
    app_type?: "s2s_oauth" | "meeting_sdk";
    scopes?: string[];
    production_credentials?: {
        client_id?: string;
        client_secret?: string;
    };
    development_credentials?: {
        client_id?: string;
        client_secret?: string;
    };
};
type AppGetInformationAboutAppPathParams = {
    appId: string;
};
type AppGetInformationAboutAppResponse = {
    app_id?: string;
    app_name?: string;
    app_description?: string;
    app_type?: "ZoomApp" | "ChatBotApp" | "OAuthApp";
    app_usage?: 1 | 2;
    app_status?: "PUBLISHED" | "UNPUBLISHED";
    app_links?: {
        documentation_url?: string;
        privacy_policy_url?: string;
        support_url?: string;
        terms_of_use_url?: string;
    };
    app_permissions?: {
        group?: string;
        group_message?: string;
        title?: string;
        permissions?: {
            name?: string;
        }[];
    }[];
    app_requirements?: {
        user_role?: "admin" | "user";
        min_client_version?: string;
        account_eligibility?: {
            account_types?: string[];
            premium_events?: {
                event_name?: string;
                event?: string;
            }[];
        };
    };
    app_scopes?: string[];
};
type AppDeletesAppPathParams = {
    appId: string;
};
type AppGetAPICallLogsPathParams = {
    appId: string;
};
type AppGetAPICallLogsQueryParams = {
    next_page_token?: string;
    page_size?: number;
    duration?: 7 | 14 | 30;
    query?: string;
    method?: "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH";
    status_code?: 400 | 401 | 403 | 404 | 409 | 429 | 500 | 501 | 502 | 503 | 504 | 505 | 506 | 507 | 508 | 510 | 511;
};
type AppGetAPICallLogsResponse = {
    next_page_token?: string;
    page_size?: number;
    call_logs?: {
        url_pattern?: string;
        time?: string;
        http_status?: 200 | 201 | 202 | 203 | 204 | 205 | 300 | 301 | 302 | 303 | 304 | 305 | 306 | 307 | 308 | 400 | 401 | 403 | 404 | 405 | 406 | 408 | 409 | 429 | 500 | 501 | 502 | 503 | 504 | 505 | 506 | 507 | 508 | 510 | 511;
        method?: "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH";
        trace_id?: string;
    }[];
};
type AppGenerateZoomAppDeeplinkPathParams = {
    appId: string;
};
type AppGenerateZoomAppDeeplinkRequestBody = {
    type: 1 | 2;
    target: "meeting" | "panel" | "modal";
    action: string;
};
type AppGenerateZoomAppDeeplinkResponse = {
    deeplink: string;
};
type AppUpdateAppPreApprovalSettingPathParams = {
    appId: string;
};
type AppUpdateAppPreApprovalSettingRequestBody = {
    action?: "approve_all" | "approve_user" | "disapprove_user" | "approve_group" | "disapprove_group" | "disapprove_all";
    user_ids?: string[];
    group_ids?: string[];
};
type AppUpdateAppPreApprovalSettingResponse = {
    executed_at?: string;
    user_ids?: string[];
    group_ids?: string[];
};
type AppGetAppsUserRequestsPathParams = {
    appId: string;
};
type AppGetAppsUserRequestsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    status?: "pending" | "approved" | "rejected";
};
type AppGetAppsUserRequestsResponse = {
    next_page_token?: string;
    page_size?: number;
} & {
    requests?: {
        request_user_id?: string;
        request_user_name?: string;
        request_user_email?: string;
        request_user_department?: string;
        request_date_time?: string;
        reason?: string;
        status?: "pending" | "approved" | "rejected";
    }[];
};
type AppAddAppAllowRequestsForUsersPathParams = {
    appId: string;
};
type AppAddAppAllowRequestsForUsersRequestBody = {
    action: "add_all" | "add_user" | "add_group";
    user_ids?: string[];
    group_ids?: string[];
};
type AppAddAppAllowRequestsForUsersResponse = {
    added_at?: string;
    user_ids?: string[];
    group_ids?: string[];
};
type AppUpdateAppsRequestStatusPathParams = {
    appId: string;
};
type AppUpdateAppsRequestStatusRequestBody = {
    action: "approve_all" | "approve" | "decline_all" | "decline" | "cancel";
    request_user_ids?: string[];
};
type AppRotateClientSecretPathParams = {
    appId: string;
};
type AppRotateClientSecretRequestBody = {
    action: "new" | "update";
    revoke_old_secret_time: string;
};
type AppRotateClientSecretResponse = {
    secret_id: string;
    new_secret: string;
    revoke_old_secret_time: string;
} | {
    secret_id: string;
    revoke_old_secret_time: string;
};
type AppGetWebhookLogsPathParams = {
    appId: string;
};
type AppGetWebhookLogsQueryParams = {
    next_page_token?: string;
    page_size?: number;
    from?: string;
    to?: string;
    event?: string;
    type?: 1 | 2 | 3;
    retry_num?: number;
};
type AppGetWebhookLogsResponse = {
    next_page_token?: string;
    page_size?: number;
    webhook_logs?: {
        event?: string;
        status?: number;
        failed_reason_type?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16;
        user_id?: string;
        endpoint?: string;
        subscription_id?: string;
        request_headers?: string;
        request_body?: string;
        response_headers?: string;
        response_body?: string;
        date_time?: string;
        trace_id?: string;
        request_id?: string;
        retry_num?: 0 | 1 | 2 | 3;
    }[];
};
type AppGetAppUserEntitlementsQueryParams = {
    user_id?: string;
};
type AppGetAppUserEntitlementsResponse = {
    id?: string;
    plan_name?: string;
    plan_id?: string;
}[];
type AppGetUsersAppRequestsPathParams = {
    userId: string;
};
type AppGetUsersAppRequestsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    type?: "active_requests" | "past_requests";
};
type AppGetUsersAppRequestsResponse = {
    next_page_token?: string;
    page_size?: number;
} & {
    apps?: {
        app_id?: string;
        app_name?: string;
        app_type?: "ZoomApp" | "ChatBotApp" | "OAuthApp";
        app_usage?: 1 | 2;
        app_status?: "PUBLISHED" | "UNPUBLISHED";
        request_id?: string;
        request_date_time?: string;
        request_status?: "pending" | "approved" | "rejected";
    }[];
};
type AppEnableOrDisableUserAppSubscriptionPathParams = {
    appId: string;
    userId: string;
};
type AppEnableOrDisableUserAppSubscriptionRequestBody = {
    action: "enable" | "disable";
};
type AppGetUsersEntitlementsPathParams = {
    userId: string;
};
type AppGetUsersEntitlementsResponse = {
    entitlements?: {
        entitlement_id?: number;
    }[];
};
type AppsGenerateAppDeeplinkRequestBody = {
    type?: 1 | 2;
    user_id?: string;
    action?: string;
};
type AppsGenerateAppDeeplinkResponse = {
    deeplink?: string;
};
type ManifestValidateAppManifestRequestBody = {
    manifest: object;
    app_id?: string;
};
type ManifestValidateAppManifestResponse = {
    ok?: boolean;
    error?: string;
    errors?: {
        message: string;
        setting: string;
    }[];
};
type ManifestExportAppManifestFromExistingAppPathParams = {
    appId: string;
};
type ManifestExportAppManifestFromExistingAppResponse = {
    manifest?: object;
};
type ManifestUpdateAppByManifestPathParams = {
    appId: string;
};
type ManifestUpdateAppByManifestRequestBody = {
    manifest: object;
};
declare class MarketplaceEndpoints extends WebEndpoints {
    readonly app: {
        sendAppNotifications: (_: object & {
            body?: AppSendAppNotificationsRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        getUserOrAccountEventSubscription: (_: object & {
            query: AppGetUserOrAccountEventSubscriptionQueryParams;
        }) => Promise<BaseResponse<AppGetUserOrAccountEventSubscriptionResponse>>;
        createEventSubscription: (_: object & {
            body: AppCreateEventSubscriptionRequestBody;
        }) => Promise<BaseResponse<AppCreateEventSubscriptionResponse>>;
        unsubscribeAppEventSubscription: (_: object & {
            query: AppUnsubscribeAppEventSubscriptionQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        deleteEventSubscription: (_: {
            path: AppDeleteEventSubscriptionPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        subscribeEventSubscription: (_: {
            path: AppSubscribeEventSubscriptionPathParams;
        } & {
            body: AppSubscribeEventSubscriptionRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listApps: (_: object & {
            query?: AppListAppsQueryParams;
        }) => Promise<BaseResponse<AppListAppsResponse>>;
        createApps: (_: object & {
            body: AppCreateAppsRequestBody;
        }) => Promise<BaseResponse<AppCreateAppsResponse>>;
        getInformationAboutApp: (_: {
            path: AppGetInformationAboutAppPathParams;
        } & object) => Promise<BaseResponse<AppGetInformationAboutAppResponse>>;
        deletesApp: (_: {
            path: AppDeletesAppPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getAPICallLogs: (_: {
            path: AppGetAPICallLogsPathParams;
        } & object & {
            query?: AppGetAPICallLogsQueryParams;
        }) => Promise<BaseResponse<AppGetAPICallLogsResponse>>;
        generateZoomAppDeeplink: (_: {
            path: AppGenerateZoomAppDeeplinkPathParams;
        } & {
            body: AppGenerateZoomAppDeeplinkRequestBody;
        } & object) => Promise<BaseResponse<AppGenerateZoomAppDeeplinkResponse>>;
        updateAppPreApprovalSetting: (_: {
            path: AppUpdateAppPreApprovalSettingPathParams;
        } & {
            body?: AppUpdateAppPreApprovalSettingRequestBody;
        } & object) => Promise<BaseResponse<AppUpdateAppPreApprovalSettingResponse>>;
        getAppsUserRequests: (_: {
            path: AppGetAppsUserRequestsPathParams;
        } & object & {
            query?: AppGetAppsUserRequestsQueryParams;
        }) => Promise<BaseResponse<AppGetAppsUserRequestsResponse>>;
        addAppAllowRequestsForUsers: (_: {
            path: AppAddAppAllowRequestsForUsersPathParams;
        } & {
            body: AppAddAppAllowRequestsForUsersRequestBody;
        } & object) => Promise<BaseResponse<AppAddAppAllowRequestsForUsersResponse>>;
        updateAppsRequestStatus: (_: {
            path: AppUpdateAppsRequestStatusPathParams;
        } & {
            body: AppUpdateAppsRequestStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        rotateClientSecret: (_: {
            path: AppRotateClientSecretPathParams;
        } & {
            body: AppRotateClientSecretRequestBody;
        } & object) => Promise<BaseResponse<AppRotateClientSecretResponse>>;
        getWebhookLogs: (_: {
            path: AppGetWebhookLogsPathParams;
        } & object & {
            query?: AppGetWebhookLogsQueryParams;
        }) => Promise<BaseResponse<AppGetWebhookLogsResponse>>;
        getAppUserEntitlements: (_: object & {
            query?: AppGetAppUserEntitlementsQueryParams;
        }) => Promise<BaseResponse<AppGetAppUserEntitlementsResponse>>;
        getUsersAppRequests: (_: {
            path: AppGetUsersAppRequestsPathParams;
        } & object & {
            query?: AppGetUsersAppRequestsQueryParams;
        }) => Promise<BaseResponse<AppGetUsersAppRequestsResponse>>;
        enableOrDisableUserAppSubscription: (_: {
            path: AppEnableOrDisableUserAppSubscriptionPathParams;
        } & {
            body: AppEnableOrDisableUserAppSubscriptionRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUsersEntitlements: (_: {
            path: AppGetUsersEntitlementsPathParams;
        } & object) => Promise<BaseResponse<AppGetUsersEntitlementsResponse>>;
    };
    readonly apps: {
        generateAppDeeplink: (_: object & {
            body?: AppsGenerateAppDeeplinkRequestBody;
        }) => Promise<BaseResponse<AppsGenerateAppDeeplinkResponse>>;
    };
    readonly manifest: {
        validateAppManifest: (_: object & {
            body: ManifestValidateAppManifestRequestBody;
        }) => Promise<BaseResponse<ManifestValidateAppManifestResponse>>;
        exportAppManifestFromExistingApp: (_: {
            path: ManifestExportAppManifestFromExistingAppPathParams;
        } & object) => Promise<BaseResponse<ManifestExportAppManifestFromExistingAppResponse>>;
        updateAppByManifest: (_: {
            path: ManifestUpdateAppByManifestPathParams;
        } & {
            body: ManifestUpdateAppByManifestRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
}

type AppDeauthorizedEvent = Event<"app_deauthorized"> & {
    event?: string;
    payload?: {
        user_id?: string;
        account_id?: string;
        client_id?: string;
        deauthorization_time?: string;
        signature?: string;
        event_ts?: number;
    };
};
type AppAuthorizationRequestCreatedEvent = Event<"app.authorization_request_created"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        app_name?: string;
        app_type?: string;
        app_status?: "published" | "development";
        app_description?: string;
        app_link?: {
            developer_documentation?: string;
            developer_privacy_policy?: string;
            developer_support?: string;
            developer_terms_of_use?: string;
        };
    };
};
type MarketplaceEvents = AppDeauthorizedEvent | AppAuthorizationRequestCreatedEvent;
declare class MarketplaceEventProcessor extends EventManager<MarketplaceEndpoints, MarketplaceEvents> {
}

type MarketplaceOAuthOptions<R extends Receiver> = CommonClientOptions<OAuth, R>;
declare class MarketplaceOAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<OAuth, ReceiverType> = MarketplaceOAuthOptions<ReceiverType>> extends ProductClient<OAuth, MarketplaceEndpoints, MarketplaceEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, ...restOptions }: OptionsType): OAuth;
    protected initEndpoints(auth: OAuth, options: OptionsType): MarketplaceEndpoints;
    protected initEventProcessor(endpoints: MarketplaceEndpoints): MarketplaceEventProcessor;
}

type MarketplaceS2SAuthOptions<R extends Receiver> = CommonClientOptions<S2SAuth, R>;
declare class MarketplaceS2SAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<S2SAuth, ReceiverType> = MarketplaceS2SAuthOptions<ReceiverType>> extends ProductClient<S2SAuth, MarketplaceEndpoints, MarketplaceEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, accountId }: OptionsType): S2SAuth;
    protected initEndpoints(auth: S2SAuth, options: OptionsType): MarketplaceEndpoints;
    protected initEventProcessor(endpoints: MarketplaceEndpoints): MarketplaceEventProcessor;
}

export { ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, CommonHttpRequestError, ConsoleLogger, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, LogLevel, MarketplaceEndpoints, MarketplaceEventProcessor, MarketplaceOAuthClient, MarketplaceS2SAuthClient, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, ReceiverInconsistentStateError, ReceiverOAuthFlowError, S2SRawResponseError, StatusCode, isCoreError, isStateStore };
export type { AppAddAppAllowRequestsForUsersPathParams, AppAddAppAllowRequestsForUsersRequestBody, AppAddAppAllowRequestsForUsersResponse, AppAuthorizationRequestCreatedEvent, AppCreateAppsRequestBody, AppCreateAppsResponse, AppCreateEventSubscriptionRequestBody, AppCreateEventSubscriptionResponse, AppDeauthorizedEvent, AppDeleteEventSubscriptionPathParams, AppDeletesAppPathParams, AppEnableOrDisableUserAppSubscriptionPathParams, AppEnableOrDisableUserAppSubscriptionRequestBody, AppGenerateZoomAppDeeplinkPathParams, AppGenerateZoomAppDeeplinkRequestBody, AppGenerateZoomAppDeeplinkResponse, AppGetAPICallLogsPathParams, AppGetAPICallLogsQueryParams, AppGetAPICallLogsResponse, AppGetAppUserEntitlementsQueryParams, AppGetAppUserEntitlementsResponse, AppGetAppsUserRequestsPathParams, AppGetAppsUserRequestsQueryParams, AppGetAppsUserRequestsResponse, AppGetInformationAboutAppPathParams, AppGetInformationAboutAppResponse, AppGetUserOrAccountEventSubscriptionQueryParams, AppGetUserOrAccountEventSubscriptionResponse, AppGetUsersAppRequestsPathParams, AppGetUsersAppRequestsQueryParams, AppGetUsersAppRequestsResponse, AppGetUsersEntitlementsPathParams, AppGetUsersEntitlementsResponse, AppGetWebhookLogsPathParams, AppGetWebhookLogsQueryParams, AppGetWebhookLogsResponse, AppListAppsQueryParams, AppListAppsResponse, AppRotateClientSecretPathParams, AppRotateClientSecretRequestBody, AppRotateClientSecretResponse, AppSendAppNotificationsRequestBody, AppSubscribeEventSubscriptionPathParams, AppSubscribeEventSubscriptionRequestBody, AppUnsubscribeAppEventSubscriptionQueryParams, AppUpdateAppPreApprovalSettingPathParams, AppUpdateAppPreApprovalSettingRequestBody, AppUpdateAppPreApprovalSettingResponse, AppUpdateAppsRequestStatusPathParams, AppUpdateAppsRequestStatusRequestBody, AppsGenerateAppDeeplinkRequestBody, AppsGenerateAppDeeplinkResponse, ClientCredentialsToken, HttpReceiverOptions, JwtToken, Logger, ManifestExportAppManifestFromExistingAppPathParams, ManifestExportAppManifestFromExistingAppResponse, ManifestUpdateAppByManifestPathParams, ManifestUpdateAppByManifestRequestBody, ManifestValidateAppManifestRequestBody, ManifestValidateAppManifestResponse, MarketplaceEvents, MarketplaceOAuthOptions, MarketplaceS2SAuthOptions, OAuthToken, Receiver, ReceiverInitOptions, S2SAuthToken, StateStore, TokenStore };
