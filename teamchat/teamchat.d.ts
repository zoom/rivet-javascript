import { AxiosResponse } from 'axios';
import { LambdaFunctionURLResult, LambdaFunctionURLHandler } from 'aws-lambda';
import { Server } from 'node:http';
import { ServerOptions } from 'node:https';
import { ReadStream } from 'node:fs';

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

type AllKeysOf<T> = T extends any ? keyof T : never;
type AllPropsOptional<T, True, False> = Exclude<{
    [P in keyof T]: undefined extends T[P] ? True : False;
}[keyof T], undefined> extends True ? True : False;
type Constructor<T> = new (...args: any[]) => T;
type ExactlyOneOf<T extends any[]> = {
    [K in keyof T]: T[K] & ProhibitKeys<Exclude<AllKeysOf<T[number]>, keyof T[K]>>;
}[number];
type MaybeArray<T> = T | T[];
type MaybePromise<T> = T | Promise<T>;
type ProhibitKeys<K extends keyof any> = Partial<Record<K, never>>;
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

type ChatChannelMentionGroupListChannelMentionGroupsPathParams = {
    channelId: string;
};
type ChatChannelMentionGroupListChannelMentionGroupsResponse = {
    mention_group_list: {
        mention_group_id: string;
        mention_group_name: string;
        mention_group_description?: string;
    }[];
};
type ChatChannelMentionGroupCreateChannelMentionGroupPathParams = {
    channelId: string;
};
type ChatChannelMentionGroupCreateChannelMentionGroupRequestBody = {
    mention_group_name: string;
    mention_group_description?: string;
    identifiers: string[];
};
type ChatChannelMentionGroupCreateChannelMentionGroupResponse = {
    mention_group_id: string;
};
type ChatChannelMentionGroupDeleteChannelMentionGroupPathParams = {
    channelId: string;
    mentionGroupId: string;
};
type ChatChannelMentionGroupUpdateChannelMentionGroupInformationPathParams = {
    channelId: string;
    mentionGroupId: string;
};
type ChatChannelMentionGroupUpdateChannelMentionGroupInformationRequestBody = {
    mention_group_name?: string;
    mention_group_description?: string;
};
type ChatChannelMentionGroupListMembersOfMentionGroupPathParams = {
    channelId: string;
    mentionGroupId: string;
};
type ChatChannelMentionGroupListMembersOfMentionGroupQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type ChatChannelMentionGroupListMembersOfMentionGroupResponse = {
    mention_group_id: string;
    members?: {
        user_id?: string;
        member_id?: string;
        email?: string;
        first_name?: string;
        last_name?: string;
        disaplay_name?: string;
        is_external?: boolean;
    }[];
    next_page_token?: string;
    page_size: number;
    has_more: boolean;
};
type ChatChannelMentionGroupAddChannelMembersToMentionGroupPathParams = {
    channelId: string;
    mentionGroupId: string;
};
type ChatChannelMentionGroupAddChannelMembersToMentionGroupRequestBody = {
    identifiers: string[];
};
type ChatChannelMentionGroupRemoveChannelMentionGroupMembersPathParams = {
    channelId: string;
    mentionGroupId: string;
};
type ChatChannelMentionGroupRemoveChannelMentionGroupMembersQueryParams = {
    identifiers: string;
};
type ChatChannelsListChannelActivityLogsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    activity_type?: "membership";
    start_date: string;
    end_date: string;
    channel_id?: string;
};
type ChatChannelsListChannelActivityLogsResponse = {
    channel_activity_logs: {
        channel_id: string;
        activity_type: "membership";
        activity_timestamp: number;
        operator: {
            display_name?: string;
            user_id?: string;
            member_id?: string;
        };
        members?: {
            member_status?: "joined" | "left";
            member_list?: {
                display_name?: string;
                user_id?: string;
                member_id?: string;
            }[];
        };
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ChatChannelsPerformOperationsOnChannelsRequestBody = {
    method: "archive" | "unarchive";
    channel_ids: string[];
};
type ChatChannelsPerformOperationsOnChannelsResponse = {
    failed_channels?: {
        channel_id?: string;
        reason?: string;
        error_code?: string;
    }[];
};
type ChatChannelsGetChannelPathParams = {
    channelId: string;
};
type ChatChannelsGetChannelResponse = {
    channel_settings?: {
        add_member_permissions?: 1 | 2;
        new_members_can_see_previous_messages_files?: boolean;
        posting_permissions?: 1 | 2 | 3;
        mention_all_permissions?: 1 | 2 | 3;
        allow_to_add_external_users?: 0 | 1 | 2 | 3;
        designated_posting_members?: {
            member_id?: string;
            user_id?: string;
        }[];
    };
    id?: string;
    jid?: string;
    name?: string;
    type?: 0 | 1 | 2 | 3 | 4 | 5;
    channel_url?: string;
};
type ChatChannelsDeleteChannelPathParams = {
    channelId: string;
};
type ChatChannelsUpdateChannelPathParams = {
    channelId: string;
};
type ChatChannelsUpdateChannelRequestBody = {
    name?: string;
    channel_settings?: {
        add_member_permissions?: 1 | 2;
        new_members_can_see_previous_messages_files?: boolean;
        posting_permissions?: 1 | 2 | 3;
        mention_all_permissions?: 1 | 2 | 3;
        designated_posting_members?: ({
            user_id?: string;
        } | {
            member_id?: string;
        })[];
    };
    type?: 1 | 2 | 3 | 5;
};
type ChatChannelsListChannelMembersPathParams = {
    channelId: string;
};
type ChatChannelsListChannelMembersQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type ChatChannelsListChannelMembersResponse = {
    members?: {
        email?: string;
        first_name?: string;
        id?: string;
        member_id?: string;
        last_name?: string;
        name?: string;
        role?: "admin" | "owner" | "member";
        is_external?: boolean;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type ChatChannelsInviteChannelMembersPathParams = {
    channelId: string;
};
type ChatChannelsInviteChannelMembersRequestBody = {
    members?: {
        email: string;
    }[];
};
type ChatChannelsInviteChannelMembersResponse = {
    added_at?: string;
    ids?: string;
    member_ids?: string;
};
type ChatChannelsBatchRemoveMembersFromChannelPathParams = {
    channelId: string;
};
type ChatChannelsBatchRemoveMembersFromChannelQueryParams = {
    member_ids: string;
    user_ids: string;
};
type ChatChannelsListChannelMembersGroupsPathParams = {
    channelId: string;
};
type ChatChannelsListChannelMembersGroupsResponse = {
    groups: {
        group_id: string;
        group_name: string;
    }[];
    channel_id: string;
};
type ChatChannelsInviteChannelMembersGroupsPathParams = {
    channelId: string;
};
type ChatChannelsInviteChannelMembersGroupsRequestBody = {
    groups?: {
        group_id: string;
    }[];
};
type ChatChannelsInviteChannelMembersGroupsResponse = {
    added_at: string;
    groups: {
        group_id: string;
        group_name: string;
    }[];
};
type ChatChannelsRemoveMemberGroupPathParams = {
    channelId: string;
    groupId: string;
};
type ChatChannelsJoinChannelPathParams = {
    channelId: string;
};
type ChatChannelsJoinChannelResponse = {
    added_at?: string;
    id?: string;
    member_id?: string;
};
type ChatChannelsLeaveChannelPathParams = {
    channelId: string;
};
type ChatChannelsRemoveMemberPathParams = {
    channelId: string;
    identifier: string;
};
type ChatChannelsListUsersChannelsPathParams = {
    userId: string;
};
type ChatChannelsListUsersChannelsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type ChatChannelsListUsersChannelsResponse = {
    channels?: {
        channel_settings?: {
            add_member_permissions?: 1 | 2;
            new_members_can_see_previous_messages_files?: boolean;
            posting_permissions?: 1 | 2 | 3;
            mention_all_permissions?: 1 | 2 | 3;
            allow_to_add_external_users?: 0 | 1 | 2 | 3;
        };
        id?: string;
        jid?: string;
        name?: string;
        type?: 0 | 1 | 2 | 3 | 4 | 5;
        channel_url?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type ChatChannelsCreateChannelPathParams = {
    userId: string;
};
type ChatChannelsCreateChannelRequestBody = {
    channel_settings?: {
        add_member_permissions?: 1 | 2;
        new_members_can_see_previous_messages_files?: boolean;
        posting_permissions?: 1 | 2 | 3;
        mention_all_permissions?: 1 | 2 | 3;
    };
    members?: {
        email: string;
    }[];
    name?: string;
    type?: 1 | 2 | 3 | 4;
    shared_space?: {
        space_id: string;
        space_channel_type?: "private" | "public_for_members";
    };
};
type ChatChannelsCreateChannelResponse = {
    id?: string;
    jid?: string;
    name?: string;
    type?: 1 | 2 | 3 | 4;
    channel_url?: string;
};
type ChatChannelsAccountLevelBatchDeleteChannelsPathParams = {
    userId: string;
};
type ChatChannelsAccountLevelBatchDeleteChannelsQueryParams = {
    channel_ids: string;
};
type ChatChannelsAccountLevelListAccountsPublicChannelsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type ChatChannelsAccountLevelListAccountsPublicChannelsResponse = {
    channels?: {
        channel_settings?: {
            add_member_permissions?: 1 | 2;
            new_members_can_see_previous_messages_files?: boolean;
            posting_permissions?: 1 | 2 | 3;
            mention_all_permissions?: 1 | 2 | 3;
            allow_to_add_external_users?: 0 | 1 | 2 | 3;
        };
        id?: string;
        jid?: string;
        name?: string;
        type?: 0 | 1 | 2 | 3 | 4 | 5;
        channel_url?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type ChatChannelsAccountLevelSearchUsersOrAccountsChannelsRequestBody = {
    user_id?: string;
    page_size?: number;
    next_page_token?: string;
    needle: {
        search_type: "by_channel_name";
        keywords: string[];
    } | {
        search_type: "by_channel_name_exact_match";
        channel_name: string;
    };
    haystack: "user_joined" | "public" | "all";
    include_archived?: boolean;
};
type ChatChannelsAccountLevelSearchUsersOrAccountsChannelsResponse = {
    channels: {
        id: string;
        name: string;
        type: 0 | 1 | 2 | 3 | 4 | 5;
        channel_url: string;
        member_count: number;
    }[];
    next_page_token?: string;
    page_size: number;
};
type ChatChannelsAccountLevelListChannelActivityLogsPathParams = {
    channelId: string;
};
type ChatChannelsAccountLevelListChannelActivityLogsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    activity_type?: "membership";
    start_date: string;
    end_date: string;
};
type ChatChannelsAccountLevelListChannelActivityLogsResponse = {
    channel_activity_logs: {
        activity_type: "membership";
        activity_timestamp: number;
        operator: {
            display_name?: string;
            user_id?: string;
            member_id?: string;
        };
        members?: {
            member_status?: "joined" | "left";
            member_list?: {
                display_name?: string;
                user_id?: string;
                member_id?: string;
            }[];
        };
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ChatChannelsAccountLevelGetRetentionPolicyOfChannelPathParams = {
    channelId: string;
};
type ChatChannelsAccountLevelGetRetentionPolicyOfChannelResponse = {
    channel_id: string;
    cloud_retention: {
        enable_custom_retention: boolean;
        retention_period: string;
    };
};
type ChatChannelsAccountLevelUpdateRetentionPolicyOfChannelPathParams = {
    channelId: string;
};
type ChatChannelsAccountLevelUpdateRetentionPolicyOfChannelRequestBody = {
    cloud_retention: {
        enable_custom_retention: boolean;
        retention_period?: string;
    };
};
type ChatChannelsAccountLevelGetChannelPathParams = {
    channelId: string;
    userId: string;
};
type ChatChannelsAccountLevelGetChannelResponse = {
    channel_settings?: {
        add_member_permissions?: 1 | 2;
        new_members_can_see_previous_messages_files?: boolean;
        posting_permissions?: 1 | 2 | 3;
        mention_all_permissions?: 1 | 2 | 3;
        allow_to_add_external_users?: 0 | 1 | 2 | 3;
        designated_posting_members?: {
            member_id?: string;
            user_id?: string;
        }[];
    };
    id?: string;
    jid?: string;
    name?: string;
    type?: 0 | 1 | 2 | 3 | 4 | 5;
    channel_url?: string;
};
type ChatChannelsAccountLevelDeleteChannelPathParams = {
    channelId: string;
    userId: string;
};
type ChatChannelsAccountLevelUpdateChannelPathParams = {
    channelId: string;
    userId: string;
};
type ChatChannelsAccountLevelUpdateChannelRequestBody = {
    name?: string;
    channel_settings?: {
        add_member_permissions?: 1 | 2;
        new_members_can_see_previous_messages_files?: boolean;
        posting_permissions?: 1 | 2 | 3;
        mention_all_permissions?: 1 | 2 | 3;
        designated_posting_members?: ({
            user_id?: string;
        } | {
            member_id?: string;
        })[];
    };
    type?: 1 | 2 | 3 | 5;
};
type ChatChannelsAccountLevelListChannelAdministratorsPathParams = {
    userId: string;
    channelId: string;
};
type ChatChannelsAccountLevelListChannelAdministratorsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type ChatChannelsAccountLevelListChannelAdministratorsResponse = {
    admins?: {
        email?: string;
        first_name?: string;
        id?: string;
        member_id?: string;
        role?: "admin" | "owner";
        last_name?: string;
        name?: string;
        is_external?: boolean;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsPathParams = {
    userId: string;
    channelId: string;
};
type ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsRequestBody = {
    admins?: ({
        email: string;
    } | {
        member_id: string;
    })[];
};
type ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsResponse = {
    added_at?: string;
    ids?: string;
    member_ids?: string;
};
type ChatChannelsAccountLevelBatchDemoteChannelAdministratorsPathParams = {
    userId: string;
    channelId: string;
};
type ChatChannelsAccountLevelBatchDemoteChannelAdministratorsQueryParams = {
    admin_ids: string;
    user_ids: string;
};
type ChatChannelsAccountLevelListChannelMembersPathParams = {
    channelId: string;
    userId: string;
};
type ChatChannelsAccountLevelListChannelMembersQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type ChatChannelsAccountLevelListChannelMembersResponse = {
    members?: {
        email?: string;
        first_name?: string;
        id?: string;
        member_id?: string;
        last_name?: string;
        name?: string;
        role?: "admin" | "owner" | "member";
        is_external?: boolean;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type ChatChannelsAccountLevelInviteChannelMembersPathParams = {
    channelId: string;
    userId: string;
};
type ChatChannelsAccountLevelInviteChannelMembersRequestBody = {
    members?: {
        email: string;
    }[];
};
type ChatChannelsAccountLevelInviteChannelMembersResponse = {
    added_at?: string;
    ids?: string;
    member_ids?: string;
};
type ChatChannelsAccountLevelBatchRemoveMembersFromUsersChannelPathParams = {
    channelId: string;
    userId: string;
};
type ChatChannelsAccountLevelBatchRemoveMembersFromUsersChannelQueryParams = {
    identifiers: string;
};
type ChatChannelsAccountLevelRemoveMemberPathParams = {
    channelId: string;
    identifier: string;
    userId: string;
};
type ChatEmojiListCustomEmojisQueryParams = {
    page_size?: number;
    search_key?: string;
    next_page_token?: string;
};
type ChatEmojiListCustomEmojisResponse = {
    emojis: {
        file_id: string;
        name: string;
        user_id: string;
        member_id: string;
        user_name: string;
        user_email: string;
        date_added: string;
    }[];
    next_page_token?: string;
    page_size: number;
    search_key?: string;
};
type ChatEmojiAddCustomEmojiRequestBody = {
    name: string;
    file: Blob | Buffer | ReadStream;
};
type ChatEmojiAddCustomEmojiResponse = {
    file_id: string;
    name: string;
};
type ChatEmojiDeleteCustomEmojiPathParams = {
    fileId: string;
};
type ChatFilesGetFileInfoPathParams = {
    fileId: string;
};
type ChatFilesGetFileInfoResponse = {
    file_id: string;
    file_name: string;
    OS_file_type: string;
    length: number;
    digest: string;
    created_time: number;
    modified_time: number;
    download_url: string;
    public_url?: string;
};
type ChatFilesDeleteChatFilePathParams = {
    fileId: string;
};
type ChatFilesUploadChatFilePathParams = {
    userId: string;
};
type ChatFilesUploadChatFileQueryParams = {
    postToPersonalChat?: string;
};
type ChatFilesUploadChatFileRequestBody = {
    file?: Blob | Buffer | ReadStream;
};
type ChatFilesUploadChatFileResponse = {
    id?: string;
};
type ChatFilesSendChatFilePathParams = {
    userId: string;
};
type ChatFilesSendChatFileRequestBody = {
    files: (Blob | Buffer | ReadStream)[];
    reply_main_message_id?: string;
    to_channel?: string;
    to_contact?: string;
};
type ChatFilesSendChatFileResponse = {
    id?: string;
};
type ChatMessagesPerformOperationsOnMessageOfChannelRequestBody = {
    method: "pin" | "unpin";
    message_id: string;
    channel_id: string;
};
type ChatMessagesListPinnedHistoryMessagesOfChannelPathParams = {
    channelId: string;
};
type ChatMessagesListPinnedHistoryMessagesOfChannelQueryParams = {
    page_size?: number;
    next_page_token?: string;
    include_history?: boolean;
};
type ChatMessagesListPinnedHistoryMessagesOfChannelResponse = {
    messages: {
        message_id: string;
        message_timestamp: number;
        pinner_user_id: string;
        pinner_member_id: string;
        pinned_time: string;
        currently_pinned: boolean;
        message: string;
        pinned_by_external_user: boolean;
    }[];
    next_page_token?: string;
    channel_id: string;
    page_size?: number;
};
type ChatMessagesGetForwardedMessagePathParams = {
    forwardId: string;
};
type ChatMessagesGetForwardedMessageResponse = {
    bot_message?: object;
    date_time?: string;
    download_url?: string;
    file_id?: string;
    file_name?: string;
    file_size?: number;
    rich_text?: {
        start_position?: number;
        end_position?: number;
        format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
        format_attr?: string;
    }[];
    files?: {
        download_url?: string;
        file_id?: string;
        file_name?: string;
        file_size?: number;
    }[];
    forward_id?: string;
    message?: string;
    message_type?: "plain_text_message" | "jpg_image_file" | "audio_file" | "video_file" | "png_image_file" | "gif_file" | "giphy_file" | "code_snippet" | "file_and_text" | "others";
    reactions?: {
        emoji?: string;
        total_count?: number;
        user_ids?: string[];
        member_ids?: string[];
    }[];
    reply_main_message_id?: string;
    reply_main_message_timestamp?: number;
    sender?: string;
    send_member_id?: string;
    sender_display_name?: string;
    timestamp?: number;
    at_items?: {
        at_contact?: string;
        at_contact_member_id?: string;
        at_type?: 1 | 2;
        end_position?: number;
        start_position?: number;
    }[];
    interactive_cards?: {
        card_id?: string;
        card_json?: string;
    }[];
};
type ChatMessagesListBookmarksQueryParams = {
    to_contact?: string;
    to_channel?: string;
    page_size?: number;
    next_page_token?: string;
};
type ChatMessagesListBookmarksResponse = {
    next_page_token?: string;
    page_size: number;
    bookmarks: ({
        channel_id: string;
        channel_name: string;
        message: string;
        message_id: string;
        message_timestamp: number;
        sender_user_id: string;
        sender_member_id: string;
        sender_display_name: string;
        is_sent_by_user: boolean;
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
    } | {
        peer_contact_name: string;
        peer_contact_user_id: string;
        peer_contact_member_id: string;
        message: string;
        message_id: string;
        message_timestamp: number;
        is_sent_by_user: boolean;
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
    })[];
};
type ChatMessagesAddOrRemoveBookmarkQueryParams = {
    message_id: string;
};
type ChatMessagesAddOrRemoveBookmarkRequestBody = {
    action: "add_bookmark" | "remove_bookmark";
    to_channel?: string;
    to_contact?: string;
};
type ChatMessagesListScheduledMessagesQueryParams = {
    to_contact?: string;
    to_channel?: string;
    next_page_token?: string;
    page_size?: number;
};
type ChatMessagesListScheduledMessagesResponse = {
    to_channel?: string;
    to_contact?: string;
    page_size: number;
    next_page_token?: string;
    messages: {
        draft_id: string;
        create_date: string;
        scheduled_time: string;
        download_url?: string;
        file_id?: string;
        file_name?: string;
        file_size?: number;
        rich_text?: {
            start_position: number;
            end_position: number;
            format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
            format_attr: string;
        }[];
        files?: {
            download_url: string;
            file_id: string;
            file_name: string;
            file_size: number;
        }[];
        message: string;
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
        at_items?: {
            at_contact: string;
            at_contact_member_id: string;
            at_type: 1 | 2;
            end_position: number;
            start_position: number;
        }[];
    }[];
};
type ChatMessagesDeleteScheduledMessagePathParams = {
    draftId: string;
};
type ChatMessagesDeleteScheduledMessageQueryParams = {
    to_contact?: string;
    to_channel?: string;
};
type ChatMessagesListUsersChatMessagesPathParams = {
    userId: string;
};
type ChatMessagesListUsersChatMessagesQueryParams = {
    to_contact?: string;
    to_channel?: string;
    date?: string;
    from?: string;
    to?: string;
    page_size?: number;
    next_page_token?: string;
    include_deleted_and_edited_message?: boolean;
    search_type?: "message" | "file";
    search_key?: string;
    exclude_child_message?: boolean;
    download_file_formats?: "audio/mp4";
};
type ChatMessagesListUsersChatMessagesResponse = {
    date?: string;
    from?: string;
    messages?: {
        bot_message?: object;
        date_time?: string;
        files?: {
            download_url?: string;
            file_id?: string;
            file_name?: string;
            file_size?: number;
        }[];
        rich_text?: {
            start_position?: number;
            end_position?: number;
            format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
            format_attr?: string;
        }[];
        download_url?: string;
        file_id?: string;
        file_name?: string;
        file_size?: number;
        id?: string;
        message?: string;
        message_type?: "plain_text_message" | "jpg_image_file" | "audio_file" | "video_file" | "png_image_file" | "gif_file" | "giphy_file" | "code_snippet" | "file_and_text" | "others";
        reactions?: {
            emoji?: string;
            total_count?: number;
            senders?: {
                user_id?: string;
                member_id?: string;
            }[];
        }[];
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
        sender?: string;
        send_member_id?: string;
        sender_display_name?: string;
        status?: "Deleted" | "Edited" | "Normal";
        timestamp?: number;
        at_items?: {
            at_contact?: string;
            at_contact_member_id?: string;
            at_type?: 1 | 2;
            end_position?: number;
            start_position?: number;
        }[];
        interactive_cards?: {
            card_id?: string;
            card_json?: string;
        }[];
    }[];
    next_page_token?: string;
    page_size?: number;
    to?: string;
};
type ChatMessagesSendChatMessagePathParams = {
    userId: string;
};
type ChatMessagesSendChatMessageRequestBody = {
    at_items?: {
        at_contact?: string;
        at_type?: 1 | 2;
        end_position?: number;
        start_position?: number;
    }[];
    rich_text?: {
        start_position?: number;
        end_position?: number;
        format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
        format_attr?: string;
    }[];
    message: string;
    file_ids?: string[];
    reply_main_message_id?: string;
    to_channel?: string;
    to_contact?: string;
    interactive_cards?: {
        card_json?: string;
    }[];
    scheduled_time?: string;
};
type ChatMessagesSendChatMessageResponse = {
    id?: string;
};
type ChatMessagesGetMessagePathParams = {
    userId: string;
    messageId: string;
};
type ChatMessagesGetMessageQueryParams = {
    to_contact?: string;
    to_channel?: string;
    download_file_formats?: "audio/mp4";
};
type ChatMessagesGetMessageResponse = {
    bot_message?: object;
    date_time?: string;
    download_url?: string;
    file_id?: string;
    file_name?: string;
    file_size?: number;
    rich_text?: {
        start_position?: number;
        end_position?: number;
        format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
        format_attr?: string;
    }[];
    files?: {
        download_url?: string;
        file_id?: string;
        file_name?: string;
        file_size?: number;
    }[];
    id?: string;
    message?: string;
    message_type?: "plain_text_message" | "jpg_image_file" | "audio_file" | "video_file" | "png_image_file" | "gif_file" | "giphy_file" | "code_snippet" | "file_and_text" | "others";
    reactions?: {
        emoji?: string;
        total_count?: number;
        user_ids?: string[];
        member_ids?: string[];
    }[];
    reply_main_message_id?: string;
    reply_main_message_timestamp?: number;
    sender?: string;
    send_member_id?: string;
    sender_display_name?: string;
    timestamp?: number;
    message_url?: string;
    at_items?: {
        at_contact?: string;
        at_contact_member_id?: string;
        at_type?: 1 | 2;
        end_position?: number;
        start_position?: number;
    }[];
    interactive_cards?: {
        card_id?: string;
        card_json?: string;
    }[];
};
type ChatMessagesUpdateMessagePathParams = {
    userId: string;
    messageId: string;
};
type ChatMessagesUpdateMessageRequestBody = {
    message?: string;
    to_channel?: string;
    to_contact?: string;
    file_ids?: string[];
    interactive_cards?: ({
        card_id?: string;
    } | {
        card_json?: string;
    })[];
};
type ChatMessagesDeleteMessagePathParams = {
    userId: string;
    messageId: string;
};
type ChatMessagesDeleteMessageQueryParams = {
    to_contact?: string;
    to_channel?: string;
};
type ChatMessagesReactToChatMessagePathParams = {
    userId: string;
    messageId: string;
};
type ChatMessagesReactToChatMessageRequestBody = {
    action?: "add" | "remove";
    emoji?: string;
    to_channel?: string;
    to_contact?: string;
    custom_emoji?: boolean;
    custom_emoji_id?: string;
};
type ChatMessagesMarkMessageReadOrUnreadPathParams = {
    userId: string;
    messageId: string;
};
type ChatMessagesMarkMessageReadOrUnreadRequestBody = {
    action?: "read" | "unread";
    timestamp?: number;
    to_channel?: string;
    to_contact?: string;
};
type ChatMessagesRetrieveThreadPathParams = {
    userId: string;
    messageId: string;
};
type ChatMessagesRetrieveThreadQueryParams = {
    to_channel?: string;
    to_contact?: string;
    from: string;
    to?: string;
    limit?: number;
    sort?: "desc" | "asc";
    need_main_message?: boolean;
    need_emoji?: boolean;
    need_attachment?: boolean;
    need_rich_text?: boolean;
    need_at_items?: boolean;
};
type ChatMessagesRetrieveThreadResponse = {
    total: number;
    messages?: {
        msg_id: string;
        message: string;
        is_reply: boolean;
        timestamp: number;
        reactions?: {
            emoji_id?: string;
            count?: number;
            is_sender?: boolean;
        }[];
        last_reply_time?: number;
        is_followed?: boolean;
        files?: {
            file_id?: string;
            file_name?: string;
            file_size?: number;
            download_url?: string;
        }[];
        sender_user_id?: string;
        sender_email?: string;
        sender_member_id?: string;
        sender_display_name?: string;
        rich_text?: {
            start_position?: number;
            end_position?: number;
            format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
            format_attr?: string;
        }[];
        at_items?: {
            at_contact?: string;
            at_contact_member_id?: string;
            at_type?: 1 | 2;
            end_position?: number;
            start_position?: number;
        }[];
        bot_message?: object;
        interactive_cards?: {
            card_id?: string;
            card_json?: string;
        }[];
        message_type?: "plain_text_message" | "jpg_image_file" | "audio_file" | "video_file" | "png_image_file" | "gif_file" | "giphy_file" | "code_snippet" | "file_and_text" | "others";
    }[];
};
type ChatMigrationMigrateChannelMembersPathParams = {
    channelId: string;
};
type ChatMigrationMigrateChannelMembersRequestBody = {
    members: {
        identifier: string;
        role?: "member" | "admin";
    }[];
};
type ChatMigrationMigrateChatMessageReactionsRequestBody = {
    reactions: {
        message_id: string;
        message_timestamp: number;
        to_channel?: string;
        to_contact?: string;
        emojis: {
            emoji: string;
            user_identifier: string[];
        }[];
    }[];
};
type ChatMigrationGetMigratedZoomChannelIDsQueryParams = {
    origin_platform: "slack";
    origin_team_id: string;
    origin_channel_ids: string;
};
type ChatMigrationGetMigratedZoomChannelIDsResponse = {
    mappings_found?: number;
    mappings_not_found?: number;
    mappings?: {
        origin_channel_id?: string;
        zm_channel_id?: string;
    }[];
};
type ChatMigrationGetMigratedZoomUserIDsQueryParams = {
    origin_platform: "slack";
    origin_team_id?: string;
    origin_user_ids: string;
};
type ChatMigrationGetMigratedZoomUserIDsResponse = {
    mappings_found?: number;
    mappings_not_found?: number;
    mappings?: {
        origin_user_id?: string;
        zm_user_id?: string;
    }[];
};
type ChatMigrationMigrateChatMessagesRequestBody = {
    messages: {
        message_timestamp: number;
        sender: string;
        to_channel?: string;
        to_contact?: string;
        message: string;
        file_ids?: string[];
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
    }[];
};
type ChatMigrationMigrateChatMessagesResponse = {
    ids?: string[];
};
type ChatMigrationMigrateChatChannelPathParams = {
    identifier: string;
};
type ChatMigrationMigrateChatChannelRequestBody = {
    members: {
        identifier: string;
        role?: "admin" | "member";
    }[];
    type: 2 | 3 | 4;
    name: string;
    created_time: string;
};
type ChatMigrationMigrateChatChannelResponse = {
    id: string;
};
type ChatMigrationMigrateConversationOrChannelOperationsPathParams = {
    identifier: string;
};
type ChatMigrationMigrateConversationOrChannelOperationsRequestBody = {
    method: "star";
    params: {
        target_id: string;
        target_type: "channel" | "contact";
    }[];
};
type ChatReminderCreateReminderMessagePathParams = {
    messageId: string;
};
type ChatReminderCreateReminderMessageRequestBody = {
    to_contact?: string;
    to_channel?: string;
    remind_time?: string;
    delay_seconds?: number;
    reminder_note?: string;
};
type ChatReminderDeleteReminderForMessagePathParams = {
    messageId: string;
};
type ChatReminderDeleteReminderForMessageQueryParams = {
    to_contact?: string;
    to_channel?: string;
};
type ChatReminderListRemindersQueryParams = {
    to_contact?: string;
    to_channel?: string;
    next_page_token?: string;
    page_size?: number;
};
type ChatReminderListRemindersResponse = {
    next_page_token: string;
    reminders: {
        reminder_note: string;
        content: string;
        message_timestamp: number;
        create_time: string;
        remind_time: string;
        message_id: string;
        main_message_id?: string;
        main_message_timestamp?: number;
    }[];
};
type ChatSessionsStarOrUnstarChannelOrContactUserPathParams = {
    userId: string;
};
type ChatSessionsStarOrUnstarChannelOrContactUserRequestBody = {
    method: "star" | "unstar";
    params: {
        target_id: string;
        target_type: "channel" | "contact";
    };
};
type ChatSessionsListUsersChatSessionsPathParams = {
    userId: string;
};
type ChatSessionsListUsersChatSessionsQueryParams = {
    type?: "1:1" | "groupchat";
    search_star?: boolean;
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
};
type ChatSessionsListUsersChatSessionsResponse = {
    from: string;
    to: string;
    next_page_token: string;
    page_size: number;
    sessions: {
        channel_id?: string;
        last_message_sent_time: string;
        name: string;
        type: string;
        peer_contact_email?: string;
        peer_contact_user_id?: string;
        peer_contact_member_id?: string;
    }[];
} | {
    next_page_token: string;
    page_size: number;
    sessions: {
        channel_id?: string;
        name: string;
        type: string;
        peer_contact_email?: string;
        peer_contact_user_id?: string;
        peer_contact_member_id?: string;
    }[];
};
type ContactsListUsersContactsQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
};
type ContactsListUsersContactsResponse = {
    contacts?: {
        email?: string;
        first_name?: string;
        id?: string;
        member_id?: string;
        last_name?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ContactsGetUsersContactDetailsPathParams = {
    identifier: string;
};
type ContactsGetUsersContactDetailsQueryParams = {
    query_presence_status?: boolean;
};
type ContactsGetUsersContactDetailsResponse = {
    direct_numbers?: string[];
    email?: string;
    extension_number?: string;
    first_name?: string;
    id?: string;
    member_id?: string;
    last_name?: string;
    phone_number?: string;
    phone_numbers?: {
        code?: string;
        country?: string;
        label?: "Mobile" | "Office" | "Home" | "Fax";
        number?: string;
        verified?: boolean;
    }[];
    presence_status?: "Do_Not_Disturb" | "Away" | "Available" | "Offline" | "In_A_Meeting" | "In_A_Call" | "In_A_Calendar_Event" | "Presenting" | "Out_of_Office" | "Busy";
};
type ContactsSearchCompanyContactsQueryParams = {
    search_key: string;
    query_presence_status?: boolean;
    page_size?: number;
    contact_types?: number;
    user_status?: "active" | "inactive";
    next_page_token?: string;
};
type ContactsSearchCompanyContactsResponse = {
    contacts?: {
        contact_type?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
        dept?: string;
        direct_numbers?: string[];
        email?: string;
        extension_number?: string;
        display_name?: string;
        first_name?: string;
        id?: string;
        member_id?: string;
        im_group_id?: string;
        im_group_name?: string;
        job_title?: string;
        last_name?: string;
        location?: string;
        phone_number?: string;
        phone_numbers?: {
            code?: string;
            country?: string;
            label?: "Mobile" | "Office" | "Home" | "Fax";
            number?: string;
            verified?: boolean;
        }[];
        presence_status?: "Do_Not_Disturb" | "Away" | "Available" | "Offline";
        user_status?: "active" | "inactive";
        activity?: "Active" | "Inactive" | "Unknown";
        sip_phone_number?: string;
        sip_uri?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type IMChatSendIMMessagesQueryParams = {
    chat_user?: string;
};
type IMChatSendIMMessagesRequestBody = {
    message?: string;
};
type IMChatSendIMMessagesResponse = {
    id?: string;
};
type IMGroupsListIMDirectoryGroupsResponse = {
    total_records?: number;
} & {
    groups?: ({
        id?: string;
    } & ({
        name?: string;
        total_members?: number;
    } & {
        search_by_account?: boolean;
        search_by_domain?: boolean;
        search_by_ma_account?: boolean;
        type?: "normal" | "shared" | "restricted";
    }))[];
};
type IMGroupsCreateIMDirectoryGroupRequestBody = {
    name?: string;
    search_by_account?: boolean;
    search_by_domain?: boolean;
    search_by_ma_account?: boolean;
    type?: "normal" | "shared" | "restricted";
};
type IMGroupsRetrieveIMDirectoryGroupPathParams = {
    groupId: string;
};
type IMGroupsRetrieveIMDirectoryGroupResponse = {
    id?: string;
} & ({
    name?: string;
    total_members?: number;
} & {
    search_by_account?: boolean;
    search_by_domain?: boolean;
    search_by_ma_account?: boolean;
    type?: "normal" | "shared" | "restricted";
});
type IMGroupsDeleteIMDirectoryGroupPathParams = {
    groupId: string;
};
type IMGroupsUpdateIMDirectoryGroupPathParams = {
    groupId: string;
};
type IMGroupsUpdateIMDirectoryGroupRequestBody = {
    name?: string;
    search_by_account?: boolean;
    search_by_domain?: boolean;
    search_by_ma_account?: boolean;
    type?: "normal" | "shared" | "restricted";
};
type IMGroupsListIMDirectoryGroupMembersPathParams = {
    groupId: string;
};
type IMGroupsListIMDirectoryGroupMembersQueryParams = {
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type IMGroupsListIMDirectoryGroupMembersResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    members?: {
        email?: string;
        first_name?: string;
        id?: string;
        last_name?: string;
        type?: number;
    }[];
};
type IMGroupsAddIMDirectoryGroupMembersPathParams = {
    groupId: string;
};
type IMGroupsAddIMDirectoryGroupMembersRequestBody = {
    members?: {
        email?: string;
        id?: string;
    }[];
};
type IMGroupsAddIMDirectoryGroupMembersResponse = {
    added_at?: string;
    ids?: string;
};
type IMGroupsDeleteIMDirectoryGroupMemberPathParams = {
    groupId: string;
    memberId: string;
};
type InvitationsSendNewContactInvitationPathParams = {
    userId: string;
};
type InvitationsSendNewContactInvitationRequestBody = {
    email: string;
    message?: string;
};
type LegalHoldListLegalHoldMattersQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type LegalHoldListLegalHoldMattersResponse = {
    legal_hold_matters: {
        matter_id: string;
        matter_name: string;
        matter_start_date?: string;
        matter_end_date?: string;
        matter_creation_date: string;
        matter_users: {
            user_id: string;
            email: string;
        }[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type LegalHoldAddLegalHoldMatterRequestBody = {
    start_date?: string;
    end_date?: string;
    matter_name: string;
    identifiers: string[];
};
type LegalHoldAddLegalHoldMatterResponse = {
    matter_id: string;
};
type LegalHoldDeleteLegalHoldMattersPathParams = {
    matterId: string;
};
type LegalHoldUpdateLegalHoldMatterPathParams = {
    matterId: string;
};
type LegalHoldUpdateLegalHoldMatterRequestBody = {
    matter_name: string;
};
type LegalHoldListLegalHoldFilesByGivenMatterPathParams = {
    matterId: string;
};
type LegalHoldListLegalHoldFilesByGivenMatterQueryParams = {
    identifier: string;
    page_size?: number;
    next_page_token?: string;
};
type LegalHoldListLegalHoldFilesByGivenMatterResponse = {
    data: {
        file_key: string;
        file_count: number;
        file_start_date: string;
        file_end_date: string;
        ready_for_download: boolean;
        total_file_size: number;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type LegalHoldDownloadLegalHoldFilesForGivenMatterPathParams = {
    matterId: string;
};
type LegalHoldDownloadLegalHoldFilesForGivenMatterQueryParams = {
    file_key: string;
};
type ReportsGetChatSessionsReportsQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
};
type ReportsGetChatSessionsReportsResponse = {
    from?: string;
    next_page_token?: string;
    page_size?: number;
    sessions?: {
        id?: string;
        last_message_sent_time?: string;
        name?: string;
        type?: "Group" | "1:1";
        channel_id?: string;
        member_emails?: string[];
        status?: "active" | "deleted";
        has_external_member?: boolean;
    }[];
    to?: string;
};
type ReportsGetChatMessageReportsPathParams = {
    sessionId: string;
};
type ReportsGetChatMessageReportsQueryParams = {
    from: string;
    to: string;
    next_page_token?: string;
    page_size?: number;
    include_fields?: "edited_messages" | "deleted_messages" | "edited_messages,deleted_messages";
    include_bot_message?: boolean;
    include_reactions?: boolean;
    query_all_modifications?: boolean;
};
type ReportsGetChatMessageReportsResponse = {
    deleted_messages?: {
        date_time?: string;
        files?: {
            download_url?: string;
            file_id?: string;
            file_name?: string;
            file_size?: number;
        }[];
        giphy_information?: {
            giphy_view_url?: string;
        }[];
        id?: string;
        message?: string;
        receiver?: string;
        is_sender_external?: boolean;
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
        sender?: string;
        sender_member_id?: string;
        sender_display_name?: string;
        timestamp?: number;
        action_timestamp?: number;
        forward_id?: string;
        rich_text?: {
            start_position?: number;
            end_position?: number;
            format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
            format_attr?: string;
        }[];
    }[];
    edited_messages?: {
        date_time?: string;
        files?: {
            download_url?: string;
            file_id?: string;
            file_name?: string;
            file_size?: number;
        }[];
        giphy_information?: {
            giphy_view_url?: string;
        }[];
        id?: string;
        message?: string;
        receiver?: string;
        is_sender_external?: boolean;
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
        sender_member_id?: string;
        sender?: string;
        sender_display_name?: string;
        timestamp?: number;
        action_timestamp?: number;
        forward_id?: string;
        rich_text?: {
            start_position?: number;
            end_position?: number;
            format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
            format_attr?: string;
        }[];
    }[];
    from?: string;
    messages?: {
        date_time?: string;
        files?: {
            download_url?: string;
            file_id?: string;
            file_name?: string;
            file_size?: number;
        }[];
        giphy_information?: {
            giphy_view_url?: string;
        }[];
        id?: string;
        message?: string;
        reactions?: {
            emoji?: string;
            total_count?: number;
            user_ids?: string[];
            member_ids?: string[];
        }[];
        receiver?: string;
        is_sender_external?: boolean;
        reply_main_message_id?: string;
        reply_main_message_timestamp?: number;
        sender?: string;
        sender_member_id?: string;
        sender_display_name?: string;
        timestamp?: number;
        action_timestamp?: number;
        forward_id?: string;
        bot_message?: {
            is_markdown_support?: boolean;
            source?: string;
            external_sender_email?: string;
            content?: object;
        };
        rich_text?: {
            start_position?: number;
            end_position?: number;
            format_type?: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
            format_attr?: string;
        }[];
    }[];
    next_page_token?: string;
    page_size?: number;
    to?: string;
};
type SharedSpacesListSharedSpacesQueryParams = {
    next_page_token?: string;
    page_size?: string;
    user_id?: string;
};
type SharedSpacesListSharedSpacesResponse = {
    next_page_token?: string;
    page_size?: number;
    shared_spaces: {
        space_id: string;
        space_name: string;
        space_desc?: string;
        space_owner: {
            user_id?: string;
            member_id: string;
            email?: string;
            display_name: string;
            is_external_user: boolean;
        };
    }[];
};
type SharedSpacesCreateSharedSpaceRequestBody = {
    space_name: string;
    space_desc?: string;
    space_members?: {
        identifier: string;
        role?: "admin" | "member" | "owner";
    }[];
    space_settings?: {
        allow_to_add_external_users?: 0 | 1 | 2 | 3;
        add_member_permissions?: 1 | 2;
        create_channels_permission?: 1 | 2;
    };
};
type SharedSpacesCreateSharedSpaceResponse = {
    space_id: string;
    channel_id: string;
    space_name: string;
    space_desc?: string;
    space_members?: {
        identifier?: string;
        role?: "admin" | "member" | "owner";
    }[];
    space_settings?: {
        allow_to_add_external_users?: 0 | 1 | 2 | 3;
        add_member_permissions?: 1 | 2;
        create_channels_permission?: 1 | 2;
    };
};
type SharedSpacesGetSharedSpacePathParams = {
    spaceId: string;
};
type SharedSpacesGetSharedSpaceResponse = {
    space_id: string;
    space_name: string;
    space_desc?: string;
    owner: {
        user_id?: string;
        member_id: string;
        email?: string;
        display_name: string;
        is_external_user: boolean;
    };
    space_settings: {
        allow_to_add_external_users?: 0 | 1 | 2 | 3;
        add_member_permissions?: 1 | 2;
        create_channels_permission?: 1 | 2;
    };
};
type SharedSpacesDeleteSharedSpacePathParams = {
    spaceId: string;
};
type SharedSpacesUpdateSharedSpaceSettingsPathParams = {
    spaceId: string;
};
type SharedSpacesUpdateSharedSpaceSettingsRequestBody = {
    space_name?: string;
    space_desc?: string;
    space_settings?: {
        allow_to_add_external_users?: 0 | 1 | 2 | 3;
        add_member_permissions?: 1 | 2;
        create_channels_permission?: 1 | 2;
    };
};
type SharedSpacesPromoteSharedSpaceMembersToAdministratorsPathParams = {
    spaceId: string;
};
type SharedSpacesPromoteSharedSpaceMembersToAdministratorsRequestBody = {
    members: {
        identifier: string;
    }[];
};
type SharedSpacesPromoteSharedSpaceMembersToAdministratorsResponse = {
    successful_operations_count: number;
    unsuccessful_operations_count: number;
    users: {
        user_id: string;
        member_id: string;
        is_external_user: boolean;
        operation_status: "successful" | "unsuccessful";
    }[];
};
type SharedSpacesDemoteSharedSpaceAdministratorsToMembersPathParams = {
    spaceId: string;
};
type SharedSpacesDemoteSharedSpaceAdministratorsToMembersQueryParams = {
    identifiers: string;
};
type SharedSpacesDemoteSharedSpaceAdministratorsToMembersResponse = {
    successful_operations_count: number;
    unsuccessful_operations_count: number;
    users: {
        user_id: string;
        member_id: string;
        is_external_user: boolean;
        operation_status: "successful" | "unsuccessful";
    }[];
};
type SharedSpacesListSharedSpaceChannelsPathParams = {
    spaceId: string;
};
type SharedSpacesListSharedSpaceChannelsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type SharedSpacesListSharedSpaceChannelsResponse = {
    next_page_token?: string;
    page_size?: number;
    channels: {
        channel_id: string;
        channel_name: string;
        description?: string;
        space_channel_type: "private" | "public_for_members" | "general";
        member_count: number;
    }[];
};
type SharedSpacesMoveSharedSpaceChannelsPathParams = {
    spaceId: string;
};
type SharedSpacesMoveSharedSpaceChannelsRequestBody = {
    channel_ids: string[];
    move_direction: "move_into" | "move_out";
};
type SharedSpacesMoveSharedSpaceChannelsResponse = {
    space_id: string;
    move_direction: string;
    channels: {
        channel_id: string;
        is_moved: boolean;
    }[];
};
type SharedSpacesListSharedSpaceMembersPathParams = {
    spaceId: string;
};
type SharedSpacesListSharedSpaceMembersQueryParams = {
    page_size?: number;
    next_page_token?: string;
    role?: "all" | "member" | "owner" | "admin";
    status?: "all" | "active" | "inactive";
};
type SharedSpacesListSharedSpaceMembersResponse = {
    next_page_token?: string;
    page_size?: number;
    members: {
        user_id?: string;
        member_id: string;
        email?: string;
        role: "member" | "owner" | "admin";
        status: "active" | "inactive";
        first_name: string;
        last_name: string;
        display_name: string;
        is_external_user: boolean;
    }[];
};
type SharedSpacesAddMembersToSharedSpacePathParams = {
    spaceId: string;
};
type SharedSpacesAddMembersToSharedSpaceRequestBody = {
    members: {
        identifier: string;
    }[];
};
type SharedSpacesAddMembersToSharedSpaceResponse = {
    successful_operations_count: number;
    unsuccessful_operations_count: number;
    users: {
        user_id: string;
        member_id: string;
        is_external_user: boolean;
        operation_status: "successful" | "unsuccessful";
    }[];
};
type SharedSpacesRemoveMembersFromSharedSpacePathParams = {
    spaceId: string;
};
type SharedSpacesRemoveMembersFromSharedSpaceQueryParams = {
    identifiers: string;
};
type SharedSpacesRemoveMembersFromSharedSpaceResponse = {
    successful_operations_count: number;
    unsuccessful_operations_count: number;
    users: {
        user_id: string;
        member_id: string;
        is_external_user: boolean;
        operation_status: "successful" | "unsuccessful";
    }[];
};
type SharedSpacesTransferSharedSpaceOwnershipPathParams = {
    spaceId: string;
};
type SharedSpacesTransferSharedSpaceOwnershipQueryParams = {
    identifier: string;
};
declare class TeamChatEndpoints extends WebEndpoints {
    readonly chatChannelMentionGroup: {
        listChannelMentionGroups: (_: {
            path: ChatChannelMentionGroupListChannelMentionGroupsPathParams;
        } & object) => Promise<BaseResponse<ChatChannelMentionGroupListChannelMentionGroupsResponse>>;
        createChannelMentionGroup: (_: {
            path: ChatChannelMentionGroupCreateChannelMentionGroupPathParams;
        } & {
            body: ChatChannelMentionGroupCreateChannelMentionGroupRequestBody;
        } & object) => Promise<BaseResponse<ChatChannelMentionGroupCreateChannelMentionGroupResponse>>;
        deleteChannelMentionGroup: (_: {
            path: ChatChannelMentionGroupDeleteChannelMentionGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateChannelMentionGroupInformation: (_: {
            path: ChatChannelMentionGroupUpdateChannelMentionGroupInformationPathParams;
        } & {
            body?: ChatChannelMentionGroupUpdateChannelMentionGroupInformationRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listMembersOfMentionGroup: (_: {
            path: ChatChannelMentionGroupListMembersOfMentionGroupPathParams;
        } & object & {
            query?: ChatChannelMentionGroupListMembersOfMentionGroupQueryParams;
        }) => Promise<BaseResponse<ChatChannelMentionGroupListMembersOfMentionGroupResponse>>;
        addChannelMembersToMentionGroup: (_: {
            path: ChatChannelMentionGroupAddChannelMembersToMentionGroupPathParams;
        } & {
            body: ChatChannelMentionGroupAddChannelMembersToMentionGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        removeChannelMentionGroupMembers: (_: {
            path: ChatChannelMentionGroupRemoveChannelMentionGroupMembersPathParams;
        } & object & {
            query: ChatChannelMentionGroupRemoveChannelMentionGroupMembersQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly chatChannels: {
        listChannelActivityLogs: (_: object & {
            query: ChatChannelsListChannelActivityLogsQueryParams;
        }) => Promise<BaseResponse<ChatChannelsListChannelActivityLogsResponse>>;
        performOperationsOnChannels: (_: object & {
            body: ChatChannelsPerformOperationsOnChannelsRequestBody;
        }) => Promise<BaseResponse<ChatChannelsPerformOperationsOnChannelsResponse>>;
        getChannel: (_: {
            path: ChatChannelsGetChannelPathParams;
        } & object) => Promise<BaseResponse<ChatChannelsGetChannelResponse>>;
        deleteChannel: (_: {
            path: ChatChannelsDeleteChannelPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateChannel: (_: {
            path: ChatChannelsUpdateChannelPathParams;
        } & {
            body?: ChatChannelsUpdateChannelRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listChannelMembers: (_: {
            path: ChatChannelsListChannelMembersPathParams;
        } & object & {
            query?: ChatChannelsListChannelMembersQueryParams;
        }) => Promise<BaseResponse<ChatChannelsListChannelMembersResponse>>;
        inviteChannelMembers: (_: {
            path: ChatChannelsInviteChannelMembersPathParams;
        } & {
            body?: ChatChannelsInviteChannelMembersRequestBody;
        } & object) => Promise<BaseResponse<ChatChannelsInviteChannelMembersResponse>>;
        batchRemoveMembersFromChannel: (_: {
            path: ChatChannelsBatchRemoveMembersFromChannelPathParams;
        } & object & {
            query: ChatChannelsBatchRemoveMembersFromChannelQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listChannelMembersGroups: (_: {
            path: ChatChannelsListChannelMembersGroupsPathParams;
        } & object) => Promise<BaseResponse<ChatChannelsListChannelMembersGroupsResponse>>;
        inviteChannelMembersGroups: (_: {
            path: ChatChannelsInviteChannelMembersGroupsPathParams;
        } & {
            body?: ChatChannelsInviteChannelMembersGroupsRequestBody;
        } & object) => Promise<BaseResponse<ChatChannelsInviteChannelMembersGroupsResponse>>;
        removeMemberGroup: (_: {
            path: ChatChannelsRemoveMemberGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        joinChannel: (_: {
            path: ChatChannelsJoinChannelPathParams;
        } & object) => Promise<BaseResponse<ChatChannelsJoinChannelResponse>>;
        leaveChannel: (_: {
            path: ChatChannelsLeaveChannelPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        removeMember: (_: {
            path: ChatChannelsRemoveMemberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listUsersChannels: (_: {
            path: ChatChannelsListUsersChannelsPathParams;
        } & object & {
            query?: ChatChannelsListUsersChannelsQueryParams;
        }) => Promise<BaseResponse<ChatChannelsListUsersChannelsResponse>>;
        createChannel: (_: {
            path: ChatChannelsCreateChannelPathParams;
        } & {
            body?: ChatChannelsCreateChannelRequestBody;
        } & object) => Promise<BaseResponse<ChatChannelsCreateChannelResponse>>;
    };
    readonly chatChannelsAccountLevel: {
        batchDeleteChannels: (_: {
            path: ChatChannelsAccountLevelBatchDeleteChannelsPathParams;
        } & object & {
            query: ChatChannelsAccountLevelBatchDeleteChannelsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listAccountsPublicChannels: (_: object & {
            query?: ChatChannelsAccountLevelListAccountsPublicChannelsQueryParams;
        }) => Promise<BaseResponse<ChatChannelsAccountLevelListAccountsPublicChannelsResponse>>;
        searchUsersOrAccountsChannels: (_: object & {
            body: ChatChannelsAccountLevelSearchUsersOrAccountsChannelsRequestBody;
        }) => Promise<BaseResponse<ChatChannelsAccountLevelSearchUsersOrAccountsChannelsResponse>>;
        listChannelActivityLogs: (_: {
            path: ChatChannelsAccountLevelListChannelActivityLogsPathParams;
        } & object & {
            query: ChatChannelsAccountLevelListChannelActivityLogsQueryParams;
        }) => Promise<BaseResponse<ChatChannelsAccountLevelListChannelActivityLogsResponse>>;
        getRetentionPolicyOfChannel: (_: {
            path: ChatChannelsAccountLevelGetRetentionPolicyOfChannelPathParams;
        } & object) => Promise<BaseResponse<ChatChannelsAccountLevelGetRetentionPolicyOfChannelResponse>>;
        updateRetentionPolicyOfChannel: (_: {
            path: ChatChannelsAccountLevelUpdateRetentionPolicyOfChannelPathParams;
        } & {
            body: ChatChannelsAccountLevelUpdateRetentionPolicyOfChannelRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getChannel: (_: {
            path: ChatChannelsAccountLevelGetChannelPathParams;
        } & object) => Promise<BaseResponse<ChatChannelsAccountLevelGetChannelResponse>>;
        deleteChannel: (_: {
            path: ChatChannelsAccountLevelDeleteChannelPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateChannel: (_: {
            path: ChatChannelsAccountLevelUpdateChannelPathParams;
        } & {
            body?: ChatChannelsAccountLevelUpdateChannelRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listChannelAdministrators: (_: {
            path: ChatChannelsAccountLevelListChannelAdministratorsPathParams;
        } & object & {
            query?: ChatChannelsAccountLevelListChannelAdministratorsQueryParams;
        }) => Promise<BaseResponse<ChatChannelsAccountLevelListChannelAdministratorsResponse>>;
        promoteChannelMembersToAdministrators: (_: {
            path: ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsPathParams;
        } & {
            body?: ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsRequestBody;
        } & object) => Promise<BaseResponse<ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsResponse>>;
        batchDemoteChannelAdministrators: (_: {
            path: ChatChannelsAccountLevelBatchDemoteChannelAdministratorsPathParams;
        } & object & {
            query: ChatChannelsAccountLevelBatchDemoteChannelAdministratorsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listChannelMembers: (_: {
            path: ChatChannelsAccountLevelListChannelMembersPathParams;
        } & object & {
            query?: ChatChannelsAccountLevelListChannelMembersQueryParams;
        }) => Promise<BaseResponse<ChatChannelsAccountLevelListChannelMembersResponse>>;
        inviteChannelMembers: (_: {
            path: ChatChannelsAccountLevelInviteChannelMembersPathParams;
        } & {
            body?: ChatChannelsAccountLevelInviteChannelMembersRequestBody;
        } & object) => Promise<BaseResponse<ChatChannelsAccountLevelInviteChannelMembersResponse>>;
        batchRemoveMembersFromUsersChannel: (_: {
            path: ChatChannelsAccountLevelBatchRemoveMembersFromUsersChannelPathParams;
        } & object & {
            query: ChatChannelsAccountLevelBatchRemoveMembersFromUsersChannelQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        removeMember: (_: {
            path: ChatChannelsAccountLevelRemoveMemberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly chatEmoji: {
        listCustomEmojis: (_: object & {
            query?: ChatEmojiListCustomEmojisQueryParams;
        }) => Promise<BaseResponse<ChatEmojiListCustomEmojisResponse>>;
        addCustomEmoji: (_: object & {
            body: ChatEmojiAddCustomEmojiRequestBody;
        }) => Promise<BaseResponse<ChatEmojiAddCustomEmojiResponse>>;
        deleteCustomEmoji: (_: {
            path: ChatEmojiDeleteCustomEmojiPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly chatFiles: {
        getFileInfo: (_: {
            path: ChatFilesGetFileInfoPathParams;
        } & object) => Promise<BaseResponse<ChatFilesGetFileInfoResponse>>;
        deleteChatFile: (_: {
            path: ChatFilesDeleteChatFilePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        uploadChatFile: (_: {
            path: ChatFilesUploadChatFilePathParams;
        } & {
            body?: ChatFilesUploadChatFileRequestBody;
        } & {
            query?: ChatFilesUploadChatFileQueryParams;
        }) => Promise<BaseResponse<ChatFilesUploadChatFileResponse>>;
        sendChatFile: (_: {
            path: ChatFilesSendChatFilePathParams;
        } & {
            body: ChatFilesSendChatFileRequestBody;
        } & object) => Promise<BaseResponse<ChatFilesSendChatFileResponse>>;
    };
    readonly chatMessages: {
        performOperationsOnMessageOfChannel: (_: object & {
            body: ChatMessagesPerformOperationsOnMessageOfChannelRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        listPinnedHistoryMessagesOfChannel: (_: {
            path: ChatMessagesListPinnedHistoryMessagesOfChannelPathParams;
        } & object & {
            query?: ChatMessagesListPinnedHistoryMessagesOfChannelQueryParams;
        }) => Promise<BaseResponse<ChatMessagesListPinnedHistoryMessagesOfChannelResponse>>;
        getForwardedMessage: (_: {
            path: ChatMessagesGetForwardedMessagePathParams;
        } & object) => Promise<BaseResponse<ChatMessagesGetForwardedMessageResponse>>;
        listBookmarks: (_: object & {
            query?: ChatMessagesListBookmarksQueryParams;
        }) => Promise<BaseResponse<ChatMessagesListBookmarksResponse>>;
        addOrRemoveBookmark: (_: object & {
            body: ChatMessagesAddOrRemoveBookmarkRequestBody;
        } & {
            query: ChatMessagesAddOrRemoveBookmarkQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listScheduledMessages: (_: object & {
            query?: ChatMessagesListScheduledMessagesQueryParams;
        }) => Promise<BaseResponse<ChatMessagesListScheduledMessagesResponse>>;
        deleteScheduledMessage: (_: {
            path: ChatMessagesDeleteScheduledMessagePathParams;
        } & object & {
            query?: ChatMessagesDeleteScheduledMessageQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listUsersChatMessages: (_: {
            path: ChatMessagesListUsersChatMessagesPathParams;
        } & object & {
            query?: ChatMessagesListUsersChatMessagesQueryParams;
        }) => Promise<BaseResponse<ChatMessagesListUsersChatMessagesResponse>>;
        sendChatMessage: (_: {
            path: ChatMessagesSendChatMessagePathParams;
        } & {
            body: ChatMessagesSendChatMessageRequestBody;
        } & object) => Promise<BaseResponse<ChatMessagesSendChatMessageResponse>>;
        getMessage: (_: {
            path: ChatMessagesGetMessagePathParams;
        } & object & {
            query?: ChatMessagesGetMessageQueryParams;
        }) => Promise<BaseResponse<ChatMessagesGetMessageResponse>>;
        updateMessage: (_: {
            path: ChatMessagesUpdateMessagePathParams;
        } & {
            body?: ChatMessagesUpdateMessageRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteMessage: (_: {
            path: ChatMessagesDeleteMessagePathParams;
        } & object & {
            query?: ChatMessagesDeleteMessageQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        reactToChatMessage: (_: {
            path: ChatMessagesReactToChatMessagePathParams;
        } & {
            body?: ChatMessagesReactToChatMessageRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        markMessageReadOrUnread: (_: {
            path: ChatMessagesMarkMessageReadOrUnreadPathParams;
        } & {
            body?: ChatMessagesMarkMessageReadOrUnreadRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        retrieveThread: (_: {
            path: ChatMessagesRetrieveThreadPathParams;
        } & object & {
            query: ChatMessagesRetrieveThreadQueryParams;
        }) => Promise<BaseResponse<ChatMessagesRetrieveThreadResponse>>;
    };
    readonly chatMigration: {
        migrateChannelMembers: (_: {
            path: ChatMigrationMigrateChannelMembersPathParams;
        } & {
            body: ChatMigrationMigrateChannelMembersRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        migrateChatMessageReactions: (_: object & {
            body: ChatMigrationMigrateChatMessageReactionsRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        getMigratedZoomChannelIDs: (_: object & {
            query: ChatMigrationGetMigratedZoomChannelIDsQueryParams;
        }) => Promise<BaseResponse<ChatMigrationGetMigratedZoomChannelIDsResponse>>;
        getMigratedZoomUserIDs: (_: object & {
            query: ChatMigrationGetMigratedZoomUserIDsQueryParams;
        }) => Promise<BaseResponse<ChatMigrationGetMigratedZoomUserIDsResponse>>;
        migrateChatMessages: (_: object & {
            body: ChatMigrationMigrateChatMessagesRequestBody;
        }) => Promise<BaseResponse<ChatMigrationMigrateChatMessagesResponse>>;
        migrateChatChannel: (_: {
            path: ChatMigrationMigrateChatChannelPathParams;
        } & {
            body: ChatMigrationMigrateChatChannelRequestBody;
        } & object) => Promise<BaseResponse<ChatMigrationMigrateChatChannelResponse>>;
        migrateConversationOrChannelOperations: (_: {
            path: ChatMigrationMigrateConversationOrChannelOperationsPathParams;
        } & {
            body: ChatMigrationMigrateConversationOrChannelOperationsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly chatReminder: {
        createReminderMessage: (_: {
            path: ChatReminderCreateReminderMessagePathParams;
        } & {
            body?: ChatReminderCreateReminderMessageRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteReminderForMessage: (_: {
            path: ChatReminderDeleteReminderForMessagePathParams;
        } & object & {
            query?: ChatReminderDeleteReminderForMessageQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listReminders: (_: object & {
            query?: ChatReminderListRemindersQueryParams;
        }) => Promise<BaseResponse<ChatReminderListRemindersResponse>>;
    };
    readonly chatSessions: {
        starOrUnstarChannelOrContactUser: (_: {
            path: ChatSessionsStarOrUnstarChannelOrContactUserPathParams;
        } & {
            body: ChatSessionsStarOrUnstarChannelOrContactUserRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listUsersChatSessions: (_: {
            path: ChatSessionsListUsersChatSessionsPathParams;
        } & object & {
            query?: ChatSessionsListUsersChatSessionsQueryParams;
        }) => Promise<BaseResponse<ChatSessionsListUsersChatSessionsResponse>>;
    };
    readonly contacts: {
        listUsersContacts: (_: object & {
            query?: ContactsListUsersContactsQueryParams;
        }) => Promise<BaseResponse<ContactsListUsersContactsResponse>>;
        getUsersContactDetails: (_: {
            path: ContactsGetUsersContactDetailsPathParams;
        } & object & {
            query?: ContactsGetUsersContactDetailsQueryParams;
        }) => Promise<BaseResponse<ContactsGetUsersContactDetailsResponse>>;
        searchCompanyContacts: (_: object & {
            query: ContactsSearchCompanyContactsQueryParams;
        }) => Promise<BaseResponse<ContactsSearchCompanyContactsResponse>>;
    };
    readonly iMChat: {
        sendIMMessages: (_: object & {
            body?: IMChatSendIMMessagesRequestBody;
        } & {
            query?: IMChatSendIMMessagesQueryParams;
        }) => Promise<BaseResponse<IMChatSendIMMessagesResponse>>;
    };
    readonly iMGroups: {
        listIMDirectoryGroups: (_: object) => Promise<BaseResponse<IMGroupsListIMDirectoryGroupsResponse>>;
        createIMDirectoryGroup: (_: object & {
            body?: IMGroupsCreateIMDirectoryGroupRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        retrieveIMDirectoryGroup: (_: {
            path: IMGroupsRetrieveIMDirectoryGroupPathParams;
        } & object) => Promise<BaseResponse<IMGroupsRetrieveIMDirectoryGroupResponse>>;
        deleteIMDirectoryGroup: (_: {
            path: IMGroupsDeleteIMDirectoryGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateIMDirectoryGroup: (_: {
            path: IMGroupsUpdateIMDirectoryGroupPathParams;
        } & {
            body?: IMGroupsUpdateIMDirectoryGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listIMDirectoryGroupMembers: (_: {
            path: IMGroupsListIMDirectoryGroupMembersPathParams;
        } & object & {
            query?: IMGroupsListIMDirectoryGroupMembersQueryParams;
        }) => Promise<BaseResponse<IMGroupsListIMDirectoryGroupMembersResponse>>;
        addIMDirectoryGroupMembers: (_: {
            path: IMGroupsAddIMDirectoryGroupMembersPathParams;
        } & {
            body?: IMGroupsAddIMDirectoryGroupMembersRequestBody;
        } & object) => Promise<BaseResponse<IMGroupsAddIMDirectoryGroupMembersResponse>>;
        deleteIMDirectoryGroupMember: (_: {
            path: IMGroupsDeleteIMDirectoryGroupMemberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly invitations: {
        sendNewContactInvitation: (_: {
            path: InvitationsSendNewContactInvitationPathParams;
        } & {
            body: InvitationsSendNewContactInvitationRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly legalHold: {
        listLegalHoldMatters: (_: object & {
            query?: LegalHoldListLegalHoldMattersQueryParams;
        }) => Promise<BaseResponse<LegalHoldListLegalHoldMattersResponse>>;
        addLegalHoldMatter: (_: object & {
            body: LegalHoldAddLegalHoldMatterRequestBody;
        }) => Promise<BaseResponse<LegalHoldAddLegalHoldMatterResponse>>;
        deleteLegalHoldMatters: (_: {
            path: LegalHoldDeleteLegalHoldMattersPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateLegalHoldMatter: (_: {
            path: LegalHoldUpdateLegalHoldMatterPathParams;
        } & {
            body: LegalHoldUpdateLegalHoldMatterRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listLegalHoldFilesByGivenMatter: (_: {
            path: LegalHoldListLegalHoldFilesByGivenMatterPathParams;
        } & object & {
            query: LegalHoldListLegalHoldFilesByGivenMatterQueryParams;
        }) => Promise<BaseResponse<LegalHoldListLegalHoldFilesByGivenMatterResponse>>;
        downloadLegalHoldFilesForGivenMatter: (_: {
            path: LegalHoldDownloadLegalHoldFilesForGivenMatterPathParams;
        } & object & {
            query: LegalHoldDownloadLegalHoldFilesForGivenMatterQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly reports: {
        getChatSessionsReports: (_: object & {
            query: ReportsGetChatSessionsReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetChatSessionsReportsResponse>>;
        getChatMessageReports: (_: {
            path: ReportsGetChatMessageReportsPathParams;
        } & object & {
            query: ReportsGetChatMessageReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetChatMessageReportsResponse>>;
    };
    readonly sharedSpaces: {
        listSharedSpaces: (_: object & {
            query?: SharedSpacesListSharedSpacesQueryParams;
        }) => Promise<BaseResponse<SharedSpacesListSharedSpacesResponse>>;
        createSharedSpace: (_: object & {
            body: SharedSpacesCreateSharedSpaceRequestBody;
        }) => Promise<BaseResponse<SharedSpacesCreateSharedSpaceResponse>>;
        getSharedSpace: (_: {
            path: SharedSpacesGetSharedSpacePathParams;
        } & object) => Promise<BaseResponse<SharedSpacesGetSharedSpaceResponse>>;
        deleteSharedSpace: (_: {
            path: SharedSpacesDeleteSharedSpacePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateSharedSpaceSettings: (_: {
            path: SharedSpacesUpdateSharedSpaceSettingsPathParams;
        } & {
            body?: SharedSpacesUpdateSharedSpaceSettingsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        promoteSharedSpaceMembersToAdministrators: (_: {
            path: SharedSpacesPromoteSharedSpaceMembersToAdministratorsPathParams;
        } & {
            body: SharedSpacesPromoteSharedSpaceMembersToAdministratorsRequestBody;
        } & object) => Promise<BaseResponse<SharedSpacesPromoteSharedSpaceMembersToAdministratorsResponse>>;
        demoteSharedSpaceAdministratorsToMembers: (_: {
            path: SharedSpacesDemoteSharedSpaceAdministratorsToMembersPathParams;
        } & object & {
            query: SharedSpacesDemoteSharedSpaceAdministratorsToMembersQueryParams;
        }) => Promise<BaseResponse<SharedSpacesDemoteSharedSpaceAdministratorsToMembersResponse>>;
        listSharedSpaceChannels: (_: {
            path: SharedSpacesListSharedSpaceChannelsPathParams;
        } & object & {
            query?: SharedSpacesListSharedSpaceChannelsQueryParams;
        }) => Promise<BaseResponse<SharedSpacesListSharedSpaceChannelsResponse>>;
        moveSharedSpaceChannels: (_: {
            path: SharedSpacesMoveSharedSpaceChannelsPathParams;
        } & {
            body: SharedSpacesMoveSharedSpaceChannelsRequestBody;
        } & object) => Promise<BaseResponse<SharedSpacesMoveSharedSpaceChannelsResponse>>;
        listSharedSpaceMembers: (_: {
            path: SharedSpacesListSharedSpaceMembersPathParams;
        } & object & {
            query?: SharedSpacesListSharedSpaceMembersQueryParams;
        }) => Promise<BaseResponse<SharedSpacesListSharedSpaceMembersResponse>>;
        addMembersToSharedSpace: (_: {
            path: SharedSpacesAddMembersToSharedSpacePathParams;
        } & {
            body: SharedSpacesAddMembersToSharedSpaceRequestBody;
        } & object) => Promise<BaseResponse<SharedSpacesAddMembersToSharedSpaceResponse>>;
        removeMembersFromSharedSpace: (_: {
            path: SharedSpacesRemoveMembersFromSharedSpacePathParams;
        } & object & {
            query: SharedSpacesRemoveMembersFromSharedSpaceQueryParams;
        }) => Promise<BaseResponse<SharedSpacesRemoveMembersFromSharedSpaceResponse>>;
        transferSharedSpaceOwnership: (_: {
            path: SharedSpacesTransferSharedSpaceOwnershipPathParams;
        } & object & {
            query: SharedSpacesTransferSharedSpaceOwnershipQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
}

type TeamChatSharedSpacesMemberLeftEvent = Event<"team_chat.shared_spaces_member_left"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            space_id: string;
            space_name: string;
            timestamp: number;
        };
    };
};
type TeamChatChannelInvitationRemovedEvent = Event<"team_chat.channel_invitation_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            invitee: {
                display_name: string;
                user_email?: string;
                member_id?: string;
            };
            inviters: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
                date_created: string;
            }[];
            date_time?: string;
            timestamp: number;
        };
    };
};
type TeamChatEmojiAddedEvent = Event<"team_chat.emoji_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            name: string;
            file_id: string;
        };
    };
};
type TeamChatFileChangedEvent = Event<"team_chat.file_changed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            files: {
                file_id: string;
                file_name: string;
                file_size: number;
                OS_file_type: string;
            }[];
        };
    };
};
type TeamChatChannelJoinDeclinedEvent = Event<"team_chat.channel_join_declined"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            requester: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
            };
            date_time: string;
            timestamp: number;
            type?: "by_channel_owner_account_admin" | "by_requester_account_admin" | "by_channel_owner";
        };
    };
};
type ChatChannelMemberJoinedEvent = Event<"chat_channel.member_joined"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
        };
        operator_id: string;
    };
};
type ChatMessageUpdatedEvent = Event<"chat_message.updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            id: string;
            type: "to_contact" | "to_channel";
            date_time: string;
            timestamp: number;
            session_id: string;
            contact_email: string;
            contact_id: string;
            channel_id: string;
            channel_name: string;
            message: string;
        };
        operator_id: string;
    };
};
type ChatChannelDeletedEvent = Event<"chat_channel.deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
        };
        operator_id: string;
    };
};
type ChatMessageDeletedEvent = Event<"chat_message.deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            id: string;
            type: "to_contact" | "to_channel";
            date_time: string;
            timestamp: number;
            session_id: string;
            contact_email: string;
            contact_id: string;
            channel_id: string;
            channel_name: string;
            message: string;
        };
        operator_id: string;
    };
};
type TeamChatEmojiRemovedEvent = Event<"team_chat.emoji_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            name: string;
            file_id: string;
        };
    };
};
type TeamChatChannelPinAddedEvent = Event<"team_chat.channel_pin_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            channel_name: string;
            channel_id: string;
            type: 1 | 2 | 3 | 4 | 5;
            message_id: string;
            message: string;
            message_timestamp: number;
            date_time: string;
            timestamp: number;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
        };
    };
};
type TeamChatDmReactionAddedEvent = Event<"team_chat.dm_reaction_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            msg_id: string;
            msg_time: string;
            emoji_time: string;
            emoji: string;
            timestamp: number;
            contact_email: string;
            contact_id: string;
            contact_member_id: string;
        };
    };
};
type TeamChatChannelArchivedEvent = Event<"team_chat.channel_archived"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
        };
    };
};
type TeamChatBookmarkRemovedEvent = Event<"team_chat.bookmark_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            type: "to_contact" | "to_channel";
            channel_id?: string;
            message_id: string;
            message: string;
            message_timestamp: number;
            sender: string;
            sender_id: string;
            sender_member_id: string;
            by_external_user: boolean;
            date_time: string;
            timestamp: number;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
        };
    };
};
type TeamChatChannelPinRemovedEvent = Event<"team_chat.channel_pin_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            channel_name: string;
            channel_id: string;
            type: 1 | 2 | 3 | 4 | 5;
            message_id: string;
            message: string;
            message_timestamp: number;
            date_time: string;
            timestamp: number;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
        };
    };
};
type TeamChatChannelJoinApprovalRequestedEvent = Event<"team_chat.channel_join_approval_requested"> & {
    event: string;
    event_ts: number;
    payload: {
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            requester: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
            };
            date_time: string;
            timestamp: number;
            type: "to_channel_account_admin" | "to_requester_account_admin" | "to_channel_owner";
        };
    };
};
type TeamChatFileDownloadedEvent = Event<"team_chat.file_downloaded"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            contact_email?: string;
            contact_id?: string;
            contact_member_id?: string;
            channel_id?: string;
            timestamp: number;
            file: {
                file_id: string;
                file_name: string;
                file_size: number;
                file_type: string;
                file_owner_id?: string;
                file_owner_member_id: string;
            };
        };
    };
};
type TeamChatDmMessagePostedEvent = Event<"team_chat.dm_message_posted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            message_id: string;
            reply_main_message_id?: string;
            session_id: string;
            date_time: string;
            timestamp: number;
            contact_email: string;
            contact_id: string;
            contact_account_id: string;
            contact_member_id: string;
            message?: string;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
        };
    };
};
type TeamChatSharedSpacesEditedEvent = Event<"team_chat.shared_spaces_edited"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            space_id: string;
            new_settings: {
                name: string;
                desc: string;
                option: {
                    is_public: boolean;
                    add_new_members: "by_owner_and_admins" | "by_any_member";
                    add_new_channels: "by_owner_and_admins" | "by_any_member";
                    add_external_users: "disabled" | "by_same_org" | "by_owner_and_admins" | "by_any_member";
                };
            };
            old_settings: {
                name: string;
                desc: string;
                option: {
                    is_public: boolean;
                    add_new_members: "by_owner_and_admins" | "by_any_member";
                    add_new_channels: "by_owner_and_admins" | "by_any_member";
                    add_external_users: "disabled" | "by_same_org" | "by_owner_and_admins" | "by_any_member";
                };
            };
            timestamp?: number;
        };
        additionalProperties?: never;
    };
    additionalProperties?: never;
};
type ChatChannelUpdatedEvent = Event<"chat_channel.updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
        };
        operator_id: string;
    };
};
type TeamChatChannelAppAddedEvent = Event<"team_chat.channel_app_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user?: boolean;
        object: {
            channel_name: string;
            channel_id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
            app_members?: {
                id: string;
                display_name: string;
            }[];
        };
    };
};
type TeamChatStarredEvent = Event<"team_chat.starred"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            items: {
                type: "contact" | "channel";
                channel_id?: string;
                contact_email?: string;
                contact_id?: string;
                contact_member_id?: string;
                is_external_user?: boolean;
            }[];
            date_time: string;
            timestamp: number;
        };
    };
};
type TeamChatChannelMessageDeletedEvent = Event<"team_chat.channel_message_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            message_id: string;
            date_time: string;
            timestamp: number;
            channel_id: string;
            channel_owner_account_id: string;
            channel_name: string;
            reply_main_message_id?: string;
        };
    };
};
type ChatChannelCreatedEvent = Event<"chat_channel.created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
            members: ExactlyOneOf<[
                {
                    id: string;
                    display_name: string;
                }
            ]>[];
        };
        operator_id: string;
    };
};
type ChatChannelMemberInvitedEvent = Event<"chat_channel.member_invited"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
            members: ExactlyOneOf<[
                {
                    id: string;
                    display_name: string;
                }
            ]>[];
        };
        operator_id: string;
    };
};
type TeamChatChannelInvitationAcceptedEvent = Event<"team_chat.channel_invitation_accepted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            invitee: {
                display_name: string;
                user_email?: string;
                member_id?: string;
            };
            inviters: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
                date_created: string;
            }[];
            date_time?: string;
            timestamp: number;
        };
    };
};
type ChatChannelMemberLeftEvent = Event<"chat_channel.member_left"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
        };
        operator_id: string;
    };
};
type TeamChatChannelJoinRequestedEvent = Event<"team_chat.channel_join_requested"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            requester: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
            };
            date_time: string;
            timestamp: number;
        };
    };
};
type TeamChatDmMessageUpdatedEvent = Event<"team_chat.dm_message_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            message_id: string;
            reply_main_message_id?: string;
            session_id: string;
            date_time: string;
            timestamp: number;
            contact_email: string;
            contact_id: string;
            contact_account_id: string;
            contact_member_id: string;
            message?: string;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
        };
    };
};
type ChatMessageRepliedEvent = Event<"chat_message.replied"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            id: string;
            type: "to_contact" | "to_channel";
            date_time: string;
            timestamp: number;
            session_id: string;
            contact_email: string;
            contact_id: string;
            channel_id: string;
            channel_name: string;
            message: string;
            parent_msg_id: string;
        };
        operator_id: string;
    };
};
type TeamChatChannelInvitationRejectedEvent = Event<"team_chat.channel_invitation_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            invitee: {
                display_name: string;
                user_email?: string;
                member_id?: string;
            };
            inviters: {
                id?: string;
                display_name: string;
                user_email: string;
                member_id: string;
                date_created: string;
            }[];
            date_time: string;
            timestamp: number;
        };
    };
};
type TeamChatChannelReactionRemovedEvent = Event<"team_chat.channel_reaction_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            msg_id: string;
            msg_time: string;
            emoji_time: string;
            emoji: string;
            timestamp: number;
            channel_id: string;
        };
    };
};
type TeamChatSharedSpacesMemberInvitedEvent = Event<"team_chat.shared_spaces_member_invited"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            space_id: string;
            space_name: string;
            members: {
                user_id: string;
                user_email: string;
                display_name?: string;
                role: "owner" | "admin" | "member";
                member_id: string;
            }[];
            timestamp: number;
        };
    };
};
type TeamChatUnstarredEvent = Event<"team_chat.unstarred"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            items: {
                type: "contact" | "channel";
                channel_id?: string;
                contact_email?: string;
                contact_id?: string;
                contact_member_id?: string;
                is_external_user?: boolean;
            }[];
            date_time: string;
            timestamp: number;
        };
    };
};
type TeamChatFileUnsharedEvent = Event<"team_chat.file_unshared"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            type: "to_contact" | "to_channel";
            channel_id?: string;
            contact_email?: string;
            contact_id?: string;
            contact_member_id?: string;
            is_external_user?: boolean;
            files: {
                file_id: string;
                file_name: string;
                file_size: number;
                OS_file_type: string;
            }[];
        };
    };
};
type TeamChatChannelMessageUpdatedEvent = Event<"team_chat.channel_message_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            message_id: string;
            reply_main_message_id?: string;
            session_id: string;
            date_time: string;
            timestamp: number;
            channel_id: string;
            channel_owner_account_id: string;
            channel_name: string;
            message?: string;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
            at_items?: {
                at_contact?: string;
                at_contact_user_id?: string;
                at_contact_member_id?: string;
                at_type: 1 | 2;
                end_position: number;
                start_position: number;
            }[];
        };
    };
};
type ChatChannelMemberRemovedEvent = Event<"chat_channel.member_removed"> & {
    event: string;
    event_ts: string;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: string;
            name: string;
            type: 1 | 2 | 3 | 4 | 5;
            timestamp: number;
            date_time: string;
            members: ExactlyOneOf<[
                {
                    id: string;
                    display_name: string;
                }
            ]>[];
        };
    };
};
type TeamChatDmReactionRemovedEvent = Event<"team_chat.dm_reaction_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            msg_id: string;
            msg_time: string;
            emoji_time: string;
            emoji: string;
            timestamp: number;
            contact_email: string;
            contact_id: string;
            contact_member_id: string;
        };
    };
};
type TeamChatDmMessageDeletedEvent = Event<"team_chat.dm_message_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            message_id: string;
            date_time: string;
            contact_account_id: string;
            timestamp: number;
            contact_email: string;
            contact_id: string;
            contact_member_id: string;
            reply_main_message_id?: string;
        };
    };
};
type TeamChatChannelUnarchivedEvent = Event<"team_chat.channel_unarchived"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            name: string;
            id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
        };
    };
};
type TeamChatChannelMessagePostedEvent = Event<"team_chat.channel_message_posted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            message_id: string;
            reply_main_message_id?: string;
            session_id: string;
            date_time: string;
            timestamp: number;
            channel_id: string;
            channel_owner_account_id: string;
            channel_name: string;
            message?: string;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
            at_items?: {
                at_contact?: string;
                at_contact_user_id?: string;
                at_contact_member_id?: string;
                at_type: 1 | 2;
                end_position: number;
                start_position: number;
            }[];
        };
    };
};
type TeamChatChannelJoinApprovedEvent = Event<"team_chat.channel_join_approved"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            requester: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
            };
            date_time: string;
            timestamp: number;
            type?: "by_channel_owner_account_admin" | "by_requester_account_admin" | "by_channel_owner";
        };
    };
};
type TeamChatBookmarkAddedEvent = Event<"team_chat.bookmark_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            type: "to_contact" | "to_channel";
            channel_id?: string;
            message_id: string;
            message: string;
            message_timestamp: number;
            sender: string;
            sender_id: string;
            sender_member_id: string;
            by_external_user: boolean;
            date_time: string;
            timestamp: number;
            files?: {
                OS_file_type: string;
                file_id: string;
                file_message_type: "file" | "image" | "audio" | "audio v2" | "code snippet" | "screen shot";
                file_name: string;
                file_size: number;
            }[];
            rich_text?: {
                start_position: number;
                end_position: number;
                format_type: "Bold" | "Italic" | "Strikethrough" | "BulletedList" | "NumberedList" | "Underline" | "FontSize" | "FontColor" | "BackgroundColor" | "LeftIndent" | "Paragraph" | "Quote" | "AddLink";
                format_attr?: string;
            }[];
        };
    };
};
type TeamChatChannelReactionAddedEvent = Event<"team_chat.channel_reaction_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            msg_id: string;
            msg_time: string;
            emoji_time: string;
            emoji: string;
            timestamp: number;
            channel_id: string;
        };
    };
};
type TeamChatChannelInvitationCreatedEvent = Event<"team_chat.channel_invitation_created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            invitee: {
                display_name: string;
                user_email?: string;
                member_id?: string;
            };
            inviters: {
                user_id: string;
                display_name: string;
                user_email?: string;
                member_id: string;
                date_created: string;
            }[];
            date_time: string;
            timestamp: number;
        };
    };
};
type TeamChatChannelAppRemovedEvent = Event<"team_chat.channel_app_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user?: boolean;
        object: {
            channel_name: string;
            channel_id: string;
            type: 1 | 2 | 3 | 4 | 5;
            date_time: string;
            timestamp: number;
            app_members?: {
                id: string;
                display_name: string;
            }[];
        };
    };
};
type TeamChatSharedSpacesMemberRemovedEvent = Event<"team_chat.shared_spaces_member_removed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            space_id: string;
            space_name: string;
            members: {
                user_id: string;
                user_email: string;
                display_name: string;
                member_id: string;
            }[];
            timestamp: number;
        };
    };
};
type TeamChatFileSharedEvent = Event<"team_chat.file_shared"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            type: "to_contact" | "to_channel";
            channel_id?: string;
            contact_email?: string;
            contact_id?: string;
            contact_member_id?: string;
            is_external_user?: boolean;
            files: {
                file_id: string;
                file_name: string;
                file_size: number;
                OS_file_type: string;
            }[];
        };
    };
};
type TeamChatChannelInvitationApprovedEvent = Event<"team_chat.channel_invitation_approved"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            invitee: {
                display_name: string;
                user_email?: string;
                member_id?: string;
            };
            inviters: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
                date_created: string;
            }[];
            date_time: string;
            timestamp: number;
            type: "by_channel_owner_account_admin" | "by_invitee_account_admin";
        };
    };
};
type TeamChatFileUploadedEvent = Event<"team_chat.file_uploaded"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            files: {
                file_id: string;
                file_name: string;
                file_size: number;
                OS_file_type: string;
            }[];
        };
    };
};
type TeamChatFileDeletedEvent = Event<"team_chat.file_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            files: {
                file_id: string;
                file_name: string;
                file_size: number;
                OS_file_type: string;
            }[];
        };
    };
};
type ChatMessageSentEvent = Event<"chat_message.sent"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            id: string;
            type: "to_contact" | "to_channel";
            date_time: string;
            timestamp: number;
            session_id: string;
            contact_email: string;
            contact_id: string;
            channel_id: string;
            channel_name: string;
            message: string;
        };
        operator_id: string;
    };
};
type TeamChatChannelInvitationDeclinedEvent = Event<"team_chat.channel_invitation_declined"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operator_member_id: string;
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            invitee: {
                display_name: string;
                user_email?: string;
                member_id?: string;
            };
            inviters: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
                date_created: string;
            }[];
            date_time: string;
            timestamp: number;
            type?: "by_channel_owner_account_admin" | "by_invitee_account_admin";
        };
    };
};
type TeamChatChannelInvitationApprovalRequestedEvent = Event<"team_chat.channel_invitation_approval_requested"> & {
    event: string;
    event_ts: number;
    payload: {
        object: {
            organization?: {
                org_id: string;
                org_name: string;
            };
            channel?: {
                channel_id: string;
                channel_name: string;
                type: 1 | 2 | 3 | 4 | 5;
            };
            invitee: {
                user_id: string;
                display_name?: string;
                user_email: string;
                member_id?: string;
            };
            inviters: {
                user_id: string;
                display_name: string;
                user_email: string;
                member_id: string;
                date_created: string;
            }[];
            date_time: string;
            timestamp: number;
            type: "to_channel_account_admin" | "to_invitee_account_admin" | "to_invitee";
        };
    };
};
type TeamChatEvents = TeamChatSharedSpacesMemberLeftEvent | TeamChatChannelInvitationRemovedEvent | TeamChatEmojiAddedEvent | TeamChatFileChangedEvent | TeamChatChannelJoinDeclinedEvent | ChatChannelMemberJoinedEvent | ChatMessageUpdatedEvent | ChatChannelDeletedEvent | ChatMessageDeletedEvent | TeamChatEmojiRemovedEvent | TeamChatChannelPinAddedEvent | TeamChatDmReactionAddedEvent | TeamChatChannelArchivedEvent | TeamChatBookmarkRemovedEvent | TeamChatChannelPinRemovedEvent | TeamChatChannelJoinApprovalRequestedEvent | TeamChatFileDownloadedEvent | TeamChatDmMessagePostedEvent | TeamChatSharedSpacesEditedEvent | ChatChannelUpdatedEvent | TeamChatChannelAppAddedEvent | TeamChatStarredEvent | TeamChatChannelMessageDeletedEvent | ChatChannelCreatedEvent | ChatChannelMemberInvitedEvent | TeamChatChannelInvitationAcceptedEvent | ChatChannelMemberLeftEvent | TeamChatChannelJoinRequestedEvent | TeamChatDmMessageUpdatedEvent | ChatMessageRepliedEvent | TeamChatChannelInvitationRejectedEvent | TeamChatChannelReactionRemovedEvent | TeamChatSharedSpacesMemberInvitedEvent | TeamChatUnstarredEvent | TeamChatFileUnsharedEvent | TeamChatChannelMessageUpdatedEvent | ChatChannelMemberRemovedEvent | TeamChatDmReactionRemovedEvent | TeamChatDmMessageDeletedEvent | TeamChatChannelUnarchivedEvent | TeamChatChannelMessagePostedEvent | TeamChatChannelJoinApprovedEvent | TeamChatBookmarkAddedEvent | TeamChatChannelReactionAddedEvent | TeamChatChannelInvitationCreatedEvent | TeamChatChannelAppRemovedEvent | TeamChatSharedSpacesMemberRemovedEvent | TeamChatFileSharedEvent | TeamChatChannelInvitationApprovedEvent | TeamChatFileUploadedEvent | TeamChatFileDeletedEvent | ChatMessageSentEvent | TeamChatChannelInvitationDeclinedEvent | TeamChatChannelInvitationApprovalRequestedEvent;
type MessageReplyContext = {
    reply: (msg: string) => Promise<Awaited<ReturnType<TeamChatEndpoints["chatMessages"]["sendChatMessage"]>>>;
};
declare class TeamChatEventProcessor extends EventManager<TeamChatEndpoints, TeamChatEvents> {
    onChannelMessagePosted(contents: string | RegExp, listener: ReturnType<typeof this.withContext<"team_chat.channel_message_posted", MessageReplyContext>>): void;
}

type TeamChatOptions<R extends Receiver> = CommonClientOptions<OAuth, R>;
declare class TeamChatClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<OAuth, ReceiverType> = TeamChatOptions<ReceiverType>> extends ProductClient<OAuth, TeamChatEndpoints, TeamChatEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, ...restOptions }: OptionsType): OAuth;
    protected initEndpoints(auth: OAuth, options: OptionsType): TeamChatEndpoints;
    protected initEventProcessor(endpoints: TeamChatEndpoints): TeamChatEventProcessor;
}

type TeamChatS2SAuthOptions<R extends Receiver> = CommonClientOptions<S2SAuth, R>;
declare class TeamChatS2SAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<S2SAuth, ReceiverType> = TeamChatS2SAuthOptions<ReceiverType>> extends ProductClient<S2SAuth, TeamChatEndpoints, TeamChatEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, accountId }: OptionsType): S2SAuth;
    protected initEndpoints(auth: S2SAuth, options: OptionsType): TeamChatEndpoints;
    protected initEventProcessor(endpoints: TeamChatEndpoints): TeamChatEventProcessor;
}

export { ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, CommonHttpRequestError, ConsoleLogger, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, LogLevel, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, ReceiverInconsistentStateError, ReceiverOAuthFlowError, S2SRawResponseError, StatusCode, TeamChatClient, TeamChatEndpoints, TeamChatEventProcessor, TeamChatS2SAuthClient, isCoreError, isStateStore };
export type { ChatChannelCreatedEvent, ChatChannelDeletedEvent, ChatChannelMemberInvitedEvent, ChatChannelMemberJoinedEvent, ChatChannelMemberLeftEvent, ChatChannelMemberRemovedEvent, ChatChannelMentionGroupAddChannelMembersToMentionGroupPathParams, ChatChannelMentionGroupAddChannelMembersToMentionGroupRequestBody, ChatChannelMentionGroupCreateChannelMentionGroupPathParams, ChatChannelMentionGroupCreateChannelMentionGroupRequestBody, ChatChannelMentionGroupCreateChannelMentionGroupResponse, ChatChannelMentionGroupDeleteChannelMentionGroupPathParams, ChatChannelMentionGroupListChannelMentionGroupsPathParams, ChatChannelMentionGroupListChannelMentionGroupsResponse, ChatChannelMentionGroupListMembersOfMentionGroupPathParams, ChatChannelMentionGroupListMembersOfMentionGroupQueryParams, ChatChannelMentionGroupListMembersOfMentionGroupResponse, ChatChannelMentionGroupRemoveChannelMentionGroupMembersPathParams, ChatChannelMentionGroupRemoveChannelMentionGroupMembersQueryParams, ChatChannelMentionGroupUpdateChannelMentionGroupInformationPathParams, ChatChannelMentionGroupUpdateChannelMentionGroupInformationRequestBody, ChatChannelUpdatedEvent, ChatChannelsAccountLevelBatchDeleteChannelsPathParams, ChatChannelsAccountLevelBatchDeleteChannelsQueryParams, ChatChannelsAccountLevelBatchDemoteChannelAdministratorsPathParams, ChatChannelsAccountLevelBatchDemoteChannelAdministratorsQueryParams, ChatChannelsAccountLevelBatchRemoveMembersFromUsersChannelPathParams, ChatChannelsAccountLevelBatchRemoveMembersFromUsersChannelQueryParams, ChatChannelsAccountLevelDeleteChannelPathParams, ChatChannelsAccountLevelGetChannelPathParams, ChatChannelsAccountLevelGetChannelResponse, ChatChannelsAccountLevelGetRetentionPolicyOfChannelPathParams, ChatChannelsAccountLevelGetRetentionPolicyOfChannelResponse, ChatChannelsAccountLevelInviteChannelMembersPathParams, ChatChannelsAccountLevelInviteChannelMembersRequestBody, ChatChannelsAccountLevelInviteChannelMembersResponse, ChatChannelsAccountLevelListAccountsPublicChannelsQueryParams, ChatChannelsAccountLevelListAccountsPublicChannelsResponse, ChatChannelsAccountLevelListChannelActivityLogsPathParams, ChatChannelsAccountLevelListChannelActivityLogsQueryParams, ChatChannelsAccountLevelListChannelActivityLogsResponse, ChatChannelsAccountLevelListChannelAdministratorsPathParams, ChatChannelsAccountLevelListChannelAdministratorsQueryParams, ChatChannelsAccountLevelListChannelAdministratorsResponse, ChatChannelsAccountLevelListChannelMembersPathParams, ChatChannelsAccountLevelListChannelMembersQueryParams, ChatChannelsAccountLevelListChannelMembersResponse, ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsPathParams, ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsRequestBody, ChatChannelsAccountLevelPromoteChannelMembersToAdministratorsResponse, ChatChannelsAccountLevelRemoveMemberPathParams, ChatChannelsAccountLevelSearchUsersOrAccountsChannelsRequestBody, ChatChannelsAccountLevelSearchUsersOrAccountsChannelsResponse, ChatChannelsAccountLevelUpdateChannelPathParams, ChatChannelsAccountLevelUpdateChannelRequestBody, ChatChannelsAccountLevelUpdateRetentionPolicyOfChannelPathParams, ChatChannelsAccountLevelUpdateRetentionPolicyOfChannelRequestBody, ChatChannelsBatchRemoveMembersFromChannelPathParams, ChatChannelsBatchRemoveMembersFromChannelQueryParams, ChatChannelsCreateChannelPathParams, ChatChannelsCreateChannelRequestBody, ChatChannelsCreateChannelResponse, ChatChannelsDeleteChannelPathParams, ChatChannelsGetChannelPathParams, ChatChannelsGetChannelResponse, ChatChannelsInviteChannelMembersGroupsPathParams, ChatChannelsInviteChannelMembersGroupsRequestBody, ChatChannelsInviteChannelMembersGroupsResponse, ChatChannelsInviteChannelMembersPathParams, ChatChannelsInviteChannelMembersRequestBody, ChatChannelsInviteChannelMembersResponse, ChatChannelsJoinChannelPathParams, ChatChannelsJoinChannelResponse, ChatChannelsLeaveChannelPathParams, ChatChannelsListChannelActivityLogsQueryParams, ChatChannelsListChannelActivityLogsResponse, ChatChannelsListChannelMembersGroupsPathParams, ChatChannelsListChannelMembersGroupsResponse, ChatChannelsListChannelMembersPathParams, ChatChannelsListChannelMembersQueryParams, ChatChannelsListChannelMembersResponse, ChatChannelsListUsersChannelsPathParams, ChatChannelsListUsersChannelsQueryParams, ChatChannelsListUsersChannelsResponse, ChatChannelsPerformOperationsOnChannelsRequestBody, ChatChannelsPerformOperationsOnChannelsResponse, ChatChannelsRemoveMemberGroupPathParams, ChatChannelsRemoveMemberPathParams, ChatChannelsUpdateChannelPathParams, ChatChannelsUpdateChannelRequestBody, ChatEmojiAddCustomEmojiRequestBody, ChatEmojiAddCustomEmojiResponse, ChatEmojiDeleteCustomEmojiPathParams, ChatEmojiListCustomEmojisQueryParams, ChatEmojiListCustomEmojisResponse, ChatFilesDeleteChatFilePathParams, ChatFilesGetFileInfoPathParams, ChatFilesGetFileInfoResponse, ChatFilesSendChatFilePathParams, ChatFilesSendChatFileRequestBody, ChatFilesSendChatFileResponse, ChatFilesUploadChatFilePathParams, ChatFilesUploadChatFileQueryParams, ChatFilesUploadChatFileRequestBody, ChatFilesUploadChatFileResponse, ChatMessageDeletedEvent, ChatMessageRepliedEvent, ChatMessageSentEvent, ChatMessageUpdatedEvent, ChatMessagesAddOrRemoveBookmarkQueryParams, ChatMessagesAddOrRemoveBookmarkRequestBody, ChatMessagesDeleteMessagePathParams, ChatMessagesDeleteMessageQueryParams, ChatMessagesDeleteScheduledMessagePathParams, ChatMessagesDeleteScheduledMessageQueryParams, ChatMessagesGetForwardedMessagePathParams, ChatMessagesGetForwardedMessageResponse, ChatMessagesGetMessagePathParams, ChatMessagesGetMessageQueryParams, ChatMessagesGetMessageResponse, ChatMessagesListBookmarksQueryParams, ChatMessagesListBookmarksResponse, ChatMessagesListPinnedHistoryMessagesOfChannelPathParams, ChatMessagesListPinnedHistoryMessagesOfChannelQueryParams, ChatMessagesListPinnedHistoryMessagesOfChannelResponse, ChatMessagesListScheduledMessagesQueryParams, ChatMessagesListScheduledMessagesResponse, ChatMessagesListUsersChatMessagesPathParams, ChatMessagesListUsersChatMessagesQueryParams, ChatMessagesListUsersChatMessagesResponse, ChatMessagesMarkMessageReadOrUnreadPathParams, ChatMessagesMarkMessageReadOrUnreadRequestBody, ChatMessagesPerformOperationsOnMessageOfChannelRequestBody, ChatMessagesReactToChatMessagePathParams, ChatMessagesReactToChatMessageRequestBody, ChatMessagesRetrieveThreadPathParams, ChatMessagesRetrieveThreadQueryParams, ChatMessagesRetrieveThreadResponse, ChatMessagesSendChatMessagePathParams, ChatMessagesSendChatMessageRequestBody, ChatMessagesSendChatMessageResponse, ChatMessagesUpdateMessagePathParams, ChatMessagesUpdateMessageRequestBody, ChatMigrationGetMigratedZoomChannelIDsQueryParams, ChatMigrationGetMigratedZoomChannelIDsResponse, ChatMigrationGetMigratedZoomUserIDsQueryParams, ChatMigrationGetMigratedZoomUserIDsResponse, ChatMigrationMigrateChannelMembersPathParams, ChatMigrationMigrateChannelMembersRequestBody, ChatMigrationMigrateChatChannelPathParams, ChatMigrationMigrateChatChannelRequestBody, ChatMigrationMigrateChatChannelResponse, ChatMigrationMigrateChatMessageReactionsRequestBody, ChatMigrationMigrateChatMessagesRequestBody, ChatMigrationMigrateChatMessagesResponse, ChatMigrationMigrateConversationOrChannelOperationsPathParams, ChatMigrationMigrateConversationOrChannelOperationsRequestBody, ChatReminderCreateReminderMessagePathParams, ChatReminderCreateReminderMessageRequestBody, ChatReminderDeleteReminderForMessagePathParams, ChatReminderDeleteReminderForMessageQueryParams, ChatReminderListRemindersQueryParams, ChatReminderListRemindersResponse, ChatSessionsListUsersChatSessionsPathParams, ChatSessionsListUsersChatSessionsQueryParams, ChatSessionsListUsersChatSessionsResponse, ChatSessionsStarOrUnstarChannelOrContactUserPathParams, ChatSessionsStarOrUnstarChannelOrContactUserRequestBody, ClientCredentialsToken, ContactsGetUsersContactDetailsPathParams, ContactsGetUsersContactDetailsQueryParams, ContactsGetUsersContactDetailsResponse, ContactsListUsersContactsQueryParams, ContactsListUsersContactsResponse, ContactsSearchCompanyContactsQueryParams, ContactsSearchCompanyContactsResponse, HttpReceiverOptions, IMChatSendIMMessagesQueryParams, IMChatSendIMMessagesRequestBody, IMChatSendIMMessagesResponse, IMGroupsAddIMDirectoryGroupMembersPathParams, IMGroupsAddIMDirectoryGroupMembersRequestBody, IMGroupsAddIMDirectoryGroupMembersResponse, IMGroupsCreateIMDirectoryGroupRequestBody, IMGroupsDeleteIMDirectoryGroupMemberPathParams, IMGroupsDeleteIMDirectoryGroupPathParams, IMGroupsListIMDirectoryGroupMembersPathParams, IMGroupsListIMDirectoryGroupMembersQueryParams, IMGroupsListIMDirectoryGroupMembersResponse, IMGroupsListIMDirectoryGroupsResponse, IMGroupsRetrieveIMDirectoryGroupPathParams, IMGroupsRetrieveIMDirectoryGroupResponse, IMGroupsUpdateIMDirectoryGroupPathParams, IMGroupsUpdateIMDirectoryGroupRequestBody, InvitationsSendNewContactInvitationPathParams, InvitationsSendNewContactInvitationRequestBody, JwtToken, LegalHoldAddLegalHoldMatterRequestBody, LegalHoldAddLegalHoldMatterResponse, LegalHoldDeleteLegalHoldMattersPathParams, LegalHoldDownloadLegalHoldFilesForGivenMatterPathParams, LegalHoldDownloadLegalHoldFilesForGivenMatterQueryParams, LegalHoldListLegalHoldFilesByGivenMatterPathParams, LegalHoldListLegalHoldFilesByGivenMatterQueryParams, LegalHoldListLegalHoldFilesByGivenMatterResponse, LegalHoldListLegalHoldMattersQueryParams, LegalHoldListLegalHoldMattersResponse, LegalHoldUpdateLegalHoldMatterPathParams, LegalHoldUpdateLegalHoldMatterRequestBody, Logger, MessageReplyContext, OAuthToken, Receiver, ReceiverInitOptions, ReportsGetChatMessageReportsPathParams, ReportsGetChatMessageReportsQueryParams, ReportsGetChatMessageReportsResponse, ReportsGetChatSessionsReportsQueryParams, ReportsGetChatSessionsReportsResponse, S2SAuthToken, SharedSpacesAddMembersToSharedSpacePathParams, SharedSpacesAddMembersToSharedSpaceRequestBody, SharedSpacesAddMembersToSharedSpaceResponse, SharedSpacesCreateSharedSpaceRequestBody, SharedSpacesCreateSharedSpaceResponse, SharedSpacesDeleteSharedSpacePathParams, SharedSpacesDemoteSharedSpaceAdministratorsToMembersPathParams, SharedSpacesDemoteSharedSpaceAdministratorsToMembersQueryParams, SharedSpacesDemoteSharedSpaceAdministratorsToMembersResponse, SharedSpacesGetSharedSpacePathParams, SharedSpacesGetSharedSpaceResponse, SharedSpacesListSharedSpaceChannelsPathParams, SharedSpacesListSharedSpaceChannelsQueryParams, SharedSpacesListSharedSpaceChannelsResponse, SharedSpacesListSharedSpaceMembersPathParams, SharedSpacesListSharedSpaceMembersQueryParams, SharedSpacesListSharedSpaceMembersResponse, SharedSpacesListSharedSpacesQueryParams, SharedSpacesListSharedSpacesResponse, SharedSpacesMoveSharedSpaceChannelsPathParams, SharedSpacesMoveSharedSpaceChannelsRequestBody, SharedSpacesMoveSharedSpaceChannelsResponse, SharedSpacesPromoteSharedSpaceMembersToAdministratorsPathParams, SharedSpacesPromoteSharedSpaceMembersToAdministratorsRequestBody, SharedSpacesPromoteSharedSpaceMembersToAdministratorsResponse, SharedSpacesRemoveMembersFromSharedSpacePathParams, SharedSpacesRemoveMembersFromSharedSpaceQueryParams, SharedSpacesRemoveMembersFromSharedSpaceResponse, SharedSpacesTransferSharedSpaceOwnershipPathParams, SharedSpacesTransferSharedSpaceOwnershipQueryParams, SharedSpacesUpdateSharedSpaceSettingsPathParams, SharedSpacesUpdateSharedSpaceSettingsRequestBody, StateStore, TeamChatBookmarkAddedEvent, TeamChatBookmarkRemovedEvent, TeamChatChannelAppAddedEvent, TeamChatChannelAppRemovedEvent, TeamChatChannelArchivedEvent, TeamChatChannelInvitationAcceptedEvent, TeamChatChannelInvitationApprovalRequestedEvent, TeamChatChannelInvitationApprovedEvent, TeamChatChannelInvitationCreatedEvent, TeamChatChannelInvitationDeclinedEvent, TeamChatChannelInvitationRejectedEvent, TeamChatChannelInvitationRemovedEvent, TeamChatChannelJoinApprovalRequestedEvent, TeamChatChannelJoinApprovedEvent, TeamChatChannelJoinDeclinedEvent, TeamChatChannelJoinRequestedEvent, TeamChatChannelMessageDeletedEvent, TeamChatChannelMessagePostedEvent, TeamChatChannelMessageUpdatedEvent, TeamChatChannelPinAddedEvent, TeamChatChannelPinRemovedEvent, TeamChatChannelReactionAddedEvent, TeamChatChannelReactionRemovedEvent, TeamChatChannelUnarchivedEvent, TeamChatDmMessageDeletedEvent, TeamChatDmMessagePostedEvent, TeamChatDmMessageUpdatedEvent, TeamChatDmReactionAddedEvent, TeamChatDmReactionRemovedEvent, TeamChatEmojiAddedEvent, TeamChatEmojiRemovedEvent, TeamChatEvents, TeamChatFileChangedEvent, TeamChatFileDeletedEvent, TeamChatFileDownloadedEvent, TeamChatFileSharedEvent, TeamChatFileUnsharedEvent, TeamChatFileUploadedEvent, TeamChatOptions, TeamChatS2SAuthOptions, TeamChatSharedSpacesEditedEvent, TeamChatSharedSpacesMemberInvitedEvent, TeamChatSharedSpacesMemberLeftEvent, TeamChatSharedSpacesMemberRemovedEvent, TeamChatStarredEvent, TeamChatUnstarredEvent, TokenStore };
