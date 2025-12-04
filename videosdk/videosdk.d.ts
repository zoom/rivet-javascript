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
declare class JwtAuth extends Auth<JwtToken> {
    private generateToken;
    getToken(): Promise<string>;
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

type ByosStorageUpdateBringYourOwnStorageSettingsRequestBody = {
    bring_our_own_storage: boolean;
    storage_location_id?: string;
};
type ByosStorageListStorageLocationResponse = {
    id: string;
    name: string;
    provider: "aws_s3";
    selected?: boolean;
    s3: {
        region: string;
        bucket: string;
        authentication_mechanism: "aws_access_key";
    };
}[];
type ByosStorageAddStorageLocationRequestBody = {
    name: string;
    provider: "aws_s3";
    s3: {
        region: string;
        bucket: string;
        authentication_mechanism: "aws_access_key";
        access_key: {
            id: string;
            key: string;
        };
    };
};
type ByosStorageAddStorageLocationResponse = {
    id: string;
    name: string;
    provider: "aws_s3";
    s3: {
        region: string;
        bucket: string;
        authentication_mechanism: "aws_access_key";
    };
};
type ByosStorageStorageLocationDetailPathParams = {
    storageLocationId: string;
};
type ByosStorageStorageLocationDetailResponse = {
    id: string;
    name: string;
    provider: "aws_s3";
    s3: {
        region: string;
        bucket: string;
        authentication_mechanism: "aws_access_key";
    };
    verify_status: "success" | "failure";
};
type ByosStorageDeleteStorageLocationDetailPathParams = {
    storageLocationId: string;
};
type ByosStorageChangeStorageLocationDetailPathParams = {
    storageLocationId: string;
};
type ByosStorageChangeStorageLocationDetailRequestBody = {
    name?: string;
    provider?: "aws_s3";
    s3?: {
        region?: string;
        bucket?: string;
        authentication_mechanism?: "aws_access_key";
        access_key?: {
            id?: string;
            key?: string;
        };
    };
};
type CloudRecordingListRecordingsOfAccountQueryParams = {
    page_size?: number;
    next_page_token?: string;
    trash?: boolean;
    trash_type?: string;
    from?: string;
    to?: string;
};
type CloudRecordingListRecordingsOfAccountResponse = {
    from?: string;
    to?: string;
    page_size?: number;
    total_records?: number;
    next_page_token?: string;
} & {
    sessions?: ({
        session_id?: string;
        session_name?: string;
        start_time?: string;
        duration?: number;
        total_size?: number;
        recording_count?: number;
        session_key?: string;
    } & {
        recording_files?: {
            id?: string;
            recording_start?: string;
            recording_end?: string;
            file_type?: string;
            file_size?: number;
            download_url?: string;
            external_storage_url?: string;
            status?: "completed";
            deleted_time?: string;
            recording_type?: string;
        }[];
    } & {
        participant_video_files?: {
            id?: string;
            recording_start?: string;
            recording_end?: string;
            file_name?: string;
            file_type?: string;
            file_extension?: string;
            file_size?: number;
            download_url?: string;
            recording_type?: "individual_user" | "individual_shared_screen";
            status?: "completed";
            user_id?: string;
            user_key?: string;
        }[];
    })[];
};
type CloudRecordingListSessionsRecordingsPathParams = {
    sessionId: string;
};
type CloudRecordingListSessionsRecordingsQueryParams = {
    include_fields?: string;
    ttl?: number;
};
type CloudRecordingListSessionsRecordingsResponse = ({
    session_id?: string;
    session_name?: string;
    start_time?: string;
    duration?: number;
    total_size?: number;
    recording_count?: number;
    session_key?: string;
} & {
    recording_files?: {
        id?: string;
        recording_start?: string;
        recording_end?: string;
        file_type?: string;
        file_size?: number;
        download_url?: string;
        external_storage_url?: string;
        status?: "completed";
        deleted_time?: string;
        recording_type?: string;
    }[];
} & {
    participant_video_files?: {
        id?: string;
        recording_start?: string;
        recording_end?: string;
        file_name?: string;
        file_type?: string;
        file_extension?: string;
        file_size?: number;
        download_url?: string;
        recording_type?: "individual_user" | "individual_shared_screen";
        status?: "completed";
    }[];
}) & {
    download_access_token?: string;
} & {
    participant_audio_files?: {
        id?: string;
        recording_start?: string;
        recording_end?: string;
        file_name?: string;
        file_type?: string;
        file_extension?: string;
        file_size?: number;
        download_url?: string;
        status?: "completed";
        user_id?: string;
        user_key?: string;
    }[];
} & {
    participant_video_files?: {
        id?: string;
        recording_start?: string;
        recording_end?: string;
        file_name?: string;
        file_type?: string;
        file_extension?: string;
        file_size?: number;
        download_url?: string;
        recording_type?: "individual_user" | "individual_shared_screen";
        status?: "completed";
        user_id?: string;
        user_key?: string;
    }[];
};
type CloudRecordingDeleteSessionsRecordingsPathParams = {
    sessionId: string;
};
type CloudRecordingDeleteSessionsRecordingsQueryParams = {
    action?: "trash" | "delete";
};
type CloudRecordingRecoverSessionsRecordingsPathParams = {
    sessionId: string;
};
type CloudRecordingRecoverSessionsRecordingsRequestBody = {
    action?: "recover";
};
type CloudRecordingDeleteSessionsRecordingFilePathParams = {
    sessionId: string;
    recordingId: string;
};
type CloudRecordingDeleteSessionsRecordingFileQueryParams = {
    action?: "trash" | "delete";
};
type CloudRecordingRecoverSingleRecordingPathParams = {
    sessionId: string;
    recordingId: string;
};
type CloudRecordingRecoverSingleRecordingRequestBody = {
    action?: "recover";
};
type SessionsListSessionsQueryParams = {
    type?: "past" | "live";
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    session_key?: string;
    session_name?: string;
};
type SessionsListSessionsResponse = {
    from?: string;
    to?: string;
    page_size?: number;
    next_page_token?: string;
    sessions?: {
        id?: string;
        session_name?: string;
        start_time?: string;
        end_time?: string;
        duration?: string;
        user_count?: number;
        has_voip?: boolean;
        has_video?: boolean;
        has_screen_share?: boolean;
        has_recording?: boolean;
        has_pstn?: boolean;
        session_key?: string;
        has_session_summary?: boolean;
        audio_quality?: "good" | "fair" | "poor" | "bad";
        video_quality?: "good" | "fair" | "poor" | "bad";
        screen_share_quality?: "good" | "fair" | "poor" | "bad";
    }[];
};
type SessionsCreateSessionRequestBody = {
    session_name: string;
    session_password?: string;
    settings?: {
        auto_recording?: "cloud" | "none";
    };
};
type SessionsCreateSessionResponse = {
    session_id?: string;
    session_number?: number;
    session_name: string;
    session_password?: string;
    passcode?: string;
    created_at?: string;
    settings?: {
        auto_recording?: "cloud" | "none";
        global_dial_in_countries?: string[];
        global_dial_in_numbers?: {
            country?: string;
            country_name?: string;
            number?: string;
            type?: "toll" | "tollfree" | "premium";
        }[];
    };
};
type SessionsGetSessionDetailsPathParams = {
    sessionId: string;
};
type SessionsGetSessionDetailsQueryParams = {
    type?: "past" | "live" | "scheduled";
};
type SessionsGetSessionDetailsResponse = {
    id?: string;
    session_number?: number;
    session_name?: string;
    passcode?: string;
    start_time?: string;
    end_time?: string;
    duration?: string;
    user_count?: number;
    has_voip?: boolean;
    has_video?: boolean;
    has_screen_share?: boolean;
    has_recording?: boolean;
    has_pstn?: boolean;
    session_key?: string;
    has_session_summary?: boolean;
    created_at?: string;
    settings?: {
        auto_recording?: "cloud" | "none";
        global_dial_in_countries?: string[];
        global_dial_in_numbers?: {
            country?: string;
            country_name?: string;
            number?: string;
            type?: "toll" | "tollfree" | "premium";
        }[];
    };
    audio_quality?: "good" | "fair" | "poor" | "bad";
    video_quality?: "good" | "fair" | "poor" | "bad";
    screen_share_quality?: "good" | "fair" | "poor" | "bad";
    total_minutes?: number;
};
type SessionsDeleteSessionPathParams = {
    sessionId: string;
};
type SessionsUseInSessionEventsControlsPathParams = {
    sessionId: string;
};
type SessionsUseInSessionEventsControlsRequestBody = {
    method?: "recording.start" | "recording.stop" | "recording.pause" | "recording.resume" | "user.invite.callout" | "user.invite.room_system_callout" | "stream_ingestion.bind" | "stream_ingestion.unbind" | "stream_ingestion.send" | "stream_ingestion.stop" | "audio.block" | "audio.unblock" | "video.block" | "video.unblock" | "share.block" | "share.unblock" | "user.remove";
    params?: {
        invitee_name?: string;
        phone_number?: string;
        invite_options?: {
            require_greeting?: boolean;
            require_pressing_one?: boolean;
        };
        call_type?: string;
        device_ip?: string;
        h323_headers?: {
            from_display_name?: string;
            to_display_name?: string;
        };
        sip_headers?: {
            from_display_name?: string;
            to_display_name?: string;
            from_uri?: string;
            additional_headers?: {
                key?: string;
                value?: string;
            }[];
        };
        participant_uuid?: string;
        stream_ingestion_stream_id?: string;
    };
};
type SessionsGetSessionLiveStreamDetailsPathParams = {
    sessionId: string;
};
type SessionsGetSessionLiveStreamDetailsResponse = {
    stream_url?: string;
    stream_key?: string;
    page_url?: string;
    resolution?: string;
};
type SessionsUpdateSessionLiveStreamPathParams = {
    sessionId: string;
};
type SessionsUpdateSessionLiveStreamRequestBody = {
    stream_url: string;
    stream_key: string;
    page_url: string;
    resolution?: string;
};
type SessionsUpdateSessionLivestreamStatusPathParams = {
    sessionId: string;
};
type SessionsUpdateSessionLivestreamStatusRequestBody = {
    action?: "start" | "stop" | "mode";
    settings?: {
        active_speaker_name?: boolean;
        display_name?: string;
        layout?: "gallery_view" | "speaker_view";
        close_caption?: "burnt-in" | "embedded" | "off";
    };
};
type SessionsGetSessionSIPURIWithPasscodePathParams = {
    sessionId: string;
};
type SessionsGetSessionSIPURIWithPasscodeRequestBody = {
    passcode?: string;
};
type SessionsGetSessionSIPURIWithPasscodeResponse = {
    sip_dialing?: string;
    participant_identifier_code?: string;
    expire_in?: number;
};
type SessionsUpdateSessionStatusPathParams = {
    sessionId: string;
};
type SessionsUpdateSessionStatusRequestBody = {
    action?: "end";
};
type SessionsListSessionStreamingIngestionsPathParams = {
    sessionId: string;
};
type SessionsListSessionStreamingIngestionsResponse = {
    stream_id?: string;
    rtmp_connection_status?: 0 | 1;
    rtmp_stream_push_status?: 0 | 1;
}[];
type SessionsListSessionUsersPathParams = {
    sessionId: string;
};
type SessionsListSessionUsersQueryParams = {
    type?: "past" | "live";
    page_size?: number;
    next_page_token?: string;
};
type SessionsListSessionUsersResponse = {
    page_size?: number;
    next_page_token?: string;
    users?: {
        id?: string;
        name?: string;
        device?: "Phone" | "H.323/SIP" | "Windows" | "Mac" | "iOS" | "Android";
        ip_address?: string;
        location?: string;
        network_type?: "Wired" | "Wifi" | "PPP" | "Cellular" | "Others";
        microphone?: string;
        speaker?: string;
        camera?: string;
        data_center?: string;
        connection_type?: string;
        join_time?: string;
        leave_time?: string;
        user_key?: string;
        audio_call?: {
            call_number?: string;
            call_type?: string;
            zoom_number?: string;
        }[];
        participant_uuid?: string;
        client?: string;
        os?: string;
        os_version?: string;
        browser_name?: string;
        browser_version?: string;
        audio_quality?: "good" | "fair" | "poor" | "bad";
        video_quality?: "good" | "fair" | "poor" | "bad";
        screen_share_quality?: "good" | "fair" | "poor" | "bad";
        is_original_host?: boolean;
    }[];
};
type SessionsListSessionUsersQoSPathParams = {
    sessionId: string;
};
type SessionsListSessionUsersQoSQueryParams = {
    type?: "past" | "live";
    page_size?: number;
    next_page_token?: string;
};
type SessionsListSessionUsersQoSResponse = {
    page_size?: number;
    next_page_token?: string;
    users?: {
        id?: string;
        name?: string;
        device?: "Phone" | "H.323/SIP" | "Windows" | "Mac" | "iOS" | "Android";
        client?: string;
        os?: string;
        os_version?: string;
        browser_name?: string;
        browser_version?: string;
        ip_address?: string;
        location?: string;
        network_type?: "Wired" | "Wifi" | "PPP" | "Cellular" | "Others";
        microphone?: string;
        speaker?: string;
        camera?: string;
        data_center?: string;
        connection_type?: string;
        join_time?: string;
        leave_time?: string;
        user_key?: string;
        is_original_host?: boolean;
        user_qos?: {
            date_time?: string;
            audio_input?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
            };
            audio_output?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
            };
            video_input?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            video_output?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            as_input?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            as_output?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            audio_device_from_rwg?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
            };
            audio_device_to_rwg?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
            };
            video_device_from_rwg?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            video_device_to_rwg?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            as_device_from_rwg?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            as_device_to_rwg?: {
                bitrate?: string;
                latency?: string;
                jitter?: string;
                avg_loss?: string;
                max_loss?: string;
                resolution?: string;
                frame_rate?: string;
            };
            wifi_rssi?: {
                max_rssi?: number;
                avg_rssi?: number;
                min_rssi?: number;
                rssi_unit?: string;
            };
            cpu_usage?: {
                zoom_min_cpu_usage?: string;
                zoom_avg_cpu_usage?: string;
                zoom_max_cpu_usage?: string;
                system_max_cpu_usage?: string;
            };
        }[];
    }[];
};
type SessionsGetSharingRecordingDetailsPathParams = {
    sessionId: string;
};
type SessionsGetSharingRecordingDetailsQueryParams = {
    type?: "past" | "live";
    page_size?: number;
    next_page_token?: string;
};
type SessionsGetSharingRecordingDetailsResponse = {
    page_size?: number;
    next_page_token?: string;
    users?: {
        id?: string;
        name?: string;
        user_key?: string;
        details?: {
            content?: "local_recording" | "cloud_recording" | "desktop" | "application" | "whiteboard" | "airplay" | "camera" | "video_sdk";
            start_time?: string;
            end_time?: string;
        }[];
    }[];
};
type SessionsGetSessionUserQoSPathParams = {
    sessionId: string;
    userId: string;
};
type SessionsGetSessionUserQoSQueryParams = {
    type?: "past" | "live";
};
type SessionsGetSessionUserQoSResponse = {
    id?: string;
    name?: string;
    device?: "Phone" | "H.323/SIP" | "Windows" | "Mac" | "iOS" | "Android";
    os?: string;
    os_version?: string;
    browser_name?: string;
    browser_version?: string;
    client?: string;
    ip_address?: string;
    location?: string;
    network_type?: "Wired" | "Wifi" | "PPP" | "Cellular" | "Others";
    microphone?: string;
    speaker?: string;
    camera?: string;
    data_center?: string;
    connection_type?: string;
    join_time?: string;
    leave_time?: string;
    user_key?: string;
    is_original_host?: boolean;
    user_qos?: {
        date_time?: string;
        audio_input?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
        };
        audio_output?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
        };
        video_input?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        video_output?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        as_input?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        as_output?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        audio_device_from_rwg?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
        };
        audio_device_to_rwg?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
        };
        video_device_from_rwg?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        video_device_to_rwg?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        as_device_from_rwg?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        as_device_to_rwg?: {
            bitrate?: string;
            latency?: string;
            jitter?: string;
            avg_loss?: string;
            max_loss?: string;
            resolution?: string;
            frame_rate?: string;
        };
        wifi_rssi?: {
            max_rssi?: number;
            avg_rssi?: number;
            min_rssi?: number;
            rssi_unit?: string;
        };
        cpu_usage?: {
            zoom_min_cpu_usage?: string;
            zoom_avg_cpu_usage?: string;
            zoom_max_cpu_usage?: string;
            system_max_cpu_usage?: string;
        };
    }[];
};
type SessionsListStreamIngestionsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type SessionsListStreamIngestionsResponse = {
    page_size?: number;
    next_page_token?: string;
    stream_ingestions?: {
        stream_id?: string;
        stream_name?: string;
        stream_description?: string;
        stream_key?: string;
        stream_url?: string;
        backup_stream_url?: string;
    }[];
};
type SessionsCreateStreamIngestionRequestBody = {
    stream_name: string;
    stream_description?: string;
};
type SessionsCreateStreamIngestionResponse = {
    stream_id?: string;
    stream_name?: string;
    stream_description?: string;
    stream_key?: string;
    stream_url?: string;
    backup_stream_url?: string;
};
type SessionsGetStreamIngestionPathParams = {
    streamId: string;
};
type SessionsGetStreamIngestionResponse = {
    stream_id?: string;
    stream_name?: string;
    stream_description?: string;
    stream_key?: string;
    stream_url?: string;
    backup_stream_url?: string;
};
type SessionsDeleteStreamIngestionPathParams = {
    streamId: string;
};
type SessionsUpdateStreamIngestionPathParams = {
    streamId: string;
};
type SessionsUpdateStreamIngestionRequestBody = {
    stream_name?: string;
    stream_description?: string;
};
type VideoSDKReportsGetCloudRecordingUsageReportQueryParams = {
    from: string;
    to: string;
};
type VideoSDKReportsGetCloudRecordingUsageReportResponse = {
    from?: string;
    to?: string;
    cloud_recording_storage?: {
        date?: string;
        usage?: string;
        plan_usage?: string;
        free_usage?: string;
    }[];
};
type VideoSDKReportsGetDailyUsageReportQueryParams = {
    year?: number;
    month?: number;
};
type VideoSDKReportsGetDailyUsageReportResponse = {
    year?: number;
    month?: number;
    dates?: {
        date?: string;
        sessions?: number;
        users?: number;
        session_minutes?: number;
    }[];
};
type VideoSDKReportsGetOperationLogsReportQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    category_type?: "all" | "user" | "user_settings" | "account" | "billing" | "im" | "recording" | "phone_contacts" | "webinar" | "sub_account" | "role" | "zoom_rooms";
};
type VideoSDKReportsGetOperationLogsReportResponse = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    operation_logs?: {
        time?: string;
        operator?: string;
        category_type?: string;
        action?: string;
        operation_detail?: string;
    }[];
};
type VideoSDKReportsGetTelephoneReportQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    type?: "1" | "2" | "3";
    query_date_type?: "start_time" | "end_time" | "session_start_time" | "session_end_time";
};
type VideoSDKReportsGetTelephoneReportResponse = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    telephony_usage?: {
        session_id?: string;
        phone_number?: string;
        signaled_number?: string;
        start_time?: string;
        end_time?: string;
        duration?: number;
        total?: number;
        country_name?: string;
        call_in_number?: string;
        type?: "toll-free" | "call-out" | "call-in" | "US toll-number" | "global toll-number" | "premium" | "premium call-in";
        rate?: number;
    }[];
};
declare class VideoSdkEndpoints extends WebEndpoints {
    readonly byosStorage: {
        updateBringYourOwnStorageSettings: (_: object & {
            body: ByosStorageUpdateBringYourOwnStorageSettingsRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        listStorageLocation: (_: object) => Promise<BaseResponse<ByosStorageListStorageLocationResponse>>;
        addStorageLocation: (_: object & {
            body: ByosStorageAddStorageLocationRequestBody;
        }) => Promise<BaseResponse<ByosStorageAddStorageLocationResponse>>;
        storageLocationDetail: (_: {
            path: ByosStorageStorageLocationDetailPathParams;
        } & object) => Promise<BaseResponse<ByosStorageStorageLocationDetailResponse>>;
        deleteStorageLocationDetail: (_: {
            path: ByosStorageDeleteStorageLocationDetailPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        changeStorageLocationDetail: (_: {
            path: ByosStorageChangeStorageLocationDetailPathParams;
        } & {
            body?: ByosStorageChangeStorageLocationDetailRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly cloudRecording: {
        listRecordingsOfAccount: (_: object & {
            query?: CloudRecordingListRecordingsOfAccountQueryParams;
        }) => Promise<BaseResponse<CloudRecordingListRecordingsOfAccountResponse>>;
        listSessionsRecordings: (_: {
            path: CloudRecordingListSessionsRecordingsPathParams;
        } & object & {
            query?: CloudRecordingListSessionsRecordingsQueryParams;
        }) => Promise<BaseResponse<CloudRecordingListSessionsRecordingsResponse>>;
        deleteSessionsRecordings: (_: {
            path: CloudRecordingDeleteSessionsRecordingsPathParams;
        } & object & {
            query?: CloudRecordingDeleteSessionsRecordingsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        recoverSessionsRecordings: (_: {
            path: CloudRecordingRecoverSessionsRecordingsPathParams;
        } & {
            body?: CloudRecordingRecoverSessionsRecordingsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteSessionsRecordingFile: (_: {
            path: CloudRecordingDeleteSessionsRecordingFilePathParams;
        } & object & {
            query?: CloudRecordingDeleteSessionsRecordingFileQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        recoverSingleRecording: (_: {
            path: CloudRecordingRecoverSingleRecordingPathParams;
        } & {
            body?: CloudRecordingRecoverSingleRecordingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly sessions: {
        listSessions: (_: object & {
            query: SessionsListSessionsQueryParams;
        }) => Promise<BaseResponse<SessionsListSessionsResponse>>;
        createSession: (_: object & {
            body: SessionsCreateSessionRequestBody;
        }) => Promise<BaseResponse<SessionsCreateSessionResponse>>;
        getSessionDetails: (_: {
            path: SessionsGetSessionDetailsPathParams;
        } & object & {
            query?: SessionsGetSessionDetailsQueryParams;
        }) => Promise<BaseResponse<SessionsGetSessionDetailsResponse>>;
        deleteSession: (_: {
            path: SessionsDeleteSessionPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        useInSessionEventsControls: (_: {
            path: SessionsUseInSessionEventsControlsPathParams;
        } & {
            body?: SessionsUseInSessionEventsControlsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getSessionLiveStreamDetails: (_: {
            path: SessionsGetSessionLiveStreamDetailsPathParams;
        } & object) => Promise<BaseResponse<SessionsGetSessionLiveStreamDetailsResponse>>;
        updateSessionLiveStream: (_: {
            path: SessionsUpdateSessionLiveStreamPathParams;
        } & {
            body: SessionsUpdateSessionLiveStreamRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateSessionLivestreamStatus: (_: {
            path: SessionsUpdateSessionLivestreamStatusPathParams;
        } & {
            body?: SessionsUpdateSessionLivestreamStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getSessionSIPURIWithPasscode: (_: {
            path: SessionsGetSessionSIPURIWithPasscodePathParams;
        } & {
            body?: SessionsGetSessionSIPURIWithPasscodeRequestBody;
        } & object) => Promise<BaseResponse<SessionsGetSessionSIPURIWithPasscodeResponse>>;
        updateSessionStatus: (_: {
            path: SessionsUpdateSessionStatusPathParams;
        } & {
            body?: SessionsUpdateSessionStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listSessionStreamingIngestions: (_: {
            path: SessionsListSessionStreamingIngestionsPathParams;
        } & object) => Promise<BaseResponse<SessionsListSessionStreamingIngestionsResponse>>;
        listSessionUsers: (_: {
            path: SessionsListSessionUsersPathParams;
        } & object & {
            query?: SessionsListSessionUsersQueryParams;
        }) => Promise<BaseResponse<SessionsListSessionUsersResponse>>;
        listSessionUsersQoS: (_: {
            path: SessionsListSessionUsersQoSPathParams;
        } & object & {
            query?: SessionsListSessionUsersQoSQueryParams;
        }) => Promise<BaseResponse<SessionsListSessionUsersQoSResponse>>;
        getSharingRecordingDetails: (_: {
            path: SessionsGetSharingRecordingDetailsPathParams;
        } & object & {
            query?: SessionsGetSharingRecordingDetailsQueryParams;
        }) => Promise<BaseResponse<SessionsGetSharingRecordingDetailsResponse>>;
        getSessionUserQoS: (_: {
            path: SessionsGetSessionUserQoSPathParams;
        } & object & {
            query?: SessionsGetSessionUserQoSQueryParams;
        }) => Promise<BaseResponse<SessionsGetSessionUserQoSResponse>>;
        listStreamIngestions: (_: object & {
            query?: SessionsListStreamIngestionsQueryParams;
        }) => Promise<BaseResponse<SessionsListStreamIngestionsResponse>>;
        createStreamIngestion: (_: object & {
            body: SessionsCreateStreamIngestionRequestBody;
        }) => Promise<BaseResponse<SessionsCreateStreamIngestionResponse>>;
        getStreamIngestion: (_: {
            path: SessionsGetStreamIngestionPathParams;
        } & object) => Promise<BaseResponse<SessionsGetStreamIngestionResponse>>;
        deleteStreamIngestion: (_: {
            path: SessionsDeleteStreamIngestionPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateStreamIngestion: (_: {
            path: SessionsUpdateStreamIngestionPathParams;
        } & {
            body?: SessionsUpdateStreamIngestionRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly videoSDKReports: {
        getCloudRecordingUsageReport: (_: object & {
            query: VideoSDKReportsGetCloudRecordingUsageReportQueryParams;
        }) => Promise<BaseResponse<VideoSDKReportsGetCloudRecordingUsageReportResponse>>;
        getDailyUsageReport: (_: object & {
            query?: VideoSDKReportsGetDailyUsageReportQueryParams;
        }) => Promise<BaseResponse<VideoSDKReportsGetDailyUsageReportResponse>>;
        getOperationLogsReport: (_: object & {
            query: VideoSDKReportsGetOperationLogsReportQueryParams;
        }) => Promise<BaseResponse<VideoSDKReportsGetOperationLogsReportResponse>>;
        getTelephoneReport: (_: object & {
            query: VideoSDKReportsGetTelephoneReportQueryParams;
        }) => Promise<BaseResponse<VideoSDKReportsGetTelephoneReportResponse>>;
    };
}

type SessionUserPhoneCalloutRingingEvent = Event<"session.user_phone_callout_ringing"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            session_key: string;
            user_key: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
                from_number: number;
            };
        };
    };
};
type SessionUserRoomSystemCalloutRingingEvent = Event<"session.user_room_system_callout_ringing"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            host_id: string;
            message_id: string;
            inviter_name: string;
            participant: {
                call_type: string;
                device_ip: string;
            };
        };
    };
};
type SessionRecordingStartedEvent = Event<"session.recording_started"> & {
    event: "session.recording_started";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
            recording_file: {
                recording_start?: string;
                recording_end?: string;
            };
        };
    };
};
type SessionRecordingResumedEvent = Event<"session.recording_resumed"> & {
    event: "session.recording_resumed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
            recording_file: {
                recording_start?: string;
                recording_end?: string;
            };
        };
    };
};
type SessionLiveStreamingStoppedEvent = Event<"session.live_streaming_stopped"> & {
    event: "session.live_streaming_stopped";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            start_time: string;
            live_streaming: {
                service: "Facebook" | "Workplace_by_Facebook" | "YouTube" | "Custom_Live_Streaming_Service";
                custom_live_streaming_settings: {
                    stream_url: string;
                    stream_key: string;
                    page_url: string;
                    resolution?: string;
                };
                date_time: string;
            };
        };
    };
};
type SessionStreamIngestionStoppedEvent = Event<"session.stream_ingestion_stopped"> & {
    event: "session.stream_ingestion_stopped";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key?: string;
            stream_ingestion: {
                stream_id: string;
                stream_name: string;
                stream_description?: string;
                stream_key: string;
                stream_url: string;
                backup_stream_url: string;
            };
        };
    };
};
type SessionUserRoomSystemCalloutRejectedEvent = Event<"session.user_room_system_callout_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            host_id: string;
            message_id: string;
            inviter_name: string;
            participant: {
                call_type: string;
                device_ip: string;
            };
        };
    };
};
type SessionAlertEvent = Event<"session.alert"> & {
    event: "session.alert";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            issues: ("Unstable audio quality" | "Unstable video quality" | "Unstable screen share quality" | "High CPU occupation" | "Call Reconnection")[];
        };
    };
};
type SessionRecordingSummaryCompletedEvent = Event<"session.recording_summary_completed"> & {
    event: "session.recording_summary_completed";
    event_ts: number;
    download_token: string;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
            recording_files: {
                id?: string;
                recording_start?: string;
                recording_end?: string;
                file_name?: string;
                file_path?: string;
                file_type?: "SUMMARY";
                file_size?: number;
                file_extension?: "JSON";
                download_url?: string;
                status?: "completed";
                recording_type?: "summary";
            }[];
        };
    };
};
type SessionSharingEndedEvent = Event<"session.sharing_ended"> & {
    event: "session.sharing_ended";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            user: {
                id: string;
                name: string;
                user_key?: string;
                sharing_details: {
                    content: "application" | "whiteboard" | "desktop" | "unknown";
                    date_time: string;
                };
            };
        };
    };
};
type SessionRecordingPausedEvent = Event<"session.recording_paused"> & {
    event: "session.recording_paused";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
            recording_file: {
                recording_start?: string;
                recording_end?: string;
            };
        };
    };
};
type SessionEndedEvent = Event<"session.ended"> & {
    event: "session.ended";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            start_time: string;
            end_time: string;
        };
    };
};
type SessionStartedEvent = Event<"session.started"> & {
    event: "session.started";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            start_time: string;
        };
    };
};
type SessionStreamIngestionUnbindEvent = Event<"session.stream_ingestion_unbind"> & {
    event: "session.stream_ingestion_unbind";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key?: string;
            stream_ingestion: {
                stream_id: string;
                stream_name: string;
                stream_description?: string;
                stream_key: string;
                stream_url: string;
                backup_stream_url: string;
            };
        };
    };
};
type SessionLiveStreamingStartedEvent = Event<"session.live_streaming_started"> & {
    event: "session.live_streaming_started";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            start_time: string;
            live_streaming: {
                service: "Facebook" | "Workplace_by_Facebook" | "YouTube" | "Custom_Live_Streaming_Service";
                custom_live_streaming_settings: {
                    stream_url: string;
                    stream_key: string;
                    page_url: string;
                    resolution?: string;
                };
                date_time: string;
            };
        };
    };
};
type SessionUserRoomSystemCalloutMissedEvent = Event<"session.user_room_system_callout_missed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            host_id: string;
            message_id: string;
            inviter_name: string;
            participant: {
                call_type: string;
                device_ip: string;
            };
        };
    };
};
type SessionUserPhoneCalloutAcceptedEvent = Event<"session.user_phone_callout_accepted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            session_key: string;
            user_key: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
                from_number: number;
            };
        };
    };
};
type SessionUserLeftEvent = Event<"session.user_left"> & {
    event: "session.user_left";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            user: {
                id: string;
                name: string;
                leave_time: string;
                leave_reason?: string;
                user_key?: string;
                phone_number?: string;
                participant_uuid: string;
            };
        };
    };
};
type SessionSharingStartedEvent = Event<"session.sharing_started"> & {
    event: "session.sharing_started";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            user: {
                id: string;
                name: string;
                user_key?: string;
                sharing_details: {
                    content: "application" | "whiteboard" | "desktop" | "unknown";
                    date_time: string;
                };
            };
        };
    };
};
type SessionUserPhoneCalloutCanceledEvent = Event<"session.user_phone_callout_canceled"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            user_key: string;
            participant: {
                invitee_name: string;
                phone_number: number;
                from_number: number;
            };
        };
    };
};
type SessionRecordingTranscriptCompletedEvent = Event<"session.recording_transcript_completed"> & {
    event: "session.recording_transcript_completed";
    event_ts: number;
    download_token: string;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
            recording_files: {
                id?: string;
                recording_start?: string;
                recording_end?: string;
                file_name?: string;
                file_path?: string;
                file_type?: "MP4" | "M4A" | "CHAT" | "TRANSCRIPT" | "CSV" | "CC" | "TB" | "CHAT_MESSAGE" | "TIMELINE";
                file_size?: number;
                file_extension?: "MP4" | "M4A" | "TXT" | "VTT" | "CSV" | "JSON" | "JPG";
                download_url?: string;
                status?: "completed";
                recording_type?: "shared_screen_with_speaker_view(CC)" | "shared_screen_with_speaker_view" | "shared_screen_with_gallery_view" | "gallery_view" | "shared_screen" | "audio_only" | "audio_transcript" | "chat_file" | "active_speaker" | "host_video" | "audio_only_each_participant" | "cc_transcript" | "closed_caption" | "poll" | "timeline" | "thumbnail" | "chat_message";
            }[];
        };
    };
};
type SessionRecordingDeletedEvent = Event<"session.recording_deleted"> & {
    event: "session.recording_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
        };
    };
};
type SessionUserRoomSystemCalloutFailedEvent = Event<"session.user_room_system_callout_failed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            host_id: string;
            message_id: string;
            inviter_name: string;
            reason_type: 0 | 1 | 2 | 3 | 4 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
            participant: {
                call_type: string;
                device_ip: string;
            };
        };
    };
};
type SessionRecordingCompletedEvent = Event<"session.recording_completed"> & {
    event: "session.recording_completed";
    event_ts: number;
    download_token: string;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
            recording_files: {
                id?: string;
                recording_start?: string;
                recording_end?: string;
                file_name?: string;
                file_path?: string;
                file_type?: "MP4" | "M4A" | "CHAT" | "TRANSCRIPT" | "CSV" | "CC" | "TB" | "CHAT_MESSAGE";
                file_size?: number;
                file_extension?: "MP4" | "M4A" | "TXT" | "VTT" | "CSV" | "JSON" | "JPG";
                download_url?: string;
                status?: "completed";
                recording_type?: "shared_screen_with_speaker_view(CC)" | "shared_screen_with_speaker_view" | "shared_screen_with_gallery_view" | "gallery_view" | "shared_screen" | "audio_only" | "audio_transcript" | "chat_file" | "active_speaker" | "host_video" | "audio_only_each_participant" | "cc_transcript" | "closed_caption" | "poll" | "timeline" | "thumbnail" | "chat_message";
            }[];
            participant_audio_files?: {
                id?: string;
                recording_start?: string;
                recording_end?: string;
                file_name?: string;
                file_path?: string;
                file_type?: "MP4" | "M4A" | "CHAT" | "TRANSCRIPT" | "CSV" | "CC" | "TB" | "CHAT_MESSAGE";
                file_size?: number;
                file_extension?: "MP4" | "M4A" | "TXT" | "VTT" | "CSV" | "JSON" | "JPG";
                download_url?: string;
                status?: "completed";
                recording_type?: "shared_screen_with_speaker_view(CC)" | "shared_screen_with_speaker_view" | "shared_screen_with_gallery_view" | "gallery_view" | "shared_screen" | "audio_only" | "audio_transcript" | "chat_file" | "active_speaker" | "host_video" | "audio_only_each_participant" | "cc_transcript" | "closed_caption" | "poll" | "timeline" | "thumbnail" | "chat_message";
                user_id?: string;
                user_key?: string;
            }[];
            participant_video_files?: {
                id?: string;
                recording_start?: string;
                recording_end?: string;
                file_name?: string;
                file_path?: string;
                file_type?: "MP4";
                file_size?: number;
                file_extension?: "MP4";
                download_url?: string;
                status?: "completed";
                recording_type?: "individual_user" | "individual_shared_screen";
                user_id?: string;
                user_key?: string;
            }[];
        };
    };
};
type SessionRecordingTranscriptFailedEvent = Event<"session.recording_transcript_failed"> & {
    event: "session.recording_transcript_failed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
        };
    };
};
type SessionRecordingTrashedEvent = Event<"session.recording_trashed"> & {
    event: "session.recording_trashed";
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
        };
    };
};
type SessionUserJoinedEvent = Event<"session.user_joined"> & {
    event: "session.user_joined";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            session_id: string;
            session_name: string;
            session_key?: string;
            user: {
                id: string;
                name: string;
                join_time: string;
                user_key?: string;
                phone_number?: string;
                participant_uuid: string;
            };
        };
    };
};
type SessionStreamIngestionStartedEvent = Event<"session.stream_ingestion_started"> & {
    event: "session.stream_ingestion_started";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key?: string;
            stream_ingestion: {
                stream_id: string;
                stream_name: string;
                stream_description?: string;
                stream_key: string;
                stream_url: string;
                backup_stream_url: string;
            };
        };
    };
};
type SessionStreamIngestionConnectedEvent = Event<"session.stream_ingestion_connected"> & {
    event: "session.stream_ingestion_connected";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key?: string;
            stream_ingestion: {
                stream_id: string;
                stream_name: string;
                stream_description?: string;
                stream_key: string;
                stream_url: string;
                backup_stream_url: string;
            };
        };
    };
};
type SessionStreamIngestionDisconnectedEvent = Event<"session.stream_ingestion_disconnected"> & {
    event: "session.stream_ingestion_disconnected";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key?: string;
            stream_ingestion: {
                stream_id: string;
                stream_name: string;
                stream_description?: string;
                stream_key: string;
                stream_url: string;
                backup_stream_url: string;
            };
        };
    };
};
type SessionRecordingRecoveredEvent = Event<"session.recording_recovered"> & {
    event: "session.recording_recovered";
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
        };
    };
};
type SessionUserPhoneCalloutMissedEvent = Event<"session.user_phone_callout_missed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            session_key: string;
            user_key: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
                from_number: number;
            };
        };
    };
};
type SessionUserPhoneCalloutRejectedEvent = Event<"session.user_phone_callout_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            session_key: string;
            user_key: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
                from_number: number;
            };
        };
    };
};
type SessionUserRoomSystemCalloutAcceptedEvent = Event<"session.user_room_system_callout_accepted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: number;
            uuid?: string;
            session_id: string;
            session_name: string;
            host_id: string;
            message_id: string;
            inviter_name: string;
            participant: {
                call_type: string;
                device_ip: string;
            };
        };
    };
};
type SessionRecordingStoppedEvent = Event<"session.recording_stopped"> & {
    event: "session.recording_stopped";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            session_id: string;
            session_name: string;
            session_key: string;
            start_time: string;
            timezone: string;
            recording_file: {
                recording_start?: string;
                recording_end?: string;
            };
        };
    };
};
declare const ALL_EVENTS: string[];
type VideoSdkEvents = SessionUserPhoneCalloutRingingEvent | SessionUserRoomSystemCalloutRingingEvent | SessionRecordingStartedEvent | SessionRecordingResumedEvent | SessionLiveStreamingStoppedEvent | SessionStreamIngestionStoppedEvent | SessionUserRoomSystemCalloutRejectedEvent | SessionAlertEvent | SessionRecordingSummaryCompletedEvent | SessionSharingEndedEvent | SessionRecordingPausedEvent | SessionEndedEvent | SessionStartedEvent | SessionStreamIngestionUnbindEvent | SessionLiveStreamingStartedEvent | SessionUserRoomSystemCalloutMissedEvent | SessionUserPhoneCalloutAcceptedEvent | SessionUserLeftEvent | SessionSharingStartedEvent | SessionUserPhoneCalloutCanceledEvent | SessionRecordingTranscriptCompletedEvent | SessionRecordingDeletedEvent | SessionUserRoomSystemCalloutFailedEvent | SessionRecordingCompletedEvent | SessionRecordingTranscriptFailedEvent | SessionRecordingTrashedEvent | SessionUserJoinedEvent | SessionStreamIngestionStartedEvent | SessionStreamIngestionConnectedEvent | SessionStreamIngestionDisconnectedEvent | SessionRecordingRecoveredEvent | SessionUserPhoneCalloutMissedEvent | SessionUserPhoneCalloutRejectedEvent | SessionUserRoomSystemCalloutAcceptedEvent | SessionRecordingStoppedEvent;
declare class VideoSdkEventProcessor extends EventManager<VideoSdkEndpoints, VideoSdkEvents> {
}

type VideoSdkOptions<R extends Receiver> = CommonClientOptions<JwtAuth, R>;
declare class VideoSdkClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<JwtAuth, ReceiverType> = VideoSdkOptions<ReceiverType>> extends ProductClient<JwtAuth, VideoSdkEndpoints, VideoSdkEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore }: OptionsType): JwtAuth;
    protected initEndpoints(auth: JwtAuth, options: OptionsType): VideoSdkEndpoints;
    protected initEventProcessor(endpoints: VideoSdkEndpoints): VideoSdkEventProcessor;
}

export { ALL_EVENTS, ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, CommonHttpRequestError, ConsoleLogger, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, LogLevel, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, ReceiverInconsistentStateError, ReceiverOAuthFlowError, S2SRawResponseError, StatusCode, VideoSdkClient, VideoSdkEndpoints, VideoSdkEventProcessor, isCoreError, isStateStore };
export type { ByosStorageAddStorageLocationRequestBody, ByosStorageAddStorageLocationResponse, ByosStorageChangeStorageLocationDetailPathParams, ByosStorageChangeStorageLocationDetailRequestBody, ByosStorageDeleteStorageLocationDetailPathParams, ByosStorageListStorageLocationResponse, ByosStorageStorageLocationDetailPathParams, ByosStorageStorageLocationDetailResponse, ByosStorageUpdateBringYourOwnStorageSettingsRequestBody, ClientCredentialsToken, CloudRecordingDeleteSessionsRecordingFilePathParams, CloudRecordingDeleteSessionsRecordingFileQueryParams, CloudRecordingDeleteSessionsRecordingsPathParams, CloudRecordingDeleteSessionsRecordingsQueryParams, CloudRecordingListRecordingsOfAccountQueryParams, CloudRecordingListRecordingsOfAccountResponse, CloudRecordingListSessionsRecordingsPathParams, CloudRecordingListSessionsRecordingsQueryParams, CloudRecordingListSessionsRecordingsResponse, CloudRecordingRecoverSessionsRecordingsPathParams, CloudRecordingRecoverSessionsRecordingsRequestBody, CloudRecordingRecoverSingleRecordingPathParams, CloudRecordingRecoverSingleRecordingRequestBody, HttpReceiverOptions, JwtToken, Logger, OAuthToken, Receiver, ReceiverInitOptions, S2SAuthToken, SessionAlertEvent, SessionEndedEvent, SessionLiveStreamingStartedEvent, SessionLiveStreamingStoppedEvent, SessionRecordingCompletedEvent, SessionRecordingDeletedEvent, SessionRecordingPausedEvent, SessionRecordingRecoveredEvent, SessionRecordingResumedEvent, SessionRecordingStartedEvent, SessionRecordingStoppedEvent, SessionRecordingSummaryCompletedEvent, SessionRecordingTranscriptCompletedEvent, SessionRecordingTranscriptFailedEvent, SessionRecordingTrashedEvent, SessionSharingEndedEvent, SessionSharingStartedEvent, SessionStartedEvent, SessionStreamIngestionConnectedEvent, SessionStreamIngestionDisconnectedEvent, SessionStreamIngestionStartedEvent, SessionStreamIngestionStoppedEvent, SessionStreamIngestionUnbindEvent, SessionUserJoinedEvent, SessionUserLeftEvent, SessionUserPhoneCalloutAcceptedEvent, SessionUserPhoneCalloutCanceledEvent, SessionUserPhoneCalloutMissedEvent, SessionUserPhoneCalloutRejectedEvent, SessionUserPhoneCalloutRingingEvent, SessionUserRoomSystemCalloutAcceptedEvent, SessionUserRoomSystemCalloutFailedEvent, SessionUserRoomSystemCalloutMissedEvent, SessionUserRoomSystemCalloutRejectedEvent, SessionUserRoomSystemCalloutRingingEvent, SessionsCreateSessionRequestBody, SessionsCreateSessionResponse, SessionsCreateStreamIngestionRequestBody, SessionsCreateStreamIngestionResponse, SessionsDeleteSessionPathParams, SessionsDeleteStreamIngestionPathParams, SessionsGetSessionDetailsPathParams, SessionsGetSessionDetailsQueryParams, SessionsGetSessionDetailsResponse, SessionsGetSessionLiveStreamDetailsPathParams, SessionsGetSessionLiveStreamDetailsResponse, SessionsGetSessionSIPURIWithPasscodePathParams, SessionsGetSessionSIPURIWithPasscodeRequestBody, SessionsGetSessionSIPURIWithPasscodeResponse, SessionsGetSessionUserQoSPathParams, SessionsGetSessionUserQoSQueryParams, SessionsGetSessionUserQoSResponse, SessionsGetSharingRecordingDetailsPathParams, SessionsGetSharingRecordingDetailsQueryParams, SessionsGetSharingRecordingDetailsResponse, SessionsGetStreamIngestionPathParams, SessionsGetStreamIngestionResponse, SessionsListSessionStreamingIngestionsPathParams, SessionsListSessionStreamingIngestionsResponse, SessionsListSessionUsersPathParams, SessionsListSessionUsersQoSPathParams, SessionsListSessionUsersQoSQueryParams, SessionsListSessionUsersQoSResponse, SessionsListSessionUsersQueryParams, SessionsListSessionUsersResponse, SessionsListSessionsQueryParams, SessionsListSessionsResponse, SessionsListStreamIngestionsQueryParams, SessionsListStreamIngestionsResponse, SessionsUpdateSessionLiveStreamPathParams, SessionsUpdateSessionLiveStreamRequestBody, SessionsUpdateSessionLivestreamStatusPathParams, SessionsUpdateSessionLivestreamStatusRequestBody, SessionsUpdateSessionStatusPathParams, SessionsUpdateSessionStatusRequestBody, SessionsUpdateStreamIngestionPathParams, SessionsUpdateStreamIngestionRequestBody, SessionsUseInSessionEventsControlsPathParams, SessionsUseInSessionEventsControlsRequestBody, StateStore, TokenStore, VideoSDKReportsGetCloudRecordingUsageReportQueryParams, VideoSDKReportsGetCloudRecordingUsageReportResponse, VideoSDKReportsGetDailyUsageReportQueryParams, VideoSDKReportsGetDailyUsageReportResponse, VideoSDKReportsGetOperationLogsReportQueryParams, VideoSDKReportsGetOperationLogsReportResponse, VideoSDKReportsGetTelephoneReportQueryParams, VideoSDKReportsGetTelephoneReportResponse, VideoSdkEvents, VideoSdkOptions };
