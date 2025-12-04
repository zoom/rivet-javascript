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

type AccountsListAccountsZoomPhoneSettingsQueryParams = {
    setting_types?: string;
};
type AccountsListAccountsZoomPhoneSettingsResponse = {
    call_live_transcription?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        transcription_start_prompt?: {
            enable?: boolean;
            audio_id?: string;
            audio_name?: string;
        };
    };
    local_survivability_mode?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    external_calling_on_zoom_room_common_area?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    select_outbound_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        allow_hide_outbound_caller_id?: boolean;
    };
    personal_audio_library?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        allow_music_on_hold_customization?: boolean;
        allow_voicemail_and_message_greeting_customization?: boolean;
    };
    voicemail?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        allow_videomail?: boolean;
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_share?: boolean;
        allow_virtual_background?: boolean;
    };
    voicemail_transcription?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    voicemail_notification_by_email?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        include_voicemail_file?: boolean;
        include_voicemail_transcription?: boolean;
        forward_voicemail_to_email?: boolean;
    };
    shared_voicemail_notification_by_email?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    restricted_call_hours?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        time_zone?: {
            id?: string;
            name?: string;
        };
        restricted_hours_applied?: boolean;
        restricted_holiday_hours_applied?: boolean;
        allow_internal_calls?: boolean;
    };
    allowed_call_locations?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        locations_applied?: boolean;
        allow_internal_calls?: boolean;
    };
    check_voicemails_over_phone?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    auto_call_recording?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        recording_calls?: "inbound" | "outbound" | "both";
        recording_transcription?: boolean;
        recording_start_prompt?: boolean;
        recording_start_prompt_audio_id?: string;
        recording_explicit_consent?: boolean;
        allow_stop_resume_recording?: boolean;
        disconnect_on_recording_failure?: boolean;
        play_recording_beep_tone?: {
            enable?: boolean;
            play_beep_member?: "allMembers" | "recordingUser";
            play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
            play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
        };
        inbound_audio_notification?: {
            recording_start_prompt?: boolean;
            recording_start_prompt_audio_id?: string;
            recording_explicit_consent?: boolean;
        };
        outbound_audio_notification?: {
            recording_start_prompt?: boolean;
            recording_start_prompt_audio_id?: string;
            recording_explicit_consent?: boolean;
        };
    };
    ad_hoc_call_recording?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    international_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    outbound_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    outbound_sms?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    sms?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        international_sms?: boolean;
    };
    sms_etiquette_tool?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    zoom_phone_on_mobile?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        allow_calling_sms_mms?: boolean;
    };
    zoom_phone_on_pwa?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    e2e_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    call_handling_forwarding_to_other_users?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        call_forwarding_type?: 1 | 2 | 3 | 4;
    };
    call_overflow?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        call_overflow_type?: 1 | 2 | 3 | 4;
    };
    call_transferring?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    } & {
        call_transferring_type?: 1 | 2 | 3 | 4;
    };
    elevate_to_meeting?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    call_park?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    hand_off_to_room?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    mobile_switch_to_carrier?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    delegation?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    audio_intercom?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    block_calls_without_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    block_external_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    call_queue_opt_out_reason?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    auto_delete_data_after_retention_duration?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    auto_call_from_third_party_apps?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    override_default_port?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    peer_to_peer_media?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    advanced_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    display_call_feedback_survey?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    block_list_for_inbound_calls_and_messaging?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
    };
    block_calls_as_threat?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
};
type AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersQueryParams = {
    selected?: boolean;
    site_id?: string;
    extension_type?: "autoReceptionist" | "callQueue" | "sharedLineGroup";
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersResponse = {
    customize_numbers?: {
        customize_id?: string;
        phone_number_id?: string;
        phone_number?: string;
        display_name?: string;
        incoming?: boolean;
        outgoing?: boolean;
        extension_id?: string;
        extension_type?: string;
        extension_number?: string;
        extension_name?: string;
        site?: {
            id?: string;
            name?: string;
        };
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type AccountsAddPhoneNumbersForAccountsCustomizedOutboundCallerIDRequestBody = {
    phone_number_ids?: string[];
};
type AccountsAddPhoneNumbersForAccountsCustomizedOutboundCallerIDResponse = never;
type AccountsDeletePhoneNumbersForAccountsCustomizedOutboundCallerIDQueryParams = {
    customize_ids?: string[];
};
type AlertsListAlertSettingsWithPagingQueryQueryParams = {
    page_size?: number;
    next_page_token?: string;
    module?: 1 | 2 | 3 | 4 | 5;
    rule?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
    status?: 0 | 1;
};
type AlertsListAlertSettingsWithPagingQueryResponse = {
    next_page_token?: string;
    page_size?: number;
    alert_settings?: {
        alert_setting_id?: string;
        alert_setting_name?: string;
        module?: number;
        rule?: number;
        rule_conditions?: {
            rule_condition_type?: 1 | 2 | 3 | 4 | 5;
            rule_condition_value?: string;
        }[];
        targets?: {
            target_name?: string;
        }[];
        time_frame_type?: "all_day" | "specific_time";
        time_frame_from?: string;
        time_frame_to?: string;
        frequency?: 5 | 10 | 15 | 30 | 60;
        email_recipients?: string[];
        chat_channels?: {
            chat_channel_name?: string;
            token?: string;
            end_point?: string;
        }[];
        status?: 0 | 1;
    }[];
};
type AlertsAddAlertSettingRequestBody = {
    alert_setting_name: string;
    module: number;
    rule: number;
    target_type: 1 | 2 | 3 | 4 | 5;
    target_ids?: string[];
    rule_conditions: {
        rule_condition_type?: 1 | 2 | 3 | 4 | 5;
        rule_condition_value?: string;
    }[];
    time_frame_type: "all_day" | "specific_time";
    time_frame_from: string;
    time_frame_to: string;
    frequency?: 5 | 10 | 15 | 30 | 60;
    email_recipients?: string[];
    chat_channels?: {
        chat_channel_name?: string;
        token?: string;
        end_point?: string;
    }[];
    status?: 0 | 1;
};
type AlertsAddAlertSettingResponse = {
    alert_setting_id?: string;
    alert_setting_name?: string;
};
type AlertsGetAlertSettingDetailsPathParams = {
    alertSettingId: string;
};
type AlertsGetAlertSettingDetailsResponse = {
    alert_setting_id?: string;
    alert_setting_name?: string;
    module?: number;
    rule?: number;
    rule_conditions?: {
        rule_condition_type?: 1 | 2 | 3 | 4 | 5;
        rule_condition_value?: string;
    }[];
    targets?: {
        target_id?: string;
        target_name?: string;
        target_type?: 1 | 2 | 3 | 4 | 5;
        target_extension_number?: number;
        site?: {
            id?: string;
            name?: string;
        };
        assignees?: {
            extension_number?: number;
            name?: string;
            extension_type?: "user" | "commonArea";
            extension_id?: string;
        }[];
    }[];
    time_frame_type?: "all_day" | "specific_time";
    time_frame_from?: string;
    time_frame_to?: string;
    frequency?: 5 | 10 | 15 | 30 | 60;
    email_recipients?: string[];
    chat_channels?: {
        chat_channel_name?: string;
        token?: string;
        end_point?: string;
    }[];
    status?: 0 | 1;
};
type AlertsDeleteAlertSettingPathParams = {
    alertSettingId: string;
};
type AlertsUpdateAlertSettingPathParams = {
    alertSettingId: string;
};
type AlertsUpdateAlertSettingRequestBody = {
    alert_setting_name?: string;
    rule_conditions?: {
        rule_condition_type?: 1 | 2 | 3 | 4 | 5;
        rule_condition_value?: string;
    }[];
    target_ids?: string[];
    time_frame_type?: "all_day" | "specific_time";
    time_frame_from?: string;
    time_frame_to?: string;
    frequency?: 5 | 10 | 15 | 30 | 60;
    email_recipients?: string[];
    chat_channels?: {
        chat_channel_name?: string;
        token?: string;
        end_point?: string;
    }[];
    status?: 0 | 1;
};
type AudioLibraryGetAudioItemPathParams = {
    audioId: string;
};
type AudioLibraryGetAudioItemResponse = {
    audio_id?: string;
    name?: string;
    play_url?: string;
    text?: string;
    voice_language?: "en-US" | "en-GB" | "en-GB-WLS" | "en-AU" | "en-IN" | "en-ZA" | "en-NZ" | "es-ES" | "es-US" | "es-MX" | "fr-CA" | "da-DK" | "de-DE" | "fr-FR" | "it-IT" | "is-IS" | "nl-NL" | "pt-PT" | "ja-JP" | "ko-KO" | "ko-KR" | "pt-BR" | "pl-PL" | "zh-CN" | "zh-TW" | "cmn-CN" | "tr-TR" | "nb-NO" | "ro-RO" | "ru-RU" | "sv-SE" | "cy-GB" | "ca-ES" | "de-AT" | "arb";
    voice_accent?: string;
};
type AudioLibraryDeleteAudioItemPathParams = {
    audioId: string;
};
type AudioLibraryUpdateAudioItemPathParams = {
    audioId: string;
};
type AudioLibraryUpdateAudioItemRequestBody = {
    name: string;
};
type AudioLibraryListAudioItemsPathParams = {
    userId: string;
};
type AudioLibraryListAudioItemsResponse = {
    audios?: {
        audio_id?: string;
        name?: string;
    }[];
};
type AudioLibraryAddAudioItemForTextToSpeechConversionPathParams = {
    userId: string;
};
type AudioLibraryAddAudioItemForTextToSpeechConversionRequestBody = {
    audio_name?: string;
    text?: string;
    voice_language?: string;
    voice_accent?: string;
};
type AudioLibraryAddAudioItemForTextToSpeechConversionResponse = {
    audio_id?: string;
    name?: string;
};
type AudioLibraryAddAudioItemsPathParams = {
    userId: string;
};
type AudioLibraryAddAudioItemsRequestBody = {
    attachments?: {
        audio_type?: string;
        base64_encoding?: string;
        name?: string;
    }[];
};
type AudioLibraryAddAudioItemsResponse = {
    audios?: {
        audio_id?: string;
        name?: string;
    }[];
};
type AutoReceptionistsListAutoReceptionistsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type AutoReceptionistsListAutoReceptionistsResponse = {
    auto_receptionists?: {
        cost_center?: string;
        department?: string;
        extension_id?: string;
        extension_number?: number;
        id?: string;
        name?: string;
        timezone?: string;
        audio_prompt_language?: string;
        holiday_hours?: {
            id?: string;
            name?: string;
            from?: string;
            to?: string;
        }[];
        phone_numbers?: {
            id?: string;
            number?: string;
        }[];
        site?: {
            id?: string;
            name?: string;
        };
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type AutoReceptionistsAddAutoReceptionistRequestBody = {
    name: string;
    site_id?: string;
};
type AutoReceptionistsAddAutoReceptionistResponse = {
    extension_number?: number;
    id?: string;
    name?: string;
};
type AutoReceptionistsGetAutoReceptionistPathParams = {
    autoReceptionistId: string;
};
type AutoReceptionistsGetAutoReceptionistResponse = {
    cost_center?: string;
    department?: string;
    extension_id?: string;
    extension_number?: number;
    name?: string;
    timezone?: string;
    audio_prompt_language?: "en-US" | "en-GB" | "es-US" | "fr-CA" | "da-DK" | "de-DE" | "es-ES" | "fr-FR" | "it-IT" | "nl-NL" | "pt-PT" | "ja" | "ko-KR" | "pt-BR" | "zh-CN";
    holiday_hours?: {
        id?: string;
        name?: string;
        from?: string;
        to?: string;
    }[];
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
    site?: {
        id?: string;
        name?: string;
    };
    recording_storage_location?: "US" | "AU" | "CA" | "DE" | "IN" | "JP" | "SG" | "BR" | "CN" | "MX";
    own_storage_name?: string;
};
type AutoReceptionistsDeleteNonPrimaryAutoReceptionistPathParams = {
    autoReceptionistId: string;
};
type AutoReceptionistsUpdateAutoReceptionistPathParams = {
    autoReceptionistId: string;
};
type AutoReceptionistsUpdateAutoReceptionistRequestBody = {
    cost_center?: string;
    department?: string;
    extension_number?: number;
    name?: string;
    audio_prompt_language?: "en-US" | "en-GB" | "es-US" | "fr-CA" | "da-DK" | "de-DE" | "es-ES" | "fr-FR" | "it-IT" | "nl-NL" | "pt-PT" | "ja" | "ko-KR" | "pt-BR" | "zh-CN";
    timezone?: string;
    recording_storage_location?: "US" | "AU" | "CA" | "DE" | "IN" | "JP" | "SG" | "BR" | "CN" | "MX";
};
type AutoReceptionistsAssignPhoneNumbersPathParams = {
    autoReceptionistId: string;
};
type AutoReceptionistsAssignPhoneNumbersRequestBody = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type AutoReceptionistsUnassignAllPhoneNumbersPathParams = {
    autoReceptionistId: string;
};
type AutoReceptionistsUnassignPhoneNumberPathParams = {
    autoReceptionistId: string;
    phoneNumberId: string;
};
type AutoReceptionistsGetAutoReceptionistPolicyPathParams = {
    autoReceptionistId: string;
};
type AutoReceptionistsGetAutoReceptionistPolicyResponse = {
    voicemail_access_members?: {
        shared_id?: string;
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
    }[];
    voicemail_transcription?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "site";
        modified?: boolean;
    };
    voicemail_notification_by_email?: {
        include_voicemail_file?: boolean;
        include_voicemail_transcription?: boolean;
        forward_voicemail_to_email?: boolean;
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "site";
        modified?: boolean;
    };
    sms?: {
        enable?: boolean;
        international_sms?: boolean;
        international_sms_countries?: string[];
        locked?: boolean;
        locked_by?: "invalid" | "account" | "site";
        modified?: boolean;
    };
};
type AutoReceptionistsUpdateAutoReceptionistPolicyPathParams = {
    autoReceptionistId: string;
};
type AutoReceptionistsUpdateAutoReceptionistPolicyRequestBody = {
    voicemail_transcription?: {
        enable?: boolean;
        reset?: boolean;
    };
    voicemail_notification_by_email?: {
        include_voicemail_file?: boolean;
        include_voicemail_transcription?: boolean;
        forward_voicemail_to_email?: boolean;
        enable?: boolean;
        reset?: boolean;
    };
    sms?: {
        enable?: boolean;
        reset?: boolean;
        international_sms?: boolean;
        international_sms_countries?: string[];
    };
};
type AutoReceptionistsAddPolicySubsettingPathParams = {
    autoReceptionistId: string;
    policyType: string;
};
type AutoReceptionistsAddPolicySubsettingRequestBody = {
    voicemail_access_member?: {
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
    };
};
type AutoReceptionistsAddPolicySubsettingResponse = {
    voicemail_access_member?: {
        shared_id?: string;
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
    };
};
type AutoReceptionistsDeletePolicySubsettingPathParams = {
    autoReceptionistId: string;
    policyType: string;
};
type AutoReceptionistsDeletePolicySubsettingQueryParams = {
    shared_ids: string[];
};
type AutoReceptionistsUpdatePolicySubsettingPathParams = {
    autoReceptionistId: string;
    policyType: string;
};
type AutoReceptionistsUpdatePolicySubsettingRequestBody = {
    voicemail_access_member?: {
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
        shared_id?: string;
    };
};
type BillingAccountListBillingAccountsQueryParams = {
    site_id?: string;
};
type BillingAccountListBillingAccountsResponse = {
    billing_accounts?: {
        id?: string;
        name?: string;
    }[];
};
type BillingAccountGetBillingAccountDetailsPathParams = {
    billingAccountId: string;
};
type BillingAccountGetBillingAccountDetailsResponse = {
    id?: string;
    name?: string;
};
type BlockedListListBlockedListsQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type BlockedListListBlockedListsResponse = {
    blocked_list?: {
        block_type?: "inbound" | "outbound" | "threat";
        comment?: string;
        id?: string;
        match_type?: "phoneNumber" | "prefix";
        phone_number?: string;
        status?: "active" | "inactive";
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type BlockedListCreateBlockedListRequestBody = {
    block_type?: "inbound" | "outbound" | "threat";
    comment?: string;
    country?: string;
    match_type?: "phoneNumber" | "prefix";
    phone_number?: string;
    status?: "active" | "inactive";
};
type BlockedListCreateBlockedListResponse = {
    id?: string;
};
type BlockedListGetBlockedListDetailsPathParams = {
    blockedListId: string;
};
type BlockedListGetBlockedListDetailsResponse = {
    block_type?: "inbound" | "outbound" | "threat";
    comment?: string;
    id?: string;
    match_type?: "phoneNumber" | "prefix";
    phone_number?: string;
    status?: "active" | "inactive";
};
type BlockedListDeleteBlockedListPathParams = {
    blockedListId: string;
};
type BlockedListUpdateBlockedListPathParams = {
    blockedListId: string;
};
type BlockedListUpdateBlockedListRequestBody = {
    block_type?: "inbound" | "outbound";
    comment?: string;
    country?: string;
    match_type?: "phoneNumber" | "prefix";
    phone_number?: string;
    status?: "active" | "inactive";
};
type CallHandlingGetCallHandlingSettingsPathParams = {
    extensionId: string;
};
type CallHandlingGetCallHandlingSettingsResponse = {
    business_hours?: {
        settings?: {
            allow_callers_check_voicemail?: boolean;
            allow_members_to_reset?: boolean;
            audio_while_connecting?: {
                id?: string;
                name?: string;
            };
            call_distribution?: {
                handle_multiple_calls?: boolean;
                ring_duration?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
                ring_mode?: "simultaneous" | "sequential" | "rotating" | "longest_idle";
                skip_offline_device_phone_number?: boolean;
            };
            call_forwarding_settings?: {
                description?: string;
                enable?: boolean;
                id?: string;
                phone_number?: string;
                external_contact?: {
                    name?: string;
                    email?: string;
                    external_contact_id?: string;
                    phone_numbers?: string[];
                };
            }[];
            call_not_answer_action?: 1 | 2 | 4 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
            connect_to_operator?: boolean;
            custom_hours_settings?: {
                from?: string;
                to?: string;
                type?: 0 | 1 | 2;
                weekday?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
            }[];
            greeting_prompt?: {
                id?: string;
                name?: string;
            };
            max_call_in_queue?: number;
            max_wait_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60 | 120 | 180 | 240 | 300 | 600 | 900 | 1200 | 1500 | 1800;
            music_on_hold?: {
                id?: string;
                name?: string;
            };
            receive_call?: boolean;
            require_press_1_before_connecting?: boolean;
            ring_mode?: "simultaneous" | "sequential";
            routing?: {
                action?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 14 | 15 | 18 | 19;
                forward_to?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "autoReceptionist" | "callQueue" | "commonArea";
                    id?: string;
                    phone_number?: string;
                    description?: string;
                    voicemail_greeting?: {
                        id?: string;
                        name?: string;
                    };
                    zcc_phone_number?: string;
                    zcc_phone_number_display_name?: string;
                    partner_contact_center_id?: string;
                    pcc_phone_number_display_name?: string;
                    teams_app_id?: string;
                    teams_voice_app_name?: string;
                };
                operator?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "commonArea" | "sharedLineGroup" | "callQueue";
                    id?: string;
                };
                connect_to_operator?: boolean;
                allow_callers_check_voicemail?: boolean;
                voicemail_greeting?: {
                    id?: string;
                    name?: string;
                };
                voicemail_leaving_instruction?: {
                    id?: string;
                    name?: string;
                };
                message_greeting?: {
                    id?: string;
                    name?: string;
                };
                require_press_1_before_connecting?: boolean;
                overflow_play_callee_voicemail_greeting?: boolean;
                play_callee_voicemail_greeting?: boolean;
                busy_play_callee_voicemail_greeting?: boolean;
            };
            busy_routing?: {
                action?: number;
                forward_to?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "autoReceptionist" | "callQueue" | "commonArea";
                    id?: string;
                    phone_number?: string;
                    description?: string;
                    voicemail_greeting?: {
                        id?: string;
                        name?: string;
                    };
                };
                operator?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "commonArea" | "sharedLineGroup" | "callQueue";
                    id?: string;
                };
                connect_to_operator?: boolean;
                allow_callers_check_voicemail?: boolean;
                voicemail_greeting?: {
                    id?: string;
                    name?: string;
                };
                voicemail_leaving_instruction?: {
                    id?: string;
                    name?: string;
                };
                message_greeting?: {
                    id?: string;
                    name?: string;
                };
                require_press_1_before_connecting?: boolean;
                overflow_play_callee_voicemail_greeting?: boolean;
                play_callee_voicemail_greeting?: boolean;
                busy_play_callee_voicemail_greeting?: boolean;
            };
            type?: 1 | 2;
            wrap_up_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60 | 120 | 180 | 240 | 300;
        };
        sub_setting_type?: "call_forwarding" | "custom_hours" | "call_handling";
    }[];
    closed_hours?: {
        settings?: {
            allow_callers_check_voicemail?: boolean;
            call_forwarding_settings?: {
                description?: string;
                enable?: boolean;
                id?: string;
                phone_number?: string;
                external_contact?: {
                    name?: string;
                    email?: string;
                    external_contact_id?: string;
                    phone_numbers?: string[];
                };
            }[];
            call_not_answer_action?: 1 | 2 | 4 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
            connect_to_operator?: boolean;
            max_wait_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
            require_press_1_before_connecting?: boolean;
            ring_mode?: "simultaneous" | "sequential";
            routing?: {
                action?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 14 | 15 | 18 | 19;
                forward_to?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "autoReceptionist" | "callQueue" | "commonArea";
                    id?: string;
                    phone_number?: string;
                    description?: string;
                    voicemail_greeting?: {
                        id?: string;
                        name?: string;
                    };
                    zcc_phone_number?: string;
                    zcc_phone_number_display_name?: string;
                    partner_contact_center_id?: string;
                    pcc_phone_number_display_name?: string;
                    teams_app_id?: string;
                    teams_voice_app_name?: string;
                };
                operator?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "commonArea" | "sharedLineGroup" | "callQueue";
                    id?: string;
                };
                connect_to_operator?: boolean;
                allow_callers_check_voicemail?: boolean;
                voicemail_greeting?: {
                    id?: string;
                    name?: string;
                };
                voicemail_leaving_instruction?: {
                    id?: string;
                    name?: string;
                };
                message_greeting?: {
                    id?: string;
                    name?: string;
                };
                require_press_1_before_connecting?: boolean;
                overflow_play_callee_voicemail_greeting?: boolean;
                play_callee_voicemail_greeting?: boolean;
                busy_play_callee_voicemail_greeting?: boolean;
            };
            busy_routing?: {
                action?: number;
                forward_to?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "autoReceptionist" | "callQueue" | "commonArea";
                    id?: string;
                    phone_number?: string;
                    description?: string;
                    voicemail_greeting?: {
                        id?: string;
                        name?: string;
                    };
                };
                operator?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: "user" | "commonArea" | "sharedLineGroup" | "callQueue";
                    id?: string;
                };
                connect_to_operator?: boolean;
                allow_callers_check_voicemail?: boolean;
                voicemail_greeting?: {
                    id?: string;
                    name?: string;
                };
                voicemail_leaving_instruction?: {
                    id?: string;
                    name?: string;
                };
                message_greeting?: {
                    id?: string;
                    name?: string;
                };
                require_press_1_before_connecting?: boolean;
                overflow_play_callee_voicemail_greeting?: boolean;
                play_callee_voicemail_greeting?: boolean;
                busy_play_callee_voicemail_greeting?: boolean;
            };
        };
        sub_setting_type?: "call_forwarding" | "call_handling";
    }[];
    holiday_hours?: {
        details?: {
            settings?: {
                allow_callers_check_voicemail?: boolean;
                call_forwarding_settings?: {
                    description?: string;
                    enable?: boolean;
                    id?: string;
                    phone_number?: string;
                    external_contact?: {
                        name?: string;
                        email?: string;
                        external_contact_id?: string;
                        phone_numbers?: string[];
                    };
                }[];
                call_not_answer_action?: 1 | 2 | 4 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
                connect_to_operator?: boolean;
                from?: string;
                max_wait_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
                name?: string;
                require_press_1_before_connecting?: boolean;
                ring_mode?: "simultaneous" | "sequential";
                routing?: {
                    action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: "user" | "autoReceptionist" | "callQueue" | "commonArea";
                        id?: string;
                        phone_number?: string;
                        description?: string;
                        voicemail_greeting?: object;
                    };
                    operator?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: "user" | "commonArea" | "sharedLineGroup" | "callQueue";
                        id?: string;
                    };
                    connect_to_operator?: boolean;
                    allow_callers_check_voicemail?: boolean;
                    voicemail_greeting?: {
                        id?: string;
                        name?: string;
                    };
                    require_press_1_before_connecting?: boolean;
                    overflow_play_callee_voicemail_greeting?: boolean;
                    play_callee_voicemail_greeting?: boolean;
                    busy_play_callee_voicemail_greeting?: boolean;
                };
                to?: string;
            };
            sub_setting_type?: "call_forwarding" | "call_handling" | "holiday";
        }[];
        holiday_id?: string;
    }[];
};
type CallHandlingAddCallHandlingSettingPathParams = {
    extensionId: string;
    settingType: "business_hours" | "closed_hours" | "holiday_hours";
};
type CallHandlingAddCallHandlingSettingRequestBody = {
    settings?: {
        holiday_id?: string;
        description?: string;
        phone_number?: string;
    };
    sub_setting_type?: "call_forwarding";
} | {
    settings?: {
        name?: string;
        from?: string;
        to?: string;
    };
    sub_setting_type?: "holiday";
};
type CallHandlingAddCallHandlingSettingResponse = {
    call_forwarding_id?: string;
} | {
    holiday_id?: string;
};
type CallHandlingDeleteCallHandlingSettingPathParams = {
    extensionId: string;
    settingType: "business_hours" | "closed_hours" | "holiday_hours";
};
type CallHandlingDeleteCallHandlingSettingQueryParams = {
    call_forwarding_id?: string;
    holiday_id?: string;
};
type CallHandlingUpdateCallHandlingSettingPathParams = {
    extensionId: string;
    settingType: "business_hours" | "closed_hours" | "holiday_hours";
};
type CallHandlingUpdateCallHandlingSettingRequestBody = {
    settings?: {
        call_forwarding_settings?: {
            description?: string;
            enable?: boolean;
            id?: string;
            phone_number?: string;
            external_contact?: {
                external_contact_id?: string;
            };
        }[];
        require_press_1_before_connecting?: boolean;
    };
    sub_setting_type?: "call_forwarding";
} | {
    settings?: {
        from?: string;
        holiday_id?: string;
        name?: string;
        to?: string;
    };
    sub_setting_type?: "holiday";
} | {
    settings?: {
        allow_members_to_reset?: boolean;
        custom_hours_settings?: {
            from?: string;
            to?: string;
            type?: 0 | 1 | 2;
            weekday?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
        }[];
        type?: 1 | 2;
    };
    sub_setting_type?: "custom_hours";
} | {
    settings?: {
        allow_callers_check_voicemail?: boolean;
        allow_members_to_reset?: boolean;
        audio_while_connecting_id?: string;
        call_distribution?: {
            handle_multiple_calls?: boolean;
            ring_duration?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
            ring_mode?: "simultaneous" | "sequential" | "rotating" | "longest_idle";
            skip_offline_device_phone_number?: boolean;
        };
        call_not_answer_action?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 14 | 15 | 18 | 19;
        busy_on_another_call_action?: 1 | 2 | 4 | 6 | 7 | 8 | 9 | 10 | 12 | 21 | 22;
        busy_require_press_1_before_connecting?: boolean;
        un_answered_require_press_1_before_connecting?: boolean;
        overflow_play_callee_voicemail_greeting?: boolean;
        play_callee_voicemail_greeting?: boolean;
        busy_play_callee_voicemail_greeting?: boolean;
        phone_number?: string;
        description?: string;
        busy_phone_number?: string;
        busy_description?: string;
        connect_to_operator?: boolean;
        forward_to_extension_id?: string;
        busy_forward_to_extension_id?: string;
        greeting_prompt_id?: string;
        max_call_in_queue?: number;
        max_wait_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60 | 120 | 180 | 240 | 300 | 600 | 900 | 1200 | 1500 | 1800;
        music_on_hold_id?: string;
        operator_extension_id?: string;
        receive_call?: boolean;
        ring_mode?: "simultaneous" | "sequential";
        voicemail_greeting_id?: string;
        voicemail_leaving_instruction_id?: string;
        message_greeting_id?: string;
        forward_to_zcc_phone_number?: string;
        forward_to_partner_contact_center_id?: string;
        forward_to_teams_id?: string;
        wrap_up_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60 | 120 | 180 | 240 | 300;
    };
    sub_setting_type?: "call_handling";
};
type CallLogsGetAccountsCallHistoryQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    next_page_token?: string;
    keyword?: string;
    directions?: ("inbound" | "outbound")[];
    connect_types?: ("internal" | "external")[];
    number_types?: ("zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator")[];
    call_types?: ("general" | "emergency")[];
    extension_types?: ("user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact")[];
    call_results?: ("answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable")[];
    group_ids?: string[];
    site_ids?: string[];
    department?: string;
    cost_center?: string;
    time_type?: "start_time" | "end_time";
    recording_status?: "recorded" | "non_recorded";
    with_voicemail?: boolean;
};
type CallLogsGetAccountsCallHistoryResponse = {
    call_logs?: {
        id?: string;
        call_id?: string;
        direction?: "inbound" | "outbound";
        international?: boolean;
        start_time?: string;
        answer_time?: string;
        end_time?: string;
        duration?: number;
        connect_type?: "internal" | "external";
        sbc_id?: string;
        sbc_name?: string;
        sip_group_id?: string;
        sip_group_name?: string;
        call_type?: "general" | "emergency";
        call_result?: "answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable";
        hide_caller_id?: boolean;
        end_to_end?: boolean;
        caller_ext_id?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_name?: string;
        caller_email?: string;
        caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        caller_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator";
        caller_device_type?: string;
        caller_country_iso_code?: string;
        caller_country_code?: string;
        callee_ext_id?: string;
        callee_did_number?: string;
        callee_ext_number?: string;
        callee_name?: string;
        callee_email?: string;
        callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        callee_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator";
        callee_device_type?: string;
        callee_country_iso_code?: string;
        callee_country_code?: string;
        department?: string;
        cost_center?: string;
        site_id?: string;
        group_id?: string;
        site_name?: string;
        spam?: string;
        recording_status?: "recorded" | "non_recorded";
    }[];
    from?: string;
    to?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
    next_page_token?: string;
};
type CallLogsGetCallPathPathParams = {
    callLogId: string;
};
type CallLogsGetCallPathResponse = {
    id?: string;
    call_id?: string;
    connect_type?: "internal" | "external";
    call_type?: "general" | "emergency";
    direction?: "inbound" | "outbound";
    international?: boolean;
    hide_caller_id?: boolean;
    end_to_end?: boolean;
    caller_ext_id?: string;
    caller_name?: string;
    caller_did_number?: string;
    caller_ext_number?: string;
    caller_email?: string;
    caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
    callee_ext_id?: string;
    callee_name?: string;
    callee_email?: string;
    callee_did_number?: string;
    callee_ext_number?: string;
    callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
    department?: string;
    cost_center?: string;
    site_id?: string;
    group_id?: string;
    site_name?: string;
    start_time?: string;
    answer_time?: string;
    end_time?: string;
    call_path?: {
        id?: string;
        call_id?: string;
        connect_type?: "internal" | "external";
        call_type?: "general" | "emergency";
        direction?: "inbound" | "outbound";
        hide_caller_id?: boolean;
        end_to_end?: boolean;
        caller_ext_id?: string;
        caller_name?: string;
        caller_email?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        caller_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zra_phone_number";
        caller_device_type?: string;
        caller_country_iso_code?: string;
        caller_country_code?: string;
        callee_ext_id?: string;
        callee_name?: string;
        callee_did_number?: string;
        callee_ext_number?: string;
        callee_email?: string;
        callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        callee_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zra_phone_number";
        callee_device_type?: string;
        callee_country_iso_code?: string;
        callee_country_code?: string;
        client_code?: string;
        department?: string;
        cost_center?: string;
        site_id?: string;
        group_id?: string;
        site_name?: string;
        start_time?: string;
        answer_time?: string;
        end_time?: string;
        event?: "incoming" | "transfer_from_zoom_contact_center" | "shared_line_incoming" | "outgoing" | "call_me_on" | "outgoing_to_zoom_contact_center" | "warm_transfer" | "forward" | "ring_to_member" | "overflow" | "direct_transfer" | "barge" | "monitor" | "whisper" | "listen" | "takeover" | "conference_barge" | "park" | "timeout" | "park_pick_up" | "merge" | "shared";
        result?: "answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable";
        result_reason?: "answered_by_other" | "pickup_by_other" | "call_out_by_other";
        device_private_ip?: string;
        device_public_ip?: string;
        operator_ext_number?: string;
        operator_ext_id?: string;
        operator_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        operator_name?: string;
        press_key?: string;
        segment?: number;
        node?: number;
        is_node?: number;
        recording_id?: string;
        recording_type?: "automatic" | "ad-hoc";
        hold_time?: number;
        waiting_time?: number;
        voicemail_id?: string;
    }[];
};
type CallLogsAddClientCodeToCallHistoryPathParams = {
    callLogId: string;
};
type CallLogsAddClientCodeToCallHistoryRequestBody = {
    client_code: string;
};
type CallLogsGetCallHistoryDetailPathParams = {
    callHistoryId: string;
};
type CallLogsGetCallHistoryDetailResponse = {
    id?: string;
    call_path_id?: string;
    call_id?: string;
    connect_type?: "internal" | "external";
    call_type?: "general" | "emergency";
    direction?: "inbound" | "outbound";
    hide_caller_id?: boolean;
    end_to_end?: boolean;
    caller_ext_id?: string;
    caller_name?: string;
    caller_email?: string;
    caller_did_number?: string;
    caller_ext_number?: string;
    caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
    caller_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zra_phone_number";
    caller_device_type?: string;
    caller_country_iso_code?: string;
    caller_country_code?: string;
    callee_ext_id?: string;
    callee_name?: string;
    callee_did_number?: string;
    callee_ext_number?: string;
    callee_email?: string;
    callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
    callee_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zra_phone_number";
    callee_device_type?: string;
    callee_country_iso_code?: string;
    callee_country_code?: string;
    client_code?: string;
    department?: string;
    cost_center?: string;
    site_id?: string;
    group_id?: string;
    site_name?: string;
    start_time?: string;
    answer_time?: string;
    end_time?: string;
    event?: "incoming" | "transfer_from_zoom_contact_center" | "shared_line_incoming" | "outgoing" | "call_me_on" | "outgoing_to_zoom_contact_center" | "warm_transfer" | "forward" | "ring_to_member" | "overflow" | "direct_transfer" | "barge" | "monitor" | "whisper" | "listen" | "takeover" | "conference_barge" | "park" | "timeout" | "park_pick_up" | "merge" | "shared";
    result?: "answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable";
    result_reason?: "answered_by_other" | "pickup_by_other" | "call_out_by_other";
    device_private_ip?: string;
    device_public_ip?: string;
    operator_ext_number?: string;
    operator_ext_id?: string;
    operator_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
    operator_name?: string;
    press_key?: string;
    segment?: number;
    node?: number;
    is_node?: number;
    recording_id?: string;
    recording_type?: "ad-hoc" | "automatic";
    hold_time?: number;
    waiting_time?: number;
    voicemail_id?: string;
};
type CallLogsGetAccountsCallLogsQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    type?: string;
    next_page_token?: string;
    path?: string;
    time_type?: "startTime" | "endTime";
    site_id?: string;
    charged_call_logs?: boolean;
};
type CallLogsGetAccountsCallLogsResponse = {
    call_logs?: {
        answer_start_time?: string;
        call_end_time?: string;
        call_id?: string;
        call_type?: "voip" | "pstn" | "tollfree" | "international" | "contactCenter";
        callee_country_code?: string;
        callee_country_iso_code?: string;
        callee_did_number?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: 1 | 2 | 3;
        callee_number_source?: "internal" | "external" | "byop";
        caller_country_code?: string;
        caller_country_iso_code?: string;
        caller_did_number?: string;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        caller_number_source?: "internal" | "external" | "byop";
        caller_billing_reference_id?: string;
        charge?: string;
        client_code?: string;
        date_time?: string;
        device_private_ip?: string;
        device_public_ip?: string;
        direction?: string;
        duration?: number;
        id?: string;
        owner?: {
            extension_number?: number;
            id?: string;
            name?: string;
            type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "sharedLineGroup";
        };
        path?: string;
        rate?: string;
        recording_id?: string;
        recording_type?: "OnDemand" | "Automatic";
        result?: string;
        site?: {
            id?: string;
            name?: string;
        };
        user_id?: string;
        hold_time?: number;
        waiting_time?: number;
        department?: string;
        cost_center?: string;
    }[];
    from?: string;
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    to?: string;
    total_records?: number;
};
type CallLogsGetCallLogDetailsPathParams = {
    callLogId: string;
};
type CallLogsGetCallLogDetailsResponse = {
    call_id?: string;
    call_type?: "voip" | "pstn" | "tollfree" | "international" | "contactCenter";
    callee_country_code?: string;
    callee_country_iso_code?: string;
    callee_did_number?: string;
    callee_name?: string;
    callee_number?: string;
    callee_number_type?: 1 | 2 | 3;
    callee_number_source?: "internal" | "external" | "byop";
    callee_status?: "inactive" | "deleted";
    callee_deleted_time?: string;
    caller_country_code?: string;
    caller_country_iso_code?: string;
    caller_did_number?: string;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: 1 | 2;
    caller_number_source?: "internal" | "external" | "byop";
    caller_billing_reference_id?: string;
    caller_status?: "inactive" | "deleted";
    caller_deleted_time?: string;
    date_time?: string;
    device_private_ip?: string;
    device_public_ip?: string;
    direction?: "inbound" | "outbound";
    duration?: number;
    has_recording?: boolean;
    has_voicemail?: boolean;
    id?: string;
    log_details?: {
        date_time?: string;
        hold_time?: number;
        device_private_ip?: string;
        device_public_ip?: string;
        duration?: number;
        forward_to?: {
            extension_number?: string;
            id?: string;
            name?: string;
            type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            extension_status?: "inactive" | "deleted";
            extension_deleted_time?: string;
        };
        id?: string;
        path?: string;
        result?: string;
        site?: {
            id?: string;
            name?: string;
        };
    }[];
    path?: string;
    result?: string;
    department?: string;
    cost_center?: string;
};
type CallLogsAddClientCodeToCallLogPathParams = {
    callLogId: string;
};
type CallLogsAddClientCodeToCallLogRequestBody = {
    client_code: string;
};
type CallLogsGetUserAICallSummaryDetailPathParams = {
    userId: string;
    aiCallSummaryId: string;
};
type CallLogsGetUserAICallSummaryDetailResponse = {
    ai_call_summary_id?: string;
    account_id?: string;
    call_id?: string;
    user_id?: string;
    call_summary_rate?: "thumb_up" | "thumb_down";
    transcript_language?: string;
    call_summary?: string;
    next_steps?: string;
    detailed_summary?: string;
    created_time?: string;
    modified_time?: string;
    edited?: boolean;
};
type CallLogsGetUsersCallHistoryPathParams = {
    userId: string;
};
type CallLogsGetUsersCallHistoryQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    next_page_token?: string;
    keyword?: string;
    directions?: ("inbound" | "outbound")[];
    connect_types?: ("internal" | "external")[];
    number_types?: ("zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator")[];
    call_types?: ("general" | "emergency")[];
    extension_types?: ("user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact")[];
    call_results?: ("answered" | "connected" | "voicemail" | "hang_up" | "no_answer" | "invalid_operation" | "abandoned" | "blocked" | "service_unavailable")[];
    group_ids?: string[];
    site_ids?: string[];
    department?: string;
    cost_center?: string;
    time_type?: "start_time" | "end_time";
    recording_status?: "recorded" | "non_recorded";
    with_voicemail?: boolean;
};
type CallLogsGetUsersCallHistoryResponse = {
    call_logs?: {
        id?: string;
        call_path_id?: string;
        call_id?: string;
        group_id?: string;
        connect_type?: "internal" | "external";
        call_type?: "general" | "emergency";
        direction?: "inbound" | "outbound";
        hide_caller_id?: boolean;
        end_to_end?: boolean;
        caller_ext_id?: string;
        caller_name?: string;
        caller_email?: string;
        caller_employee_id?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        caller_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator";
        caller_device_private_ip?: string;
        caller_device_public_ip?: string;
        caller_device_type?: string;
        caller_country_iso_code?: string;
        caller_country_code?: string;
        caller_site_id?: string;
        caller_department?: string;
        caller_cost_center?: string;
        callee_ext_id?: string;
        callee_name?: string;
        callee_did_number?: string;
        callee_ext_number?: string;
        callee_email?: string;
        callee_employee_id?: string;
        callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        callee_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator";
        callee_device_private_ip?: string;
        callee_device_public_ip?: string;
        callee_device_type?: string;
        callee_country_iso_code?: string;
        callee_country_code?: string;
        callee_site_id?: string;
        callee_department?: string;
        callee_cost_center?: string;
        start_time?: string;
        answer_time?: string;
        end_time?: string;
        event?: "incoming" | "transfer_from_zoom_contact_center" | "shared_line_incoming" | "outgoing" | "call_me_on" | "outgoing_to_zoom_contact_center" | "warm_transfer" | "forward" | "ring_to_member" | "overflow" | "direct_transfer" | "barge" | "monitor" | "whisper" | "listen" | "takeover" | "conference_barge" | "park" | "timeout" | "park_pick_up" | "merge" | "shared";
        result?: "answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable";
        result_reason?: "answered_by_other" | "pickup_by_other" | "call_out_by_other";
        operator_ext_number?: string;
        operator_ext_id?: string;
        operator_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        operator_name?: string;
        recording_id?: string;
        recording_type?: "ad-hoc" | "automatic";
        voicemail_id?: string;
        talk_time?: number;
        hold_time?: number;
        wait_time?: number;
    }[];
    from?: string;
    to?: string;
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
};
type CallLogsSyncUsersCallHistoryPathParams = {
    userId: string;
};
type CallLogsSyncUsersCallHistoryQueryParams = {
    sync_type?: string;
    count?: number;
    sync_token?: string;
};
type CallLogsSyncUsersCallHistoryResponse = {
    call_logs?: {
        id?: string;
        call_path_id?: string;
        call_id?: string;
        group_id?: string;
        connect_type?: "internal" | "external";
        call_type?: "general" | "emergency";
        direction?: "inbound" | "outbound";
        hide_caller_id?: boolean;
        end_to_end?: boolean;
        caller_ext_id?: string;
        caller_name?: string;
        caller_email?: string;
        caller_employee_id?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        caller_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator";
        caller_device_private_ip?: string;
        caller_device_public_ip?: string;
        caller_device_type?: string;
        caller_country_iso_code?: string;
        caller_country_code?: string;
        caller_site_id?: string;
        caller_department?: string;
        caller_cost_center?: string;
        callee_ext_id?: string;
        callee_name?: string;
        callee_did_number?: string;
        callee_ext_number?: string;
        callee_email?: string;
        callee_employee_id?: string;
        callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        callee_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number" | "zoom_revenue_accelerator";
        callee_device_private_ip?: string;
        callee_device_public_ip?: string;
        callee_device_type?: string;
        callee_country_iso_code?: string;
        callee_country_code?: string;
        callee_site_id?: string;
        callee_department?: string;
        callee_cost_center?: string;
        start_time?: string;
        answer_time?: string;
        end_time?: string;
        event?: "incoming" | "transfer_from_zoom_contact_center" | "shared_line_incoming" | "outgoing" | "call_me_on" | "outgoing_to_zoom_contact_center" | "warm_transfer" | "forward" | "ring_to_member" | "overflow" | "direct_transfer" | "barge" | "monitor" | "whisper" | "listen" | "takeover" | "conference_barge" | "park" | "timeout" | "park_pick_up" | "merge" | "shared";
        result?: "answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable";
        result_reason?: "answered_by_other" | "pickup_by_other" | "call_out_by_other";
        operator_ext_number?: string;
        operator_ext_id?: string;
        operator_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
        operator_name?: string;
        recording_id?: string;
        recording_type?: "ad-hoc" | "automatic";
        voicemail_id?: string;
        talk_time?: number;
        hold_time?: number;
        wait_time?: number;
        ai_call_summary_id?: string;
    }[];
    sync_token?: string;
};
type CallLogsDeleteUsersCallHistoryPathParams = {
    userId: string;
    callLogId: string;
};
type CallLogsGetUsersCallLogsPathParams = {
    userId: string;
};
type CallLogsGetUsersCallLogsQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    type?: "all" | "missed";
    next_page_token?: string;
    phone_number?: string;
    time_type?: "startTime" | "endTime";
};
type CallLogsGetUsersCallLogsResponse = {
    call_logs?: {
        accepted_by?: {
            extension_number?: string;
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        answer_start_time?: string;
        call_end_time?: string;
        call_id?: string;
        callee_country_code?: string;
        callee_country_iso_code?: string;
        callee_did_number?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: 1 | 2 | 3;
        callee_number_source?: "internal" | "external" | "byop";
        caller_country_code?: string;
        caller_country_iso_code?: string;
        caller_did_number?: string;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        caller_number_source?: "internal" | "external" | "byop";
        caller_billing_reference_id?: string;
        charge?: string;
        client_code?: string;
        date_time?: string;
        direction?: string;
        duration?: number;
        forwarded_by?: {
            extension_number?: string;
            extension_type?: "user" | "callQueue" | "commonAreaPhone" | "autoReceptionist" | "sharedLineGroup";
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        forwarded_to?: {
            extension_number?: string;
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        has_recording?: boolean;
        has_voicemail?: boolean;
        id?: string;
        outgoing_by?: {
            extension_number?: string;
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        path?: string;
        rate?: string;
        recording_type?: "OnDemand" | "Automatic";
        result?: string;
        site?: {
            id?: string;
            name?: string;
        };
        user_id?: string;
        hold_time?: number;
        waiting_time?: number;
        department?: string;
        cost_center?: string;
    }[];
    from?: string;
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    to?: string;
    total_records?: number;
};
type CallLogsSyncUsersCallLogsPathParams = {
    userId: string;
};
type CallLogsSyncUsersCallLogsQueryParams = {
    sync_type?: "FSync" | "ISync" | "BSync";
    count?: number;
    sync_token?: string;
};
type CallLogsSyncUsersCallLogsResponse = {
    call_logs?: {
        accepted_by?: {
            extension_number?: string;
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        answer_start_time?: string;
        call_end_time?: string;
        call_id?: string;
        callee_user_id?: string;
        callee_country_code?: string;
        callee_country_iso_code?: string;
        callee_did_number?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: 1 | 2 | 3;
        callee_number_source?: "internal" | "external" | "byop";
        caller_user_id?: string;
        caller_country_code?: string;
        caller_country_iso_code?: string;
        caller_did_number?: string;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        caller_number_source?: "internal" | "external" | "byop";
        caller_billing_reference_id?: string;
        charge?: string;
        client_code?: string;
        date_time?: string;
        direction?: string;
        duration?: number;
        forwarded_by?: {
            extension_number?: string;
            extension_type?: "user" | "callQueue" | "commonAreaPhone" | "autoReceptionist" | "sharedLineGroup";
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        forwarded_to?: {
            extension_number?: string;
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        has_recording?: boolean;
        has_voicemail?: boolean;
        id?: string;
        outgoing_by?: {
            extension_number?: string;
            location?: string;
            name?: string;
            number_type?: number;
            phone_number?: string;
        };
        path?: string;
        rate?: string;
        recording_type?: "OnDemand" | "Automatic";
        result?: string;
        site?: {
            id?: string;
            name?: string;
        };
        user_id?: string;
        hold_time?: number;
        waiting_time?: number;
    }[];
    sync_token?: string;
};
type CallLogsDeleteUsersCallLogPathParams = {
    userId: string;
    callLogId: string;
};
type CallQueuesListCallQueueAnalyticsQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    next_page_token?: string;
    site_id?: string;
    call_queue_ext_ids?: string[];
    department?: string;
    cost_center?: string;
};
type CallQueuesListCallQueueAnalyticsResponse = {
    call_queues?: {
        call_queue_id?: string;
        call_queue_name?: string;
        call_queue_ext_id?: string;
        inbound_calls?: number;
        completed_calls?: number;
        abandoned_calls?: number;
        overflowed_calls?: number;
        avg_handle_time?: number;
        avg_wrap_up_time?: number;
        avg_in_queue_wait_time?: number;
        max_in_queue_wait_time?: number;
        outbound_calls?: number;
        outbound_connected_calls?: number;
        outbound_unconnected_calls?: number;
        site_name?: string;
        site_id?: string;
    }[];
    from?: string;
    to?: string;
    page_size?: number;
    next_page_token?: string;
};
type CallQueuesListCallQueuesQueryParams = {
    next_page_token?: string;
    page_size?: number;
    site_id?: string;
    cost_center?: string;
    department?: string;
};
type CallQueuesListCallQueuesResponse = {
    call_queues?: {
        extension_id?: string;
        extension_number?: number;
        id?: string;
        name?: string;
        phone_numbers?: {
            id?: string;
            number?: string;
            source?: "internal" | "external";
        }[];
        site?: {
            id?: string;
            name?: string;
        };
        status?: "active" | "inactive";
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type CallQueuesCreateCallQueueRequestBody = {
    cost_center?: string;
    department?: string;
    description?: string;
    extension_number?: number;
    members?: {
        common_area_ids?: string[];
        users?: {
            email?: string;
            id?: string;
        }[];
    };
    name: string;
    site_id: string;
};
type CallQueuesCreateCallQueueResponse = {
    extension_number?: number;
    id?: string;
    name?: string;
    status?: string;
};
type CallQueuesGetCallQueueDetailsPathParams = {
    callQueueId: string;
};
type CallQueuesGetCallQueueDetailsResponse = {
    cost_center?: string;
    department?: string;
    extension_id?: string;
    extension_number?: number;
    id?: string;
    members?: {
        users?: {
            id?: string;
            level?: "manager" | "user";
            name?: string;
            receive_call?: boolean;
            extension_id?: string;
        }[];
        common_areas?: {
            id?: string;
            name?: string;
            extension_id?: string;
        }[];
    };
    name?: string;
    phone_numbers?: {
        id?: string;
        number?: string;
        source?: "internal" | "external";
    }[];
    site?: {
        id?: string;
        name?: string;
    };
    status?: "active" | "inactive";
    policy?: {
        voicemail_access_members?: ({
            access_user_id?: string;
            access_user_type?: "commonArea" | "user";
            allow_download?: boolean;
            allow_delete?: boolean;
            allow_sharing?: boolean;
        } & {
            shared_id?: string;
        })[];
    };
    timezone?: string;
    audio_prompt_language?: "en-US" | "en-GB" | "es-US" | "fr-CA" | "da-DK" | "de-DE" | "es-ES" | "fr-FR" | "it-IT" | "nl-NL" | "pt-PT" | "ja" | "ko-KR" | "pt-BR" | "zh-CN";
    recording_storage_location?: "US" | "AU" | "CA" | "DE" | "IN" | "JP" | "SG" | "BR" | "CN" | "MX";
    own_storage_name?: string;
};
type CallQueuesDeleteCallQueuePathParams = {
    callQueueId: string;
};
type CallQueuesUpdateCallQueueDetailsPathParams = {
    callQueueId: string;
};
type CallQueuesUpdateCallQueueDetailsRequestBody = {
    cost_center?: string;
    department?: string;
    description?: string;
    extension_number?: number;
    name?: string;
    site_id?: string;
    status?: "active" | "inactive";
    timezone?: string;
    audio_prompt_language?: "en-US" | "en-GB" | "es-US" | "fr-CA" | "da-DK" | "de-DE" | "es-ES" | "fr-FR" | "it-IT" | "nl-NL" | "pt-PT" | "ja" | "ko-KR" | "pt-BR" | "zh-CN";
    recording_storage_location?: "US" | "AU" | "CA" | "DE" | "IN" | "JP" | "SG" | "BR" | "CN" | "MX";
};
type CallQueuesListCallQueueMembersPathParams = {
    callQueueId: string;
};
type CallQueuesListCallQueueMembersResponse = {
    call_queue_members?: {
        id?: string;
        level?: "commonArea" | "user";
        name?: string;
        receive_call?: boolean;
        extension_id?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type CallQueuesAddMembersToCallQueuePathParams = {
    callQueueId: string;
};
type CallQueuesAddMembersToCallQueueRequestBody = {
    members?: {
        common_area_ids?: string[];
        users?: {
            email?: string;
            id?: string;
        }[];
    };
};
type CallQueuesUnassignAllMembersPathParams = {
    callQueueId: string;
};
type CallQueuesUnassignMemberPathParams = {
    callQueueId: string;
    memberId: string;
};
type CallQueuesAssignNumbersToCallQueuePathParams = {
    callQueueId: string;
};
type CallQueuesAssignNumbersToCallQueueRequestBody = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type CallQueuesUnassignAllPhoneNumbersPathParams = {
    callQueueId: string;
};
type CallQueuesUnassignPhoneNumberPathParams = {
    callQueueId: string;
    phoneNumberId: string;
};
type CallQueuesAddPolicySubsettingToCallQueuePathParams = {
    callQueueId: string;
    policyType: string;
};
type CallQueuesAddPolicySubsettingToCallQueueRequestBody = {
    voicemail_access_members?: {
        access_user_id?: string;
        access_user_type?: "commonArea" | "user";
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_sharing?: boolean;
    }[];
};
type CallQueuesAddPolicySubsettingToCallQueueResponse = {
    voicemail_access_members?: ({
        access_user_id?: string;
        access_user_type?: "commonArea" | "user";
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_sharing?: boolean;
    } & {
        shared_id?: string;
    })[];
};
type CallQueuesDeleteCQPolicySettingPathParams = {
    callQueueId: string;
    policyType: string;
};
type CallQueuesDeleteCQPolicySettingQueryParams = {
    shared_ids: string[];
};
type CallQueuesUpdateCallQueuesPolicySubsettingPathParams = {
    callQueueId: string;
    policyType: string;
};
type CallQueuesUpdateCallQueuesPolicySubsettingRequestBody = {
    voicemail_access_members?: ({
        access_user_id?: string;
        access_user_type?: "commonArea" | "user";
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_sharing?: boolean;
    } & {
        shared_id?: string;
    })[];
};
type CallQueuesGetCallQueueRecordingsPathParams = {
    callQueueId: string;
};
type CallQueuesGetCallQueueRecordingsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
};
type CallQueuesGetCallQueueRecordingsResponse = {
    from?: string;
    next_page_token?: string;
    page_size?: number;
    recordings?: {
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: "1" | "2" | "3";
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        date_time?: string;
        direction?: string;
        download_url?: string;
        duration?: number;
        id?: string;
    }[];
    to?: string;
    total_records?: number;
};
type CarrierResellerListPhoneNumbersQueryParams = {
    page_size?: number;
    next_page_token?: string;
    assigned_status?: "assigned" | "unassigned" | "returned";
    sub_account_id?: string;
    keyword?: string;
};
type CarrierResellerListPhoneNumbersResponse = {
    carrier_reseller_numbers?: {
        assigned_status?: "assigned" | "unassigned" | "returned";
        carrier_code?: number;
        country_iso_code?: string;
        phone_number?: string;
        status?: "inactive" | "active";
        sub_account_id?: string;
        sub_account_name?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type CarrierResellerCreatePhoneNumbersRequestBody = {
    phone_number?: string;
    status?: "active" | "inactive";
}[];
type CarrierResellerActivatePhoneNumbersRequestBody = string[];
type CarrierResellerDeletePhoneNumberPathParams = {
    number: string;
};
type CommonAreasListCommonAreasQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type CommonAreasListCommonAreasResponse = {
    common_areas?: {
        calling_plans?: {
            name?: string;
            type?: number;
            billing_account_id?: string;
            billing_account_name?: string;
            billing_subscription_id?: string;
            billing_subscription_name?: string;
        }[];
        display_name?: string;
        extension_number?: number;
        id?: string;
        phone_numbers?: {
            display_name?: string;
            id?: string;
            number?: string;
            source?: "internal" | "external";
        }[];
        site?: {
            id?: string;
            name?: string;
        };
        status?: "online" | "offline";
        desk_phones?: {
            id?: string;
            display_name?: string;
            device_type?: string;
            status?: "online" | "offline";
        }[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type CommonAreasAddCommonAreaRequestBody = {
    calling_plans?: {
        type?: number;
        billing_subscription_id?: string;
    }[];
    country_iso_code?: string;
    display_name: string;
    extension_number?: number;
    site_id?: string;
    timezone?: string;
    template_id?: string;
};
type CommonAreasAddCommonAreaResponse = {
    display_name?: string;
    id?: string;
};
type CommonAreasGenerateActivationCodesForCommonAreasRequestBody = {
    common_area_ids: string[];
};
type CommonAreasGenerateActivationCodesForCommonAreasResponse = {
    common_areas_activation_codes?: {
        common_area_id?: string;
        display_name?: string;
        extension_number?: number;
        activation_code?: string;
        activation_code_expiration?: string;
    }[];
};
type CommonAreasListActivationCodesQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type CommonAreasListActivationCodesResponse = {
    common_areas_activation_codes?: {
        common_area_id?: string;
        display_name?: string;
        extension_number?: number;
        activation_code?: string;
        activation_code_expiration?: string;
        status?: "used" | "not_used";
        site?: {
            site_id?: string;
            name?: string;
        };
    }[];
    next_page_token?: string;
    page_size?: number;
};
type CommonAreasApplyTemplateToCommonAreasPathParams = {
    templateId: string;
};
type CommonAreasApplyTemplateToCommonAreasRequestBody = {
    common_area_ids?: string[];
};
type CommonAreasGetCommonAreaDetailsPathParams = {
    commonAreaId: string;
};
type CommonAreasGetCommonAreaDetailsResponse = {
    area_code?: string;
    calling_plans?: {
        name?: string;
        type?: number;
        billing_account_id?: string;
        billing_account_name?: string;
        billing_subscription_id?: string;
        billing_subscription_name?: string;
    }[];
    cost_center?: string;
    country?: {
        code?: string;
        country_code?: string;
        name?: string;
    };
    department?: string;
    display_name?: string;
    extension_number?: number;
    emergency_address?: {
        address_line1?: string;
        address_line2?: string;
        city?: string;
        country?: string;
        id?: string;
        state_code?: string;
        status?: 1 | 2 | 3 | 4 | 5 | 6;
        zip?: string;
    };
    id?: string;
    outbound_caller_ids?: {
        is_default?: boolean;
        name?: string;
        number?: string;
    }[];
    phone_numbers?: {
        display_name?: string;
        id?: string;
        number?: string;
        source?: "internal" | "external";
    }[];
    policy?: {
        international_calling?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "site";
            modified?: boolean;
        };
        outbound_calling?: {
            enable?: boolean;
            locked?: boolean;
            modified?: boolean;
        };
    };
    site?: {
        id?: string;
        name?: string;
    };
    status?: "online" | "offline";
};
type CommonAreasDeleteCommonAreaPathParams = {
    commonAreaId: string;
};
type CommonAreasUpdateCommonAreaPathParams = {
    commonAreaId: string;
};
type CommonAreasUpdateCommonAreaRequestBody = {
    area_code?: string;
    cost_center?: string;
    country_iso_code?: string;
    department?: string;
    display_name?: string;
    emergency_address_id?: string;
    extension_number?: number;
    outbound_caller_id?: string;
    policy?: {
        international_calling?: {
            enable?: boolean;
            reset?: boolean;
        };
    };
    site_id?: string;
    timezone?: string;
};
type CommonAreasAssignCallingPlansToCommonAreaPathParams = {
    commonAreaId: string;
};
type CommonAreasAssignCallingPlansToCommonAreaRequestBody = {
    calling_plans: {
        type: number;
        billing_account_id?: string;
        billing_subscription_id?: string;
    }[];
};
type CommonAreasAssignCallingPlansToCommonAreaResponse = {
    calling_plans?: {
        name?: string;
        type?: number;
        billing_account_id?: string;
        billing_account_name?: string;
    }[];
};
type CommonAreasUnassignCallingPlanFromCommonAreaPathParams = {
    commonAreaId: string;
    type: string;
};
type CommonAreasUnassignCallingPlanFromCommonAreaQueryParams = {
    billing_account_id?: string;
};
type CommonAreasAssignPhoneNumbersToCommonAreaPathParams = {
    commonAreaId: string;
};
type CommonAreasAssignPhoneNumbersToCommonAreaRequestBody = {
    phone_numbers: {
        id?: string;
        number?: string;
    }[];
};
type CommonAreasAssignPhoneNumbersToCommonAreaResponse = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type CommonAreasUnassignPhoneNumbersFromCommonAreaPathParams = {
    commonAreaId: string;
    phoneNumberId: string;
};
type CommonAreasUpdateCommonAreaPinCodePathParams = {
    commonAreaId: string;
};
type CommonAreasUpdateCommonAreaPinCodeRequestBody = {
    pin_code: string;
};
type CommonAreasGetCommonAreaSettingsPathParams = {
    commonAreaId: string;
};
type CommonAreasGetCommonAreaSettingsResponse = {
    desk_phones?: {
        id?: string;
        display_name?: string;
        device_type?: string;
        status?: "online" | "offline";
        mac_address?: string;
        hot_desking?: {
            status?: "unsupported" | "on" | "off";
        };
        private_ip?: string;
        public_ip?: string;
    }[];
};
type CommonAreasAddCommonAreaSettingPathParams = {
    commonAreaId: string;
    settingType: string;
};
type CommonAreasAddCommonAreaSettingRequestBody = {
    device_id?: string;
};
type CommonAreasAddCommonAreaSettingResponse = {
    desk_phones?: {
        id?: string;
        display_name?: string;
    }[];
};
type CommonAreasDeleteCommonAreaSettingPathParams = {
    commonAreaId: string;
    settingType: string;
};
type CommonAreasDeleteCommonAreaSettingQueryParams = {
    device_id: string;
};
type CommonAreasUpdateCommonAreaSettingPathParams = {
    commonAreaId: string;
    settingType: string;
};
type CommonAreasUpdateCommonAreaSettingRequestBody = {
    desk_phones?: {
        id?: string;
        hot_desking?: {
            status?: "on" | "off";
        };
    }[];
};
type DashboardListCallLogsQueryParams = {
    from?: string;
    to?: string;
    site_id?: string;
    quality_type?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListCallLogsResponse = {
    call_logs?: {
        call_id?: string;
        callee?: {
            codec?: string;
            device_private_ip?: string;
            device_public_ip?: string;
            device_type?: string;
            extension_number?: string;
            headset?: string;
            isp?: string;
            microphone?: string;
            phone_number?: string;
            site_id?: string;
        };
        caller?: {
            codec?: string;
            device_private_ip?: string;
            device_public_ip?: string;
            device_type?: string;
            extension_number?: string;
            headset?: string;
            isp?: string;
            microphone?: string;
            phone_number?: string;
            site_id?: string;
        };
        date_time?: string;
        direction?: string;
        duration?: number;
        mos?: string;
    }[];
    from?: string;
    next_page_token?: string;
    page_size?: number;
    to?: string;
    total_records?: number;
};
type DashboardGetCallQoSPathParams = {
    callId: string;
};
type DashboardGetCallQoSResponse = {
    call_id?: string;
    callee_qos?: {
        device_private_ip?: string;
        device_public_ip?: string;
        receiving?: {
            date_time?: string;
            qos?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                max_loss?: string;
                mos?: string;
                network_delay?: string;
            };
        }[];
        sending?: {
            date_time?: string;
            qos?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                max_loss?: string;
                mos?: string;
                network_delay?: string;
            };
        }[];
    };
    caller_qos?: {
        device_private_ip?: string;
        device_public_ip?: string;
        receiving?: {
            date_time?: string;
            qos?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                max_loss?: string;
                mos?: string;
                network_delay?: string;
            };
        }[];
        sending?: {
            date_time?: string;
            qos?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                max_loss?: string;
                mos?: string;
                network_delay?: string;
            };
        }[];
    };
};
type DashboardGetCallDetailsFromCallLogPathParams = {
    call_id: string;
};
type DashboardGetCallDetailsFromCallLogResponse = {
    call_id?: string;
    callee?: {
        codec?: string;
        device_private_ip?: string;
        device_public_ip?: string;
        device_type?: string;
        extension_number?: string;
        headset?: string;
        isp?: string;
        microphone?: string;
        phone_number?: string;
        site_id?: string;
        id?: string;
        extension_type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
        display_name?: string;
    };
    caller?: {
        codec?: string;
        device_private_ip?: string;
        device_public_ip?: string;
        device_type?: string;
        extension_number?: string;
        headset?: string;
        isp?: string;
        microphone?: string;
        phone_number?: string;
        site_id?: string;
        id?: string;
        extension_type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
        display_name?: string;
    };
    date_time?: string;
    direction?: string;
    duration?: number;
    mos?: string;
};
type DashboardListDefaultEmergencyAddressUsersQueryParams = {
    status: "set" | "not_set";
    site_id?: string;
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListDefaultEmergencyAddressUsersResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    records?: {
        email?: string;
        user_display_name?: string;
        extension_id?: string;
        extension_number?: number;
        site_name?: string;
        site_id?: string;
        status?: "set" | "not_set";
    }[];
};
type DashboardListDetectablePersonalLocationUsersQueryParams = {
    status: "set" | "not_set";
    site_id?: string;
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListDetectablePersonalLocationUsersResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    records?: {
        email?: string;
        user_display_name?: string;
        extension_id?: string;
        extension_number?: number;
        site_name?: string;
        site_id?: string;
        status?: "set" | "not_set";
    }[];
};
type DashboardListUsersPermissionForLocationSharingQueryParams = {
    site_id?: string;
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListUsersPermissionForLocationSharingResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    user_permissions?: {
        email?: string;
        user_display_name?: string;
        extension_id?: string;
        extension_number?: number;
        site_name?: string;
        site_id?: string;
        device_permissions?: {
            last_seen_time?: number;
            location_sharing?: "allowed" | "disallowed";
            platform?: string;
        }[];
    }[];
};
type DashboardListNomadicEmergencyServicesUsersQueryParams = {
    status: "enabled" | "disabled";
    site_id?: string;
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListNomadicEmergencyServicesUsersResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    records?: {
        email?: string;
        user_display_name?: string;
        extension_id?: string;
        extension_number?: number;
        site_name?: string;
        site_id?: string;
        status?: "enabled" | "disabled";
        reason_for_disabling?: 1 | 2 | 3 | 4 | 5;
    }[];
};
type DashboardListRealTimeLocationForIPPhonesQueryParams = {
    location_type: "company" | "personal" | "unknown";
    site_id?: string;
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListRealTimeLocationForIPPhonesResponse = {
    records?: {
        device_id?: string;
        device_name?: string;
        site_id?: string;
        site_name?: string;
        public_ip?: string;
        private_ip?: string;
        bssid?: string;
        emergency_address?: string;
        mac_address?: string;
        location_name?: string;
        network_switch?: {
            port?: string;
            mac_address?: string;
        };
        location_type?: "company" | "personal" | "unknown";
        assigned_info?: {
            extension_id?: string;
            extension_number?: number;
            user_email?: string;
            user_display_name?: string;
        }[];
    }[];
    total_records?: number;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListRealTimeLocationForUsersQueryParams = {
    location_type: "company" | "personal" | "unknown";
    site_id?: string;
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListRealTimeLocationForUsersResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    records?: {
        email?: string;
        bssid?: string;
        user_display_name?: string;
        extension_id?: string;
        extension_number?: number;
        site_name?: string;
        site_id?: string;
        public_ip?: string;
        private_ip?: string;
        emergency_address?: string;
        location_name?: string;
        network_switch?: {
            port?: string;
            mac_address?: string;
        };
        location_type?: "company" | "personal" | "unknown";
    }[];
};
type DashboardListTrackedLocationsQueryParams = {
    type?: 1 | 2 | 3 | 4 | 5 | 6;
    site_id?: string;
    location_type?: "company" | "personal" | "unknown";
    keyword?: string;
};
type DashboardListTrackedLocationsResponse = {
    location_tracking?: {
        assignees?: {
            extension_number?: number;
            id?: string;
            name?: string;
        }[];
        city?: string;
        country?: string;
        device?: {
            bssid?: string;
            id?: string;
            mac_address?: string;
            name?: string;
            private_ip?: string;
            public_ip?: string;
        };
        emergency_address?: string;
        name?: string;
        network_switch?: {
            mac_address?: string;
            port?: string;
        };
        site?: {
            id?: string;
            name?: string;
        };
        type?: "company" | "personal" | "unknown";
        zip?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type DashboardListPastCallMetricsQueryParams = {
    from?: string;
    to?: string;
    phone_number?: string;
    extension_number?: string;
    quality_type?: "good" | "bad";
    department?: string;
    cost_center?: string;
    directions?: ("inbound" | "outbound" | "internal")[];
    durations?: (0 | 1 | 2 | 3)[];
    site_id?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardListPastCallMetricsResponse = {
    call_logs?: {
        call_id?: string;
        callee?: {
            codec?: string;
            device_private_ip?: string;
            device_public_ip?: string;
            device_type?: string;
            extension_number?: string;
            headset?: string;
            isp?: string;
            microphone?: string;
            phone_number?: string;
            site_id?: string;
        };
        caller?: {
            codec?: string;
            device_private_ip?: string;
            device_public_ip?: string;
            device_type?: string;
            extension_number?: string;
            headset?: string;
            isp?: string;
            microphone?: string;
            phone_number?: string;
            site_id?: string;
        };
        date_time?: string;
        direction?: "inbound" | "outbound" | "internal";
        duration?: number;
        mos?: string;
    }[];
    from?: string;
    to?: string;
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type DeviceLineKeysGetDeviceLineKeysInformationPathParams = {
    deviceId: string;
};
type DeviceLineKeysGetDeviceLineKeysInformationResponse = {
    device_id?: string;
    device_name?: string;
    positions?: {
        index?: number;
        owner_extension_name?: string;
        owner_extension_number?: number;
        extension_number?: number;
        extension_type?: "User" | "CommonArea";
        extension_id?: string;
        display_name?: string;
        phone_number?: string;
        outbound_caller_ids?: {
            extension_id?: string;
            phone_number?: string;
            usage_type?: "Main Company Number" | "Additional Company Number" | "Direct Number" | "Phone Number";
        }[];
    }[];
};
type DeviceLineKeysBatchUpdateDeviceLineKeyPositionPathParams = {
    deviceId: string;
};
type DeviceLineKeysBatchUpdateDeviceLineKeyPositionRequestBody = {
    positions?: {
        extension_id?: string;
        index?: number;
    }[];
};
type DialByNameDirectoryListUsersInDirectoryQueryParams = {
    page_size?: number;
    next_page_token?: string;
    in_directory?: boolean;
    site_id: string;
};
type DialByNameDirectoryListUsersInDirectoryResponse = {
    next_page_token?: string;
    page_size?: number;
    result?: {
        extension_id?: string;
        display_name?: string;
        email?: string;
        extension_number?: string;
        site?: {
            id?: string;
            name?: string;
        };
    }[];
};
type DialByNameDirectoryAddUsersToDirectoryRequestBody = {
    site_id: string;
    extension_ids?: string[];
};
type DialByNameDirectoryDeleteUsersFromDirectoryQueryParams = {
    site_id: string;
    extension_ids?: string[];
};
type DialByNameDirectoryListUsersInDirectoryBySitePathParams = {
    siteId: string;
};
type DialByNameDirectoryListUsersInDirectoryBySiteQueryParams = {
    page_size?: number;
    next_page_token?: string;
    in_directory?: boolean;
    site_id?: string;
};
type DialByNameDirectoryListUsersInDirectoryBySiteResponse = {
    next_page_token?: string;
    page_size?: number;
    result?: {
        extension_id?: string;
        display_name?: string;
        email?: string;
        extension_number?: string;
        site?: {
            id?: string;
            name?: string;
        };
    }[];
};
type DialByNameDirectoryAddUsersToDirectoryOfSitePathParams = {
    siteId: string;
};
type DialByNameDirectoryAddUsersToDirectoryOfSiteRequestBody = {
    site_id?: string;
    extension_ids?: string[];
};
type DialByNameDirectoryDeleteUsersFromDirectoryOfSitePathParams = {
    siteId: string;
};
type DialByNameDirectoryDeleteUsersFromDirectoryOfSiteQueryParams = {
    site_id?: string;
    extension_ids?: string[];
};
type EmergencyAddressesListEmergencyAddressesQueryParams = {
    site_id?: string;
    user_id?: string;
    level?: 0 | 1 | 2;
    status?: 1 | 2 | 3 | 4 | 5 | 6;
    address_keyword?: string;
    next_page_token?: string;
    page_size?: number;
};
type EmergencyAddressesListEmergencyAddressesResponse = {
    emergency_addresses?: {
        address_line1?: string;
        address_line2?: string;
        city?: string;
        country?: string;
        id?: string;
        is_default?: boolean;
        level?: 0 | 1 | 2;
        owner?: {
            extension_number?: number;
            id?: string;
            name?: string;
        };
        site?: {
            id?: string;
            name?: string;
        };
        state_code?: string;
        status?: 1 | 2 | 3 | 4 | 5 | 6;
        zip?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type EmergencyAddressesAddEmergencyAddressRequestBody = {
    address_line1: string;
    address_line2?: string;
    city: string;
    country: string;
    is_default?: boolean;
    site_id?: string;
    state_code: string;
    user_id?: string;
    zip: string;
};
type EmergencyAddressesAddEmergencyAddressResponse = {
    address_line1?: string;
    address_line2?: string;
    city?: string;
    country?: string;
    id?: string;
    is_default?: boolean;
    level?: 0 | 1 | 2;
    owner?: {
        extension_number?: string;
        id?: string;
        name?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    state_code?: string;
    status?: 1 | 2 | 3 | 4 | 5 | 6;
    zip?: string;
};
type EmergencyAddressesGetEmergencyAddressDetailsPathParams = {
    emergencyAddressId: string;
};
type EmergencyAddressesGetEmergencyAddressDetailsResponse = {
    address_line1?: string;
    address_line2?: string;
    city?: string;
    country?: string;
    id?: string;
    is_default?: boolean;
    level?: 0 | 1 | 2;
    owner?: {
        extension_number?: number;
        id?: string;
        name?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    state_code?: string;
    status?: 1 | 2 | 3 | 4 | 5 | 6;
    zip?: string;
};
type EmergencyAddressesDeleteEmergencyAddressPathParams = {
    emergencyAddressId: string;
};
type EmergencyAddressesUpdateEmergencyAddressPathParams = {
    emergencyAddressId: string;
};
type EmergencyAddressesUpdateEmergencyAddressRequestBody = {
    address_line1?: string;
    address_line2?: string;
    city?: string;
    country?: string;
    is_default?: boolean;
    state_code?: string;
    zip?: string;
};
type EmergencyAddressesUpdateEmergencyAddressResponse = {
    address_line1?: string;
    address_line2?: string;
    city?: string;
    country?: string;
    id?: string;
    is_default?: boolean;
    level?: 0 | 1 | 2;
    owner?: {
        extension_number?: number;
        id?: string;
        name?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    state_code?: string;
    status?: 1 | 2 | 3 | 4 | 5 | 6;
    zip?: string;
};
type EmergencyServiceLocationsBatchAddEmergencyServiceLocationsRequestBody = {
    locations: {
        bssid?: string;
        company_address: {
            address_line1: string;
            address_line2?: string;
            city?: string;
            country: string;
            state_code?: string;
            vat_number?: string;
            zip?: string;
        };
        display_name: string;
        elin?: string;
        identifier: string;
        network_switches?: {
            mac_address?: string;
            port?: string;
            port_prefix?: string;
            port_range_from?: string;
            port_range_to?: string;
        }[];
        parent_identifier?: string;
        private_ip?: string;
        public_ip?: string;
        sip_group_name?: string;
        minimum_match_criteria?: boolean;
    }[];
    site_id?: string;
};
type EmergencyServiceLocationsBatchAddEmergencyServiceLocationsResponse = {
    locations?: {
        display_name?: string;
        location_id?: string;
    }[];
};
type EmergencyServiceLocationsListEmergencyServiceLocationsQueryParams = {
    next_page_token?: string;
    page_size?: number;
    site_id?: string;
};
type EmergencyServiceLocationsListEmergencyServiceLocationsResponse = {
    locations?: {
        bssid?: string;
        elin?: {
            phone_number?: string;
            phone_number_id?: string;
        };
        id?: string;
        identifier?: string;
        name?: string;
        network_switches?: {
            mac_address?: string;
            port?: string;
            port_prefix?: string;
            port_range_from?: string;
            port_range_to?: string;
        }[];
        parent_location_id?: string;
        private_ip?: string;
        public_ip?: string;
        sip_group?: {
            display_name?: string;
            id?: string;
        };
        site?: {
            id?: string;
            name?: string;
        };
        emergency_address?: {
            id?: string;
            address_line1?: string;
            address_line2?: string;
            city?: string;
            state_code?: string;
            country?: string;
            zip?: string;
            vat_number?: string;
        };
        minimum_match_criteria?: boolean;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type EmergencyServiceLocationsAddEmergencyServiceLocationRequestBody = {
    bssid?: string;
    elin_phone_number_id?: string;
    emergency_address_id: string;
    name: string;
    parent_location_id?: string;
    private_ip?: string;
    public_ip?: string;
    sip_group_id?: string;
    site_id?: string;
    minimum_match_criteria?: boolean;
};
type EmergencyServiceLocationsAddEmergencyServiceLocationResponse = {
    id?: string;
    name?: string;
};
type EmergencyServiceLocationsGetEmergencyServiceLocationDetailsPathParams = {
    locationId: string;
};
type EmergencyServiceLocationsGetEmergencyServiceLocationDetailsResponse = {
    bssid?: string;
    elin?: {
        phone_number?: string;
        phone_number_id?: string;
    };
    emergency_address?: {
        address_line1?: string;
        address_line2?: string;
        city?: string;
        country?: string;
        id?: string;
        state_code?: string;
        zip?: string;
    };
    id?: string;
    name?: string;
    network_switches?: {
        mac_address?: string;
        port?: string;
        port_prefix?: string;
        port_range_from?: string;
        port_range_to?: string;
    }[];
    parent_location_id?: string;
    private_ip?: string;
    public_ip?: string;
    sip_group?: {
        display_name?: string;
        id?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    minimum_match_criteria?: boolean;
};
type EmergencyServiceLocationsDeleteEmergencyLocationPathParams = {
    locationId: string;
};
type EmergencyServiceLocationsUpdateEmergencyServiceLocationPathParams = {
    locationId: string;
};
type EmergencyServiceLocationsUpdateEmergencyServiceLocationRequestBody = {
    bssid?: string;
    elin_phone_number_id?: string;
    emergency_address_id?: string;
    name?: string;
    network_switches?: {
        mac_address?: string;
        port?: string;
        port_prefix?: string;
        port_range_from?: string;
        port_range_to?: string;
    }[];
    private_ip?: string;
    public_ip?: string;
    sip_group_id?: string;
    minimum_match_criteria?: boolean;
};
type ExternalContactsListExternalContactsQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type ExternalContactsListExternalContactsResponse = {
    external_contacts?: {
        description?: string;
        email?: string;
        extension_number?: string;
        external_contact_id?: string;
        id?: string;
        name?: string;
        phone_numbers?: string[];
        auto_call_recorded?: boolean;
        profile_picture_download_url?: string;
        enable_internal_extension?: boolean;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ExternalContactsAddExternalContactRequestBody = {
    description?: string;
    email?: string;
    extension_number?: string;
    id?: string;
    name: string;
    phone_numbers?: string[];
    routing_path?: string;
    auto_call_recorded?: boolean;
    profile_picture?: {
        type?: "JPG" | "JPEG" | "PNG" | "GIF";
        base64_encoding?: string;
    };
    enable_internal_extension?: boolean;
};
type ExternalContactsAddExternalContactResponse = {
    name?: string;
    external_contact_id?: string;
};
type ExternalContactsGetExternalContactDetailsPathParams = {
    externalContactId: string;
};
type ExternalContactsGetExternalContactDetailsResponse = {
    description?: string;
    email?: string;
    extension_number?: string;
    external_contact_id?: string;
    id?: string;
    name?: string;
    phone_numbers?: string[];
    auto_call_recorded?: boolean;
    profile_picture_download_url?: string;
    enable_internal_extension?: boolean;
};
type ExternalContactsDeleteExternalContactPathParams = {
    externalContactId: string;
};
type ExternalContactsUpdateExternalContactPathParams = {
    externalContactId: string;
};
type ExternalContactsUpdateExternalContactRequestBody = {
    description?: string;
    email?: string;
    extension_number?: string;
    id?: string;
    name?: string;
    phone_numbers?: string[];
    routing_path?: string;
    auto_call_recorded?: boolean;
    profile_picture?: {
        type?: "JPG" | "JPEG" | "PNG" | "GIF";
        base64_encoding?: string;
    };
    enable_internal_extension?: boolean;
};
type FirmwareUpdateRulesListFirmwareUpdateRulesQueryParams = {
    site_id?: string;
    page_size?: number;
    next_page_token?: string;
};
type FirmwareUpdateRulesListFirmwareUpdateRulesResponse = {
    next_page_token?: string;
    page_size?: number;
    rules?: {
        rule_id?: string;
        version?: string;
        device_type?: string;
        device_model?: string;
    }[];
};
type FirmwareUpdateRulesAddFirmwareUpdateRuleRequestBody = {
    site_id?: string;
    version: string;
    device_type: string;
    device_model: string;
    restart_type?: 1 | 2;
};
type FirmwareUpdateRulesAddFirmwareUpdateRuleResponse = {
    rule_Id?: string;
};
type FirmwareUpdateRulesGetFirmwareUpdateRuleInformationPathParams = {
    ruleId: string;
};
type FirmwareUpdateRulesGetFirmwareUpdateRuleInformationResponse = {
    device_type?: string;
    device_model?: string;
    version?: string;
    update_log?: string;
};
type FirmwareUpdateRulesDeleteFirmwareUpdateRulePathParams = {
    ruleId: string;
};
type FirmwareUpdateRulesDeleteFirmwareUpdateRuleQueryParams = {
    restart_type?: 1 | 2;
};
type FirmwareUpdateRulesUpdateFirmwareUpdateRulePathParams = {
    ruleId: string;
};
type FirmwareUpdateRulesUpdateFirmwareUpdateRuleRequestBody = {
    version: string;
    device_type: string;
    device_model: string;
    restart_type?: 1 | 2;
};
type FirmwareUpdateRulesListUpdatableFirmwaresQueryParams = {
    is_update?: boolean;
    site_id?: string;
};
type FirmwareUpdateRulesListUpdatableFirmwaresResponse = {
    firmwares?: {
        device_type?: string;
        device_model?: string;
        versions?: {
            version?: string;
            update_log?: string;
            expire_time?: string;
            status?: 1 | 2 | 3;
        }[];
    }[];
};
type GroupCallPickupListGroupCallPickupObjectsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    site_id?: string;
};
type GroupCallPickupListGroupCallPickupObjectsResponse = {
    group_call_pickup?: {
        id?: string;
        display_name?: string;
        extension_id?: string;
        extension_number?: number;
        member_count?: number;
        description?: string;
        delay?: 0 | 5 | 10 | 15;
        cost_center?: string;
        department?: string;
        site?: {
            id?: string;
            name?: string;
        };
        directed_call_pickup?: boolean;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type GroupCallPickupAddGroupCallPickupObjectRequestBody = {
    display_name: string;
    site_id: string;
    description?: string;
    extension_number?: number;
    delay?: 0 | 5 | 10 | 15;
    play_incoming_calls_sound?: {
        enable?: boolean;
        ring_tone?: "ringtone_1" | "ringtone_2" | "ringtone_3";
        duration?: 0 | 1 | 3 | 5;
    };
    directed_call_pickup?: boolean;
    member_extension_ids?: string[];
};
type GroupCallPickupAddGroupCallPickupObjectResponse = {
    id?: string;
    display_name?: string;
};
type GroupCallPickupGetCallPickupGroupByIDPathParams = {
    groupId: string;
};
type GroupCallPickupGetCallPickupGroupByIDResponse = {
    id?: string;
    display_name?: string;
    extension_id?: string;
    extension_number?: number;
    description?: string;
    delay?: 0 | 5 | 10 | 15;
    member_count?: number;
    cost_center?: string;
    department?: string;
    site?: {
        id?: string;
        name?: string;
    };
    play_incoming_calls_sound?: {
        enable?: boolean;
        ring_tone?: "ringtone_1" | "ringtone_2" | "ringtone_3";
        duration?: 0 | 1 | 3 | 5;
    };
    directed_call_pickup?: boolean;
};
type GroupCallPickupDeleteGroupCallPickupObjectsPathParams = {
    groupId: string;
};
type GroupCallPickupUpdateGroupCallPickupInformationPathParams = {
    groupId: string;
};
type GroupCallPickupUpdateGroupCallPickupInformationRequestBody = {
    display_name?: string;
    extension_number?: number;
    description?: string;
    delay?: 0 | 5 | 10 | 15;
    cost_center?: string;
    department?: string;
    play_incoming_calls_sound?: {
        enable?: boolean;
        ring_tone?: "ringtone_1" | "ringtone_2" | "ringtone_3";
        duration?: 0 | 1 | 3 | 5;
    };
    directed_call_pickup?: boolean;
};
type GroupCallPickupListCallPickupGroupMembersPathParams = {
    groupId: string;
};
type GroupCallPickupListCallPickupGroupMembersQueryParams = {
    page_size?: number;
    next_page_token?: string;
    site_id?: string;
    extension_type?: "user" | "commonArea";
};
type GroupCallPickupListCallPickupGroupMembersResponse = {
    group_call_pickup_member?: {
        id?: string;
        display_name?: string;
        extension_id?: string;
        extension_type?: "user" | "commonArea";
        extension_number?: number;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type GroupCallPickupAddMembersToCallPickupGroupPathParams = {
    groupId: string;
};
type GroupCallPickupAddMembersToCallPickupGroupRequestBody = {
    member_extension_ids?: string[];
};
type GroupCallPickupRemoveMembersFromCallPickupGroupPathParams = {
    groupId: string;
    extensionId: string;
};
type GroupsGetGroupPolicyDetailsPathParams = {
    groupId: string;
    policyType: "allow_emergency_calls";
};
type GroupsGetGroupPolicyDetailsResponse = {
    allow_emergency_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_emergency_calls_from_clients?: boolean;
        allow_emergency_calls_from_deskphones?: boolean;
    };
};
type GroupsUpdateGroupPolicyPathParams = {
    groupId: string;
    policyType: "allow_emergency_calls";
};
type GroupsUpdateGroupPolicyRequestBody = {
    allow_emergency_calls?: {
        enable?: boolean;
        locked?: boolean;
        reset?: boolean;
        allow_emergency_calls_from_clients?: boolean;
        allow_emergency_calls_from_deskphones?: boolean;
    };
};
type GroupsGetGroupPhoneSettingsPathParams = {
    groupId: string;
};
type GroupsGetGroupPhoneSettingsQueryParams = {
    setting_types?: string;
};
type GroupsGetGroupPhoneSettingsResponse = {
    call_live_transcription?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        transcription_start_prompt?: {
            enable?: boolean;
            audio_id?: string;
            audio_name?: string;
        };
    };
    local_survivability_mode?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    select_outbound_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_hide_outbound_caller_id?: boolean;
    };
    personal_audio_library?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_music_on_hold_customization?: boolean;
        allow_voicemail_and_message_greeting_customization?: boolean;
    };
    voicemail?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_delete?: boolean;
        allow_download?: boolean;
        allow_videomail?: boolean;
        allow_share?: boolean;
        allow_virtual_background?: boolean;
    };
    voicemail_transcription?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    voicemail_notification_by_email?: {
        include_voicemail_file?: boolean;
        include_voicemail_transcription?: boolean;
        forward_voicemail_to_email?: boolean;
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    shared_voicemail_notification_by_email?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    restricted_call_hours?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        time_zone?: {
            id?: string;
            name?: string;
        };
        restricted_hours_applied?: boolean;
        restricted_holiday_hours_applied?: boolean;
        allow_internal_calls?: boolean;
    };
    allowed_call_locations?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        locations_applied?: boolean;
        allow_internal_calls?: boolean;
    };
    check_voicemails_over_phone?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    auto_call_recording?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        recording_calls?: "inbound" | "outbound" | "both";
        recording_transcription?: boolean;
        recording_start_prompt?: boolean;
        recording_start_prompt_audio_id?: string;
        recording_explicit_consent?: boolean;
        allow_stop_resume_recording?: boolean;
        disconnect_on_recording_failure?: boolean;
        play_recording_beep_tone?: {
            enable?: boolean;
            play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
            play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
            play_beep_member?: "allMember" | "recordingSide";
        };
        inbound_audio_notification?: {
            recording_start_prompt?: boolean;
            recording_start_prompt_audio_id?: string;
            recording_explicit_consent?: boolean;
        };
        outbound_audio_notification?: {
            recording_start_prompt?: boolean;
            recording_start_prompt_audio_id?: string;
            recording_explicit_consent?: boolean;
        };
    };
    ad_hoc_call_recording?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "site";
        modified?: boolean;
        recording_transcription?: boolean;
        allow_download?: boolean;
        allow_delete?: boolean;
        recording_start_prompt?: boolean;
        recording_explicit_consent?: boolean;
        play_recording_beep_tone?: {
            enable?: boolean;
            play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
            play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
            play_beep_member?: "allMember" | "recordingSide";
        };
    };
    zoom_phone_on_mobile?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_calling_sms_mms?: boolean;
        allow_calling_clients?: ("ios" | "android" | "intune" | "blackberry")[];
        allow_sms_mms_clients?: ("ios" | "android" | "intune" | "blackberry")[];
    };
    zoom_phone_on_pwa?: {
        allow_calling?: boolean;
        allow_sms_mms?: boolean;
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    sms_etiquette_tool?: {
        enable?: boolean;
        modified?: boolean;
        sms_etiquette_policy?: {
            id?: string;
            name?: string;
            description?: string;
            rule?: 1 | 2;
            content?: string;
            action?: 1 | 2;
            active?: boolean;
        }[];
    };
    outbound_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    outbound_sms?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_copy?: boolean;
        allow_paste?: boolean;
    };
    international_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    sms?: {
        enable?: boolean;
        international_sms?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_copy?: boolean;
        allow_paste?: boolean;
    };
    e2e_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    call_handling_forwarding?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        call_forwarding_type?: 1 | 2 | 3 | 4;
    };
    call_overflow?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        call_overflow_type?: 1 | 2 | 3 | 4;
    };
    call_transferring?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        call_transferring_type?: 1 | 2 | 3 | 4;
    };
    elevate_to_meeting?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    call_park?: {
        enable?: boolean;
        expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
        call_not_picked_up_action?: number;
        forward_to?: {
            display_name?: string;
            extension_id?: string;
            extension_number?: number;
            extension_type?: "user" | "zoomRoom" | "commonArea" | "ciscoRoom/polycomRoom" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
            id?: string;
        };
        sequence?: 0 | 1;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    hand_off_to_room?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    mobile_switch_to_carrier?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    delegation?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    audio_intercom?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    block_list_for_inbound_calls_and_messaging?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    block_calls_without_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    block_external_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        block_business_hours?: boolean;
        block_closed_hours?: boolean;
        block_holiday_hours?: boolean;
        block_call_action?: 0 | 9;
    };
    peer_to_peer_media?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
    };
    advanced_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        disable_incoming_unencrypted_voicemail?: boolean;
    };
    display_call_feedback_survey?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        feedback_type?: 1 | 2;
        feedback_mos?: {
            enable?: boolean;
            min?: string;
            max?: string;
        };
        feedback_duration?: {
            enable?: boolean;
            min?: number;
            max?: number;
        };
    };
    zoom_phone_on_desktop?: {
        allow_calling_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
        allow_sms_mms_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "site";
        modified?: boolean;
    };
    allow_emergency_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group";
        modified?: boolean;
        allow_emergency_calls_from_clients?: boolean;
        allow_emergency_calls_from_deskphones?: boolean;
    };
};
type IVRGetAutoReceptionistIVRPathParams = {
    autoReceptionistId: string;
};
type IVRGetAutoReceptionistIVRQueryParams = {
    hours_type?: string;
    holiday_id?: string;
};
type IVRGetAutoReceptionistIVRResponse = {
    audio_prompt?: {
        id?: string;
        name?: string;
    };
    caller_enters_no_action?: {
        action?: number;
        audio_prompt_repeat?: 1 | 2 | 3;
        forward_to?: {
            display_name?: string;
            extension_id?: string;
            extension_number?: string;
            id?: string;
        };
    };
    key_actions?: {
        action?: number;
        key?: string;
        target?: {
            display_name?: string;
            extension_id?: string;
            extension_number?: string;
            id?: string;
            phone_number?: string;
        };
        voicemail_greeting?: {
            id?: string;
            name?: string;
        };
    }[];
};
type IVRUpdateAutoReceptionistIVRPathParams = {
    autoReceptionistId: string;
};
type IVRUpdateAutoReceptionistIVRRequestBody = {
    audio_prompt_id?: string;
    caller_enters_no_action?: {
        action?: number;
        audio_prompt_repeat?: 1 | 2 | 3;
        forward_to_extension_id?: string;
    };
    holiday_id?: string;
    hours_type?: string;
    key_action?: {
        action?: number;
        key?: string;
        target?: {
            extension_id?: string;
            phone_number?: string;
        };
        voicemail_greeting_id?: string;
    };
};
type InboundBlockedListListExtensionsInboundBlockRulesPathParams = {
    extensionId: string;
};
type InboundBlockedListListExtensionsInboundBlockRulesQueryParams = {
    keyword?: string;
    match_type?: "prefix" | "phoneNumber" | "SMS-shortCodes";
    type?: "block_for_other_reasons" | "block_as_threat";
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListListExtensionsInboundBlockRulesResponse = {
    extension_blocked_rules?: {
        id?: string;
        match_type?: "prefix" | "phoneNumber" | "SMS-shortCodes";
        phone_number?: string;
        type?: "block_for_other_reasons" | "block_as_threat";
        blocked_number?: string;
        country?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListAddExtensionsInboundBlockRulePathParams = {
    extensionId: string;
};
type InboundBlockedListAddExtensionsInboundBlockRuleRequestBody = {
    match_type: "prefix" | "phoneNumber" | "SMS-shortCodes";
    blocked_number: string;
    type: "block_for_other_reasons" | "block_as_threat";
    country?: string;
};
type InboundBlockedListAddExtensionsInboundBlockRuleResponse = {
    id?: string;
};
type InboundBlockedListDeleteExtensionsInboundBlockRulePathParams = {
    extensionId: string;
};
type InboundBlockedListDeleteExtensionsInboundBlockRuleQueryParams = {
    blocked_rule_id: string;
};
type InboundBlockedListListAccountsInboundBlockedStatisticsQueryParams = {
    keyword?: string;
    match_type?: "prefix" | "phoneNumber" | "SMS-shortCodes";
    type?: string;
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListListAccountsInboundBlockedStatisticsResponse = {
    blocked_statistic?: {
        id?: string;
        match_type?: "prefix" | "phoneNumber" | "SMS-shortCodes";
        phone_number?: string;
        type?: "block_for_other_reasons" | "block_as_threat";
        block_count?: number;
        threat_count?: number;
        blocked_number?: string;
        country?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListDeleteAccountsInboundBlockedStatisticsQueryParams = {
    blocked_statistic_id: string;
};
type InboundBlockedListMarkPhoneNumberAsBlockedForAllExtensionsRequestBody = {
    blocked_statistic_id: string;
};
type InboundBlockedListListAccountsInboundBlockRulesQueryParams = {
    keyword?: string;
    match_type?: "prefix" | "phoneNumber" | "SMS-shortCodes";
    type?: "block_for_other_reasons" | "block_as_threat";
    status?: "active" | "inactive";
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListListAccountsInboundBlockRulesResponse = {
    account_blocked_rules?: {
        id?: string;
        match_type?: "prefix" | "phoneNumber" | "SMS-shortCodes";
        phone_number?: string;
        type?: "block_for_other_reasons" | "block_as_threat";
        status?: "active" | "inactive";
        comment?: string;
        blocked_number?: string;
        country?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListAddAccountsInboundBlockRuleRequestBody = {
    match_type: "prefix" | "phoneNumber" | "SMS-shortCodes";
    blocked_number: string;
    type: "block_for_other_reasons" | "block_as_threat";
    comment?: string;
    status: "active" | "inactive";
    country?: string;
};
type InboundBlockedListAddAccountsInboundBlockRuleResponse = {
    id?: string;
};
type InboundBlockedListDeleteAccountsInboundBlockRuleQueryParams = {
    blocked_rule_id: string;
};
type InboundBlockedListUpdateAccountsInboundBlockRulePathParams = {
    blockedRuleId: string;
};
type InboundBlockedListUpdateAccountsInboundBlockRuleRequestBody = {
    match_type: "prefix" | "phoneNumber" | "SMS-shortCodes";
    blocked_number: string;
    type: "block_for_other_reasons" | "block_as_threat";
    comment?: string;
    status?: "active" | "inactive";
    country?: string;
};
type LineKeysGetLineKeyPositionAndSettingsInformationPathParams = {
    extensionId: string;
};
type LineKeysGetLineKeyPositionAndSettingsInformationResponse = {
    line_keys?: {
        alias?: string;
        index?: number;
        key_assignment?: {
            display_name?: string;
            extension_id?: string;
            extension_number?: string;
            phone_number?: string;
            retrieval_code?: string;
            speed_dial_number?: string;
        };
        line_key_id?: string;
        outbound_caller_id?: string;
        type?: "line" | "blf" | "speed_dial" | "zoom_meeting" | "call_park" | "group_call_pickup";
    }[];
};
type LineKeysBatchUpdateLineKeyPositionAndSettingsInformationPathParams = {
    extensionId: string;
};
type LineKeysBatchUpdateLineKeyPositionAndSettingsInformationRequestBody = {
    line_keys?: {
        line_key_id?: string;
        index?: number;
        type?: "line" | "blf" | "speed_dial" | "zoom_meeting" | "call_park" | "group_call_pickup";
        key_assignment?: {
            extension_id?: string;
            speed_dial_number?: string;
            retrieval_code?: string;
        };
        alias?: string;
        outbound_caller_id?: string;
    }[];
};
type LineKeysDeleteLineKeySettingPathParams = {
    extensionId: string;
    lineKeyId: string;
};
type MonitoringGroupsGetListOfMonitoringGroupsOnAccountQueryParams = {
    type?: 1 | 2 | 3 | 4;
    site_id?: string;
    page_size?: number;
    next_page_token?: string;
};
type MonitoringGroupsGetListOfMonitoringGroupsOnAccountResponse = {
    monitoring_groups?: {
        id?: string;
        monitor_members_count?: number;
        monitored_members_count?: number;
        monitoring_privileges?: ("listen" | "whisper" | "barge" | "take_over")[];
        name?: string;
        prompt?: boolean;
        site?: {
            id?: string;
            name?: string;
        };
        type?: 1 | 2 | 3 | 4;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type MonitoringGroupsCreateMonitoringGroupRequestBody = {
    monitoring_privileges?: ("listen" | "whisper" | "barge" | "take_over")[];
    name?: string;
    prompt?: boolean;
    site_id?: string;
    type?: 1 | 2 | 3 | 4;
};
type MonitoringGroupsCreateMonitoringGroupResponse = {
    id?: string;
    name?: string;
};
type MonitoringGroupsGetMonitoringGroupByIDPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsGetMonitoringGroupByIDResponse = {
    id?: string;
    monitor_members_count?: number;
    monitored_members_count?: number;
    monitoring_privileges?: ("listen" | "whisper" | "barge" | "take_over")[];
    name?: string;
    prompt?: boolean;
    site?: {
        id?: string;
        name?: string;
    };
    type?: 1 | 2 | 3 | 4;
};
type MonitoringGroupsDeleteMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsUpdateMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsUpdateMonitoringGroupRequestBody = {
    monitoring_privileges?: ("listen" | "whisper" | "barge" | "take_over")[];
    name?: string;
    prompt?: boolean;
    site_id?: string;
};
type MonitoringGroupsGetMembersOfMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsGetMembersOfMonitoringGroupQueryParams = {
    member_type: "monitor" | "monitored";
    page_size?: number;
    next_page_token?: string;
};
type MonitoringGroupsGetMembersOfMonitoringGroupResponse = {
    members?: {
        display_name?: string;
        extension_id?: string;
        extension_number?: number;
        extension_type?: "user" | "call_queue" | "shared_line_group" | "common_area_phone";
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type MonitoringGroupsAddMembersToMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsAddMembersToMonitoringGroupQueryParams = {
    member_type: "monitor" | "monitored";
};
type MonitoringGroupsAddMembersToMonitoringGroupRequestBody = string[];
type MonitoringGroupsAddMembersToMonitoringGroupResponse = never;
type MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupQueryParams = {
    member_type: "monitor" | "monitored";
};
type MonitoringGroupsRemoveMemberFromMonitoringGroupPathParams = {
    monitoringGroupId: string;
    memberExtensionId: string;
};
type MonitoringGroupsRemoveMemberFromMonitoringGroupQueryParams = {
    member_type?: "monitor" | "monitored";
};
type OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsPathParams = {
    commonAreaId: string;
};
type OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsResponse = {
    countries_regions?: {
        name?: string;
        code?: number;
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        enabled_carrier?: string[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsPathParams = {
    commonAreaId: string;
};
type OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsRequestBody = {
    country_regions?: {
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesPathParams = {
    commonAreaId: string;
};
type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: "phoneNumber" | "prefix";
    status?: "active" | "inactive";
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: "phoneNumber" | "prefix";
        prefix_number?: string;
        rule?: 1 | 2 | 3 | 4;
        comment?: string;
        status?: "active" | "inactive";
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRulePathParams = {
    commonAreaId: string;
};
type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleResponse = {
    exception_rule_id?: string;
};
type OutboundCallingDeleteCommonAreaLevelOutboundCallingExceptionRulePathParams = {
    commonAreaId: string;
    exceptionRuleId: string;
};
type OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRulePathParams = {
    commonAreaId: string;
    exceptionRuleId: string;
};
type OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsResponse = {
    countries_regions?: {
        name?: string;
        code?: number;
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        enabled_carrier?: string[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingUpdateAccountLevelOutboundCallingCountriesOrRegionsRequestBody = {
    country_regions?: {
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListAccountLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: "phoneNumber" | "prefix";
    status?: "active" | "inactive";
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListAccountLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: "phoneNumber" | "prefix";
        prefix_number?: string;
        rule?: 1 | 2 | 3 | 4;
        comment?: string;
        status?: "active" | "inactive";
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddAccountLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type OutboundCallingAddAccountLevelOutboundCallingExceptionRuleResponse = {
    exception_rule_id?: string;
};
type OutboundCallingDeleteAccountLevelOutboundCallingExceptionRulePathParams = {
    exceptionRuleId: string;
};
type OutboundCallingUpdateAccountLevelOutboundCallingExceptionRulePathParams = {
    exceptionRuleId: string;
};
type OutboundCallingUpdateAccountLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsPathParams = {
    siteId: string;
};
type OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsResponse = {
    countries_regions?: {
        name?: string;
        code?: number;
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        enabled_carrier?: string[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsPathParams = {
    siteId: string;
};
type OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsRequestBody = {
    country_regions?: {
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListSiteLevelOutboundCallingExceptionRulesPathParams = {
    siteId: string;
};
type OutboundCallingListSiteLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: "phoneNumber" | "prefix";
    status?: "active" | "inactive";
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListSiteLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: "phoneNumber" | "prefix";
        prefix_number?: string;
        rule?: 1 | 2 | 3 | 4;
        comment?: string;
        status?: "active" | "inactive";
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddSiteLevelOutboundCallingExceptionRulePathParams = {
    siteId: string;
};
type OutboundCallingAddSiteLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type OutboundCallingAddSiteLevelOutboundCallingExceptionRuleResponse = {
    exception_rule_id?: string;
};
type OutboundCallingDeleteSiteLevelOutboundCallingExceptionRulePathParams = {
    siteId: string;
    exceptionRuleId: string;
};
type OutboundCallingUpdateSiteLevelOutboundCallingExceptionRulePathParams = {
    siteId: string;
    exceptionRuleId: string;
};
type OutboundCallingUpdateSiteLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsPathParams = {
    userId: string;
};
type OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsResponse = {
    countries_regions?: {
        name?: string;
        code?: number;
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        enabled_carrier?: string[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsPathParams = {
    userId: string;
};
type OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsRequestBody = {
    country_regions?: {
        iso_code?: string;
        rule?: 1 | 2 | 3 | 4;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListUserLevelOutboundCallingExceptionRulesPathParams = {
    userId: string;
};
type OutboundCallingListUserLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: "phoneNumber" | "prefix";
    status?: "active" | "inactive";
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListUserLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: "phoneNumber" | "prefix";
        prefix_number?: string;
        rule?: 1 | 2 | 3 | 4;
        comment?: string;
        status?: "active" | "inactive";
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddUserLevelOutboundCallingExceptionRulePathParams = {
    userId: string;
};
type OutboundCallingAddUserLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type OutboundCallingAddUserLevelOutboundCallingExceptionRuleResponse = {
    exception_rule_id?: string;
};
type OutboundCallingDeleteUserLevelOutboundCallingExceptionRulePathParams = {
    userId: string;
    exceptionRuleId: string;
};
type OutboundCallingUpdateUserLevelOutboundCallingExceptionRulePathParams = {
    userId: string;
    exceptionRuleId: string;
};
type OutboundCallingUpdateUserLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: "phoneNumber" | "prefix";
        prefix_number: string;
        comment?: string;
        status: "active" | "inactive";
        country: string;
    };
};
type PhoneDevicesListDevicesQueryParams = {
    type: "assigned" | "unassigned";
    assignee_type?: "user" | "commonArea";
    device_source?: "haas" | "hotDesking";
    location_status?: "unknownAddress";
    site_id?: string;
    device_type?: "algo" | "audioCodes" | "cisco" | "cyberData" | "grandstream" | "poly" | "yealink" | "other";
    keyword?: string;
    next_page_token?: string;
    page_size?: number;
};
type PhoneDevicesListDevicesResponse = {
    devices?: {
        assignee?: {
            extension_number?: number;
            id?: string;
            name?: string;
            extension_type?: "user" | "commonArea";
        };
        assignees?: {
            extension_number?: number;
            id?: string;
            name?: string;
            extension_type?: "user" | "commonArea";
            extension_id?: string;
        }[];
        device_type?: string;
        display_name?: string;
        id?: string;
        mac_address?: string;
        site?: {
            id?: string;
            name?: string;
        };
        status?: "online" | "offline";
        provision_template_id?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type PhoneDevicesAddDeviceRequestBody = {
    assigned_to?: string;
    assignee_extension_ids: string[];
    display_name: string;
    mac_address: string;
    model?: string;
    type: string;
    provision_template_id?: string;
};
type PhoneDevicesAddDeviceResponse = {
    id?: string;
    display_name?: string;
};
type PhoneDevicesSyncDeskphonesRequestBody = {
    level: number;
    site_id?: string;
};
type PhoneDevicesGetDeviceDetailsPathParams = {
    deviceId: string;
};
type PhoneDevicesGetDeviceDetailsResponse = {
    assignee?: {
        extension_number?: number;
        id?: string;
        name?: string;
        extension_type?: "user" | "commonArea";
    };
    assignees?: {
        extension_number?: number;
        id?: string;
        name?: string;
        extension_type?: "user" | "commonArea";
        extension_id?: string;
    }[];
    device_type?: string;
    display_name?: string;
    id?: string;
    mac_address?: string;
    provision?: {
        sip_accounts?: {
            authorization_id?: string;
            outbound_proxy?: string;
            password?: string;
            secondary_outbound_proxy?: string;
            shared_line?: {
                alias?: string;
                line_subscription?: {
                    display_name?: string;
                    extension_number?: number;
                    phone_number?: string;
                };
                outbound_caller_id?: string;
            };
            sip_domain?: string;
            user_name?: string;
        }[];
        type?: "assisted" | "ztp" | "manual";
        url?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    status?: "online" | "offline";
    provision_template_id?: string;
    private_ip?: string;
    public_ip?: string;
    policy?: {
        call_control?: {
            status?: "unsupported" | "on" | "off";
        };
        hot_desking?: {
            status?: "unsupported" | "on" | "off";
        };
    };
};
type PhoneDevicesDeleteDevicePathParams = {
    deviceId: string;
};
type PhoneDevicesUpdateDevicePathParams = {
    deviceId: string;
};
type PhoneDevicesUpdateDeviceRequestBody = {
    assigned_to?: string;
    display_name?: string;
    provision_template_id?: string;
};
type PhoneDevicesAssignEntityToDevicePathParams = {
    deviceId: string;
};
type PhoneDevicesAssignEntityToDeviceRequestBody = {
    assignee_extension_ids: string[];
};
type PhoneDevicesAssignEntityToDeviceResponse = never;
type PhoneDevicesUnassignEntityFromDevicePathParams = {
    deviceId: string;
    extensionId: string;
};
type PhoneDevicesUpdateProvisionTemplateOfDevicePathParams = {
    deviceId: string;
};
type PhoneDevicesUpdateProvisionTemplateOfDeviceRequestBody = {
    provision_template_id?: string;
};
type PhoneDevicesRebootDeskPhonePathParams = {
    deviceId: string;
};
type PhoneDevicesListSmartphonesQueryParams = {
    site_id?: string;
    keyword?: string;
    next_page_token?: string;
    page_size?: number;
};
type PhoneDevicesListSmartphonesResponse = {
    smartphones: {
        smartphone_id?: string;
        device_name?: string;
        device_type?: string;
        serial_number?: string;
        public_ip?: string;
        activation_status?: "Activated";
        activation_time?: string;
        assignee?: {
            common_area_id?: string;
            name?: string;
            extension_number?: number;
        };
        site?: {
            site_id?: string;
            name?: string;
        };
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type PhoneNumbersAddBYOCPhoneNumbersRequestBody = {
    carrier: string;
    phone_numbers: string[];
    sip_group_id?: string;
    site_id?: string;
};
type PhoneNumbersAddBYOCPhoneNumbersResponse = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type PhoneNumbersListPhoneNumbersQueryParams = {
    next_page_token?: string;
    type?: "assigned" | "unassigned" | "byoc" | "all";
    extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "emergencyNumberPool" | "companyLocation" | "meetingService";
    page_size?: number;
    number_type?: "toll" | "tollfree";
    pending_numbers?: boolean;
    site_id?: string;
};
type PhoneNumbersListPhoneNumbersResponse = {
    next_page_token?: string;
    page_size?: number;
    phone_numbers?: {
        assignee?: {
            extension_number?: number;
            id?: string;
            name?: string;
            type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "emergencyNumberPool" | "companyLocation" | "meetingService";
        };
        capability?: string[];
        carrier?: {
            code?: number;
            name?: string;
        };
        display_name?: string;
        emergency_address?: {
            address_line1?: string;
            address_line2?: string;
            city?: string;
            country?: string;
            state_code?: string;
            zip?: string;
        };
        emergency_address_status?: 1 | 2;
        emergency_address_update_time?: string;
        id?: string;
        location?: string;
        number?: string;
        number_type?: "toll" | "tollfree";
        sip_group?: {
            display_name?: string;
            id?: string;
        };
        site?: {
            id?: string;
            name?: string;
        };
        source?: "internal" | "external";
        status?: "pending" | "available";
    }[];
    total_records?: number;
};
type PhoneNumbersDeleteUnassignedPhoneNumbersQueryParams = {
    phone_numbers: string[];
};
type PhoneNumbersUpdateSitesUnassignedPhoneNumbersPathParams = {
    siteId: string;
};
type PhoneNumbersUpdateSitesUnassignedPhoneNumbersRequestBody = {
    phone_numbers?: string[];
};
type PhoneNumbersGetPhoneNumberPathParams = {
    phoneNumberId: string;
};
type PhoneNumbersGetPhoneNumberResponse = {
    assignee?: {
        audio_prompt_language?: string;
        display_number?: string;
        extension_number?: number;
        greeting?: {
            id?: string;
            name?: string;
        };
        id?: string;
        label?: string;
        meeting_id?: string;
        name?: string;
        on_hold_music?: {
            id?: string;
            name?: string;
        };
        type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "emergencyNumberPool" | "companyLocation" | "meetingService";
    };
    capability?: string[];
    carrier?: {
        code?: number;
        name?: string;
    };
    display_name?: string;
    emergency_address?: {
        address_line1?: string;
        address_line2?: string;
        city?: string;
        country?: string;
        state_code?: string;
        zip?: string;
    };
    emergency_address_status?: 1 | 2;
    emergency_address_update_time?: string;
    id?: string;
    location?: string;
    number?: string;
    number_type?: "toll" | "tollfree";
    sip_group?: {
        display_name?: string;
        id?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    source?: "internal" | "external";
    status?: "pending" | "available";
};
type PhoneNumbersUpdatePhoneNumberPathParams = {
    phoneNumberId: string;
};
type PhoneNumbersUpdatePhoneNumberRequestBody = {
    capability?: string[];
    display_name?: string;
    emergency_address_status?: number;
    sip_group_id?: string;
};
type PhoneNumbersAssignPhoneNumberToUserPathParams = {
    userId: string;
};
type PhoneNumbersAssignPhoneNumberToUserRequestBody = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type PhoneNumbersAssignPhoneNumberToUserResponse = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type PhoneNumbersUnassignPhoneNumberPathParams = {
    userId: string;
    phoneNumberId: string;
};
type PhonePlansListCallingPlansResponse = {
    calling_plans?: {
        assigned?: number;
        available?: number;
        name?: string;
        subscribed?: number;
        type?: number;
        billing_account_id?: string;
        billing_account_name?: string;
        billing_subscription_id?: string;
        billing_subscription_name?: string;
    }[];
};
type PhonePlansListPlanInformationResponse = {
    calling_plans?: {
        assigned?: number;
        available?: number;
        name?: string;
        subscribed?: number;
        type?: number;
        billing_subscription_id?: string;
        billing_subscription_name?: string;
    }[];
    phone_numbers?: {
        assigned?: number;
        available?: number;
        name?: string;
        subscribed?: number;
    }[];
};
type PhoneRolesListPhoneRolesResponse = {
    roles?: {
        id?: string;
        name?: string;
        description?: string;
        total_members?: number;
        is_default?: boolean;
    }[];
};
type PhoneRolesDuplicatePhoneRoleRequestBody = {
    role_id: string;
    name?: string;
    description?: string;
};
type PhoneRolesDuplicatePhoneRoleResponse = {
    id?: string;
    name?: string;
};
type PhoneRolesGetRoleInformationPathParams = {
    roleId: string;
};
type PhoneRolesGetRoleInformationResponse = {
    description?: string;
    id?: string;
    name?: string;
    total_members?: number;
    is_default?: boolean;
};
type PhoneRolesDeletePhoneRolePathParams = {
    roleId: string;
};
type PhoneRolesUpdatePhoneRolePathParams = {
    roleId: string;
};
type PhoneRolesUpdatePhoneRoleRequestBody = {
    name?: string;
    description?: string;
};
type PhoneRolesListMembersInRolePathParams = {
    roleId: string;
};
type PhoneRolesListMembersInRoleQueryParams = {
    in_role?: boolean;
};
type PhoneRolesListMembersInRoleResponse = {
    members?: {
        user_id?: string;
        display_name?: string;
        email?: string;
        extension_number?: number;
        site?: {
            id?: string;
            name?: string;
        };
    }[];
};
type PhoneRolesAddMembersToRolesPathParams = {
    roleId: string;
};
type PhoneRolesAddMembersToRolesRequestBody = {
    role_id?: string;
    copy_targets?: boolean;
    copy_all_members?: boolean;
    user_ids?: string[];
};
type PhoneRolesDeleteMembersInRolePathParams = {
    roleId: string;
};
type PhoneRolesDeleteMembersInRoleQueryParams = {
    user_ids: string[];
};
type PhoneRolesListPhoneRoleTargetsPathParams = {
    roleId: string;
};
type PhoneRolesListPhoneRoleTargetsQueryParams = {
    is_default?: boolean;
    user_id?: string;
    selected?: boolean;
    target_type?: "site" | "callQueue" | "autoReceptionist" | "user" | "group" | "sharedLineGroup" | "commonArea";
    site_id?: string;
    keyword?: string;
    page_size?: string;
    next_page_token?: string;
};
type PhoneRolesListPhoneRoleTargetsResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    targets?: {
        target_id?: string;
        target_type?: "site" | "callQueue" | "autoReceptionist" | "user" | "group" | "sharedLineGroup" | "commonArea";
        target_name?: string;
        extension_number?: number;
        site_id?: string;
        site_name?: string;
    }[];
};
type PhoneRolesAddPhoneRoleTargetsPathParams = {
    roleId: string;
};
type PhoneRolesAddPhoneRoleTargetsRequestBody = {
    is_default?: boolean;
    user_id?: string;
    targets: {
        target_type?: "site" | "callQueue" | "autoReceptionist" | "user" | "group" | "sharedLineGroup" | "commonArea";
        target_ids: string[];
    }[];
};
type PhoneRolesAddPhoneRoleTargetsResponse = {
    is_default?: boolean;
    user_id?: string;
    targets?: {
        target_type?: "site" | "callQueue" | "autoReceptionist" | "user" | "group" | "sharedLineGroup" | "commonArea";
        target_ids?: string[];
    }[];
};
type PhoneRolesDeletePhoneRoleTargetsPathParams = {
    roleId: string;
};
type PhoneRolesDeletePhoneRoleTargetsRequestBody = {
    is_default?: boolean;
    user_id?: string;
    targets: {
        target_type?: "site" | "callQueue" | "autoReceptionist" | "user" | "group" | "sharedLineGroup" | "commonArea";
        target_ids: string[];
    }[];
};
type PrivateDirectoryListPrivateDirectoryMembersQueryParams = {
    next_page_token?: string;
    page_size?: number;
    keyword?: string;
    site_id?: string;
};
type PrivateDirectoryListPrivateDirectoryMembersResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    private_directory_members?: {
        extension_id: string;
        extension_type: "user" | "zoom_room" | "common_area" | "auto_receptionist" | "call_queue" | "shared_line_group";
        extension_number: number;
        extension_display_name: string;
        extension_email?: string;
        searchable_on_web_portal: "everybody" | "admins_only" | "nobody";
        site_id?: string;
        site_name?: string;
    }[];
};
type PrivateDirectoryAddMembersToPrivateDirectoryRequestBody = {
    site_id?: string;
    members: {
        extension_id: string;
        searchable_on_web_portal: "everybody" | "admins_only" | "nobody";
    }[];
};
type PrivateDirectoryRemoveMemberFromPrivateDirectoryPathParams = {
    extensionId: string;
};
type PrivateDirectoryRemoveMemberFromPrivateDirectoryQueryParams = {
    site_id?: string;
};
type PrivateDirectoryUpdatePrivateDirectoryMemberPathParams = {
    extensionId: string;
};
type PrivateDirectoryUpdatePrivateDirectoryMemberRequestBody = {
    site_id?: string;
    searchable_on_web_portal: "everybody" | "admins_only" | "nobody";
};
type ProviderExchangeListCarrierPeeringPhoneNumbersQueryParams = {
    page_size?: number;
    next_page_token?: string;
    phone_number?: string;
};
type ProviderExchangeListCarrierPeeringPhoneNumbersResponse = {
    next_page_token?: string;
    numbers?: {
        customer_account_name?: string;
        customer_account_number?: string;
        assigned: number;
        billing_reference_id?: string;
        phone_number: string;
        service_info?: string;
        sip_trunk_name: string;
        status: number;
    }[];
    total_records?: number;
};
type ProviderExchangeListPeeringPhoneNumbersQueryParams = {
    page_size?: number;
    next_page_token?: string;
    phone_number?: string;
    carrier_code?: number;
};
type ProviderExchangeListPeeringPhoneNumbersResponse = {
    next_page_token?: string;
    numbers?: {
        assigned: number;
        billing_reference_id?: string;
        phone_number: string;
        service_info?: string;
        sip_trunk_name: string;
        status: number;
    }[];
    total_records?: number;
};
type ProviderExchangeAddPeeringPhoneNumbersRequestBody = {
    carrier_code?: number;
    phone_numbers?: {
        billing_reference_id?: string;
        phone_number: string;
        service_info?: string;
        sip_trunk_name: string;
        status: number;
    }[];
};
type ProviderExchangeAddPeeringPhoneNumbersResponse = {
    unprocessed_numbers?: {
        failure_reason?: string;
        phone_number?: string;
    }[];
};
type ProviderExchangeRemovePeeringPhoneNumbersQueryParams = {
    carrier_code?: number;
    phone_numbers: string[];
};
type ProviderExchangeRemovePeeringPhoneNumbersResponse = {
    unprocessed_numbers?: {
        failure_reason?: string;
        phone_number?: string;
    }[];
};
type ProviderExchangeUpdatePeeringPhoneNumbersRequestBody = {
    carrier_code?: number;
    phone_numbers?: {
        billing_reference_id?: string;
        phone_number: string;
        service_info?: string;
        sip_trunk_name?: string;
        status?: number;
    }[];
};
type ProviderExchangeUpdatePeeringPhoneNumbersResponse = {
    unprocessed_numbers?: {
        failure_reason?: string;
        phone_number?: string;
    }[];
};
type ProvisionTemplatesListProvisionTemplatesQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type ProvisionTemplatesListProvisionTemplatesResponse = {
    next_page_token?: string;
    page_size?: number;
    provision_templates?: {
        id?: string;
        name?: string;
        description?: string;
        bound_device_count?: number;
    }[];
    total_records?: number;
};
type ProvisionTemplatesAddProvisionTemplateRequestBody = {
    name: string;
    description?: string;
    content?: string;
};
type ProvisionTemplatesAddProvisionTemplateResponse = {
    id?: string;
    name?: string;
};
type ProvisionTemplatesGetProvisionTemplatePathParams = {
    templateId: string;
};
type ProvisionTemplatesGetProvisionTemplateResponse = {
    id?: string;
    name?: string;
    description?: string;
    content?: string;
    bound_device_count?: number;
};
type ProvisionTemplatesDeleteProvisionTemplatePathParams = {
    templateId: string;
};
type ProvisionTemplatesUpdateProvisionTemplatePathParams = {
    templateId: string;
};
type ProvisionTemplatesUpdateProvisionTemplateRequestBody = {
    name?: string;
    description?: string;
    content?: string;
};
type RecordingsGetRecordingByCallIDPathParams = {
    id: string;
};
type RecordingsGetRecordingByCallIDResponse = {
    call_id?: string;
    call_log_id?: string;
    call_history_id?: string;
    callee_name?: string;
    callee_number?: string;
    callee_number_type?: 1 | 2 | 3;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: 1 | 2;
    outgoing_by?: {
        name?: string;
        extension_number?: string;
    };
    accepted_by?: {
        name?: string;
        extension_number?: string;
    };
    date_time?: string;
    direction?: string;
    download_url?: string;
    duration?: number;
    end_time?: string;
    id?: string;
    meeting_uuid?: string;
    owner?: {
        extension_number?: number;
        id?: string;
        name?: string;
        type?: "user" | "callQueue" | "commonArea";
        extension_status?: "inactive" | "deleted";
        extension_deleted_time?: string;
    };
    deleted_time?: string;
    days_left_auto_permantely_delete?: number;
    soft_deleted_type?: "Manual" | "Data Retention";
    recording_type?: "OnDemand" | "Automatic";
    file_url?: string;
    disclaimer_status?: 0 | 1 | 2;
};
type RecordingsDownloadPhoneRecordingPathParams = {
    fileId: string;
};
type RecordingsDownloadPhoneRecordingTranscriptPathParams = {
    recordingId: string;
};
type RecordingsGetCallRecordingsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    owner_type?: string;
    recording_type?: string;
    site_id?: string;
    query_date_type?: string;
    group_id?: string;
};
type RecordingsGetCallRecordingsResponse = {
    next_page_token?: string;
    page_size?: number;
    recordings?: {
        auto_delete_policy?: string;
        call_id?: string;
        call_log_id?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: 1 | 2 | 3;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        outgoing_by?: {
            name?: string;
            extension_number?: string;
        };
        accepted_by?: {
            name?: string;
            extension_number?: string;
        };
        date_time?: string;
        disclaimer_status?: 0 | 1 | 2;
        direction?: "inbound" | "outbound";
        download_url?: string;
        duration?: number;
        end_time?: string;
        id?: string;
        meeting_uuid?: string;
        owner?: {
            extension_number?: number;
            id?: string;
            name?: string;
            type?: "user" | "callQueue" | "commonArea";
            extension_status?: "inactive" | "deleted";
            extension_deleted_time?: string;
        };
        recording_type?: string;
        site?: {
            id?: string;
            name?: string;
        };
        transcript_download_url?: string;
        auto_delete_enable?: boolean;
    }[];
    total_records?: number;
};
type RecordingsDeleteCallRecordingPathParams = {
    recordingId: string;
};
type RecordingsUpdateAutoDeleteFieldPathParams = {
    recordingId: string;
};
type RecordingsUpdateAutoDeleteFieldRequestBody = {
    auto_delete_enable?: boolean;
};
type RecordingsUpdateRecordingStatusPathParams = {
    recordingId: string;
};
type RecordingsUpdateRecordingStatusRequestBody = {
    action?: "recover";
};
type RecordingsGetUsersRecordingsPathParams = {
    userId: string;
};
type RecordingsGetUsersRecordingsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
};
type RecordingsGetUsersRecordingsResponse = {
    from?: string;
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    recordings?: {
        call_id?: string;
        call_log_id?: string;
        call_history_id?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: 1 | 2 | 3;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        outgoing_by?: {
            name?: string;
            extension_number?: string;
        };
        accepted_by?: {
            name?: string;
            extension_number?: string;
        };
        date_time?: string;
        direction?: string;
        download_url?: string;
        duration?: number;
        id?: string;
        meeting_uuid?: string;
        transcript_download_url?: string;
    }[];
    to?: string;
    total_records?: number;
};
type ReportsGetCallChargesUsageReportQueryParams = {
    from?: string;
    to?: string;
    page_size?: number;
    next_page_token?: string;
    billing_account_id?: string;
    show_charges_only?: boolean;
};
type ReportsGetCallChargesUsageReportResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    from?: string;
    to?: string;
    call_charges?: {
        call_log_id?: string;
        caller_number?: string;
        caller_billing_number?: string;
        callee_number?: string;
        callee_billing_number?: string;
        call_type?: "voip" | "local" | "tollfree" | "international" | "callCenter";
        service_type?: "meeting" | "call";
        calling_party_name?: string;
        cost_center?: string;
        employee_id?: string;
        department?: string;
        end_time?: string;
        duration?: number;
        charge_mode?: "per_min" | "per_call" | "per_call_per_min" | "per_min_after_t_duration" | "per_call_per_min_after_t_duration";
        rate?: string;
        currency?: string;
        total_charge?: string;
        billing_number?: string;
        forward_number_billing?: string;
    }[];
};
type ReportsGetOperationLogsReportQueryParams = {
    from?: string;
    to?: string;
    category_type?: string;
    page_size?: number;
    next_page_token?: string;
};
type ReportsGetOperationLogsReportResponse = {
    next_page_token?: string;
    page_size?: number;
} & {
    total_records?: number;
    from?: string;
    to?: string;
} & {
    operation_logs?: {
        action?: string;
        category_type?: string;
        operation_detail?: string;
        operator?: string;
        time?: string;
    }[];
};
type ReportsGetSMSMMSChargesUsageReportQueryParams = {
    from?: string;
    to?: string;
    page_size?: number;
    next_page_token?: string;
    show_charges_only?: boolean;
};
type ReportsGetSMSMMSChargesUsageReportResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    from?: string;
    to?: string;
    sms_charges?: {
        session_id?: string;
        message_id?: string;
        message_type?: string;
        from_number?: string;
        from_extension_number?: string;
        from_display_name?: string;
        to_number?: string;
        to_extension_number?: string;
        to_display_name?: string;
        sent_time?: string;
        billing_number?: string;
        cost_center?: string;
        department?: string;
        rate?: string;
        currency?: string;
        total_charge?: string;
    }[];
};
type RoutingRulesListDirectoryBackupRoutingRulesQueryParams = {
    site_id?: string;
};
type RoutingRulesListDirectoryBackupRoutingRulesResponse = {
    name?: string;
    number_pattern?: string;
    order?: number;
    routing_path?: {
        sip_group?: {
            id?: string;
            name?: string;
        };
        type?: "other_sites" | "pstn" | "sip_group";
    };
    routing_rule_id?: string;
    site_id?: string;
    translation?: string;
}[];
type RoutingRulesAddDirectoryBackupRoutingRuleRequestBody = {
    name?: string;
    number_pattern?: string;
    sip_group_id?: string;
    site_id?: string;
    translation?: string;
    type?: "other_sites" | "pstn" | "sip_group";
};
type RoutingRulesAddDirectoryBackupRoutingRuleResponse = {
    name?: string;
    routing_rule_id?: string;
};
type RoutingRulesGetDirectoryBackupRoutingRulePathParams = {
    routingRuleId: string;
};
type RoutingRulesGetDirectoryBackupRoutingRuleResponse = {
    name?: string;
    number_pattern?: string;
    order?: number;
    routing_path?: {
        sip_group?: {
            id?: string;
            name?: string;
        };
        type?: "other_sites" | "pstn" | "sip_group";
    };
    routing_rule_id?: string;
    site_id?: string;
    translation?: string;
};
type RoutingRulesDeleteDirectoryBackupRoutingRulePathParams = {
    routingRuleId: string;
};
type RoutingRulesUpdateDirectoryBackupRoutingRulePathParams = {
    routingRuleId: string;
};
type RoutingRulesUpdateDirectoryBackupRoutingRuleRequestBody = {
    name?: string;
    number_pattern?: string;
    order?: number;
    sip_group_id?: string;
    translation?: string;
    type?: "other_sites" | "pstn" | "sip_group";
};
type SMSPostSMSMessageRequestBody = {
    attachments?: {
        base64_encoding?: string;
        type?: string;
    }[];
    message?: string;
    sender?: {
        id?: string;
        user_id?: string;
        phone_number: string;
    };
    session_id?: string;
    to_members: {
        phone_number?: string;
    }[];
};
type SMSPostSMSMessageResponse = {
    date_time?: string;
    message_id?: string;
    session_id?: string;
};
type SMSGetAccountsSMSSessionsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    session_type?: string;
    phone_number?: string;
    filter_type?: "sent_message_time" | "received_message_time" | "last_message_time" | "sent_received_message_time";
};
type SMSGetAccountsSMSSessionsResponse = {
    next_page_token?: string;
    page_size?: number;
    sms_sessions?: {
        last_access_time?: string;
        participants?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            };
            phone_number?: string;
            is_session_owner?: boolean;
            extension_status?: "inactive" | "deleted";
            extension_deleted_time?: string;
        }[];
        session_id?: string;
        session_type?: string;
    }[];
};
type SMSGetSMSSessionDetailsPathParams = {
    sessionId: string;
};
type SMSGetSMSSessionDetailsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    sort?: number;
};
type SMSGetSMSSessionDetailsResponse = {
    next_page_token?: string;
    page_size?: number;
    sms_histories?: {
        attachments?: {
            download_url?: string;
            id?: string;
            name?: string;
            size?: number;
            type?: "OTHER" | "PNG" | "GIF" | "JPG" | "AUDIO" | "VIDEO";
        }[];
        date_time?: string;
        direction?: string;
        message?: string;
        message_id?: string;
        message_type?: 1 | 2 | 3 | 4 | 5 | 6;
        sender?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            };
            phone_number: string;
        };
        to_members?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            };
            phone_number: string;
        }[];
    }[];
};
type SMSGetSMSByMessageIDPathParams = {
    sessionId: string;
    messageId: string;
};
type SMSGetSMSByMessageIDResponse = {
    attachments?: {
        download_url?: string;
        id?: string;
        name?: string;
        size?: number;
        type?: "OTHER" | "PNG" | "GIF" | "JPG" | "AUDIO" | "VIDEO";
    }[];
    date_time?: string;
    direction?: string;
    message?: string;
    message_id?: string;
    message_type?: 1 | 2 | 3 | 4 | 5 | 6;
    sender?: {
        display_name?: string;
        owner?: {
            id?: string;
            type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
        };
        phone_number: string;
    };
    to_members?: {
        display_name?: string;
        owner?: {
            id?: string;
            type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
        };
        phone_number: string;
    }[];
};
type SMSSyncSMSBySessionIDPathParams = {
    sessionId: string;
};
type SMSSyncSMSBySessionIDQueryParams = {
    sync_type?: "FSync" | "ISync" | "BSync";
    count?: number;
    sync_token?: string;
};
type SMSSyncSMSBySessionIDResponse = {
    sms_histories?: {
        attachments?: {
            download_url?: string;
            id?: string;
            name?: string;
            size?: number;
            type?: "OTHER" | "PNG" | "GIF" | "JPG" | "AUDIO" | "VIDEO";
        }[];
        date_time?: string;
        direction?: string;
        message?: string;
        message_id?: string;
        message_type?: 1 | 2 | 3 | 4 | 5 | 6;
        sender?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            };
            phone_number: string;
        };
        to_members?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            };
            phone_number: string;
        }[];
    }[];
    sync_token?: string;
};
type SMSGetUsersSMSSessionsPathParams = {
    userId: string;
};
type SMSGetUsersSMSSessionsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    session_type?: string;
    from?: string;
    to?: string;
    phone_number?: string;
    filter_type?: "sent_message_time" | "received_message_time" | "last_message_time" | "sent_received_message_time";
};
type SMSGetUsersSMSSessionsResponse = {
    next_page_token?: string;
    page_size?: number;
    sms_sessions?: {
        last_access_time?: string;
        participants?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            };
            phone_number?: string;
            is_session_owner?: boolean;
        }[];
        session_id?: string;
        session_type?: string;
    }[];
};
type SMSListUsersSMSSessionsInDescendingOrderPathParams = {
    userId: string;
};
type SMSListUsersSMSSessionsInDescendingOrderQueryParams = {
    sync_type: "FSync" | "BSync" | "ISync";
    sync_token?: string;
    count?: number;
    session_type?: string;
};
type SMSListUsersSMSSessionsInDescendingOrderResponse = {
    sms_sessions?: {
        last_access_time?: string;
        latest_message?: {
            attachments?: {
                id?: string;
                type?: "OTHER" | "PNG" | "GIF" | "JPG/JPEG" | "AUDIO" | "VIDEO";
            }[];
            date_time?: string;
            direction?: string;
            message?: string;
            message_id?: string;
            message_type?: 1 | 2 | 3 | 4 | 5 | 6;
            sender?: {
                display_name?: string;
                owner?: {
                    id?: string;
                    type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
                };
                phone_number: string;
            };
            to_members?: {
                display_name?: string;
                owner?: {
                    id?: string;
                    type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
                };
                phone_number: string;
            }[];
        };
        participants?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            };
            phone_number?: string;
            is_session_owner?: boolean;
        }[];
        session_id?: string;
        session_type?: string;
        unread_message_count?: number;
    }[];
    sync_token?: string;
};
type SMSCampaignListSMSCampaignsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type SMSCampaignListSMSCampaignsResponse = {
    next_page_token?: string;
    page_size?: number;
    sms_campaigns?: {
        id?: string;
        display_name?: string;
        status?: "draft" | "active" | "expired" | "pending" | "declined" | "--";
        brand?: {
            id?: string;
            name?: string;
        };
    }[];
    total_records?: number;
};
type SMSCampaignGetSMSCampaignPathParams = {
    smsCampaignId: string;
};
type SMSCampaignGetSMSCampaignResponse = {
    id?: string;
    display_name?: string;
    status?: "draft" | "active" | "expired" | "pending" | "declined" | "--";
    service_type?: "zoomPhone" | "contactCenter";
    brand?: {
        id?: string;
        name?: string;
    };
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
    auto_renew?: boolean;
    create_time?: string;
    use_case?: "lowVolumeMixed";
    categories_fit?: boolean;
    content_type?: ("urlLink" | "phoneNumber" | "ageGated" | "lending")[];
    sample_message_1?: string;
    sample_message_2?: string;
    sample_message_3?: string;
    sample_message_4?: string;
    sample_message_5?: string;
};
type SMSCampaignAssignPhoneNumberToSMSCampaignPathParams = {
    smsCampaignId: string;
};
type SMSCampaignAssignPhoneNumberToSMSCampaignRequestBody = {
    phone_numbers: {
        id?: string;
        number?: string;
    }[];
    loa_authorizing_person: string;
    contact_number: string;
    title: string;
    contact_emails?: string;
};
type SMSCampaignAssignPhoneNumberToSMSCampaignResponse = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams = {
    smsCampaignId: string;
};
type SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignQueryParams = {
    consumer_phone_number: string;
    zoom_phone_user_numbers: string[];
};
type SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignResponse = {
    phone_number_campaign_opt_statuses: {
        consumer_phone_number: string;
        zoom_phone_user_number: string;
        opt_status: "pending" | "opt_out" | "opt_in";
    }[];
};
type SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams = {
    smsCampaignId: string;
};
type SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignRequestBody = {
    consumer_phone_number: string;
    zoom_phone_user_numbers: string[];
    opt_status: "opt_in" | "opt_out";
};
type SMSCampaignUnassignPhoneNumberPathParams = {
    smsCampaignId: string;
    phoneNumberId: string;
};
type SMSCampaignListUsersOptStatusesOfPhoneNumbersPathParams = {
    userId: string;
};
type SMSCampaignListUsersOptStatusesOfPhoneNumbersQueryParams = {
    consumer_phone_numbers: string[];
    zoom_phone_user_numbers: string[];
};
type SMSCampaignListUsersOptStatusesOfPhoneNumbersResponse = {
    phone_number_campaign_opt_statuses: {
        consumer_phone_number: string;
        zoom_phone_user_number: string;
        opt_status: "pending" | "opt_out" | "opt_in";
    }[];
};
type SettingTemplatesListSettingTemplatesQueryParams = {
    page_size?: number;
    next_page_token?: string;
    site_id?: string;
};
type SettingTemplatesListSettingTemplatesResponse = {
    next_page_token?: string;
    page_size?: number;
    templates?: {
        description?: string;
        id?: string;
        name?: string;
        type?: "user" | "group" | "autReceptionist" | "commonArea" | "zr" | "interop";
    }[];
    total_records?: number;
};
type SettingTemplatesAddSettingTemplateRequestBody = {
    description?: string;
    name: string;
    site_id?: string;
    type: string;
};
type SettingTemplatesAddSettingTemplateResponse = {
    description?: string;
    id?: string;
    name?: string;
    type?: string;
};
type SettingTemplatesGetSettingTemplateDetailsPathParams = {
    templateId: string;
};
type SettingTemplatesGetSettingTemplateDetailsQueryParams = {
    custom_query_fields?: string;
};
type SettingTemplatesGetSettingTemplateDetailsResponse = {
    description?: string;
    id?: string;
    name?: string;
    policy?: {
        ad_hoc_call_recording?: {
            enable?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
        };
        auto_call_recording?: {
            enable?: boolean;
            recording_calls?: string;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            inbound_audio_notification?: {
                recording_start_prompt?: boolean;
            };
            outbound_audio_notification?: {
                recording_start_prompt?: boolean;
            };
        };
        sms?: {
            enable?: boolean;
            international_sms?: boolean;
        };
        voicemail?: {
            allow_transcription?: boolean;
            enable?: boolean;
        };
        call_forwarding?: {
            enable?: boolean;
            call_forwarding_type?: 1 | 2 | 3 | 4;
        };
        call_overflow?: {
            enable?: boolean;
            call_overflow_type?: 1 | 2 | 3 | 4;
        };
    };
    profile?: {
        area_code?: string;
        country?: string;
    };
    type?: "user" | "group" | "autoReceptionist" | "commonArea" | "zr" | "interop";
    user_settings?: {
        audio_prompt_language?: string;
        block_calls_without_caller_id?: boolean;
        call_handling?: {
            business_hours?: {
                business_hour_action?: 0 | 1 | 9 | 11 | 26 | 50;
                connect_to_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: "user" | "zoomRoom" | "commonArea" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                busy_action?: 0 | 1 | 11 | 12 | 13 | 26 | 50;
                busy_connect_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: "user" | "zoomRoom" | "commonAreaPhone" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                custom_hours?: {
                    from?: string;
                    to?: string;
                    type?: 1 | 2;
                    weekday?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
                }[];
                ring_type?: string;
                ringing_duration?: "10" | "15" | "20" | "25" | "30" | "35" | "40" | "45" | "50" | "55" | "60";
                type?: 1 | 2;
            };
            close_hours?: {
                close_hour_action?: 0 | 1 | 9 | 11 | 26 | 50;
                connect_to_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: "user" | "zoomRoom" | "commonAreaPhone" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                busy_action?: 0 | 1 | 11 | 12 | 13 | 26 | 50;
                busy_connect_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: "user" | "zoomRoom" | "commonArea" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                max_wait_time?: "10" | "15" | "20" | "25" | "30" | "35" | "40" | "45" | "50" | "55" | "60";
            };
        };
        desk_phone?: {
            pin_code?: string;
        };
        hold_music?: "default" | "disable";
    };
};
type SettingTemplatesUpdateSettingTemplatePathParams = {
    templateId: string;
};
type SettingTemplatesUpdateSettingTemplateRequestBody = {
    description?: string;
    name?: string;
    policy?: {
        ad_hoc_call_recording?: {
            enable?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
        };
        auto_call_recording?: {
            enable?: boolean;
            recording_calls?: "inbound" | "outbound" | "both";
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            inbound_audio_notification?: {
                recording_start_prompt?: boolean;
            };
            outbound_audio_notification?: {
                recording_start_prompt?: boolean;
            };
        };
        sms?: {
            enable?: boolean;
            international_sms?: boolean;
        };
        voicemail?: {
            allow_transcription?: boolean;
            enable?: boolean;
        };
        call_forwarding?: {
            enable?: boolean;
            call_forwarding_type?: 1 | 2 | 3 | 4;
        };
        call_overflow?: {
            enable?: boolean;
            call_overflow_type?: 1 | 2 | 3 | 4;
        };
    };
    profile?: {
        area_code?: string;
        country?: string;
    };
    user_settings?: {
        audio_prompt_language?: string;
        block_calls_without_caller_id?: boolean;
        call_handling?: {
            business_hours?: {
                business_hour_action?: 0 | 1 | 9 | 11 | 26 | 50;
                connect_to_operator?: {
                    enable?: boolean;
                    id?: string;
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                busy_action?: 0 | 1 | 11 | 12 | 13 | 26 | 50;
                busy_connect_operator?: {
                    enable?: boolean;
                    id?: string;
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                custom_hours?: {
                    from?: string;
                    to?: string;
                    type?: 1 | 2;
                    weekday?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
                }[];
                ring_type?: string;
                ringing_duration?: "10" | "15" | "20" | "25" | "30" | "35" | "40" | "45" | "50" | "55" | "60";
                type?: 1 | 2;
            };
            close_hours?: {
                close_hour_action?: 0 | 1 | 9 | 11 | 26 | 50;
                connect_to_operator?: {
                    enable?: boolean;
                    id?: string;
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                busy_action?: 0 | 1 | 11 | 12 | 13 | 26 | 50;
                busy_connect_operator?: {
                    enable?: boolean;
                    id?: string;
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                max_wait_time?: "10" | "15" | "20" | "25" | "30" | "35" | "40" | "45" | "50" | "55" | "60";
            };
        };
        desk_phone?: {
            pin_code?: string;
        };
        hold_music?: "default" | "disable";
    };
};
type SettingsGetAccountPolicyDetailsPathParams = {
    policyType: "allow_emergency_calls";
};
type SettingsGetAccountPolicyDetailsResponse = {
    allow_emergency_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account";
        allow_emergency_calls_from_clients?: boolean;
        allow_emergency_calls_from_deskphones?: boolean;
    };
};
type SettingsUpdateAccountPolicyPathParams = {
    policyType: "allow_emergency_calls";
};
type SettingsUpdateAccountPolicyRequestBody = {
    allow_emergency_calls?: {
        enable?: boolean;
        locked?: boolean;
        allow_emergency_calls_from_clients?: boolean;
        allow_emergency_calls_from_deskphones?: boolean;
    };
};
type SettingsListPortedNumbersQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type SettingsListPortedNumbersResponse = {
    next_page_token?: string;
    page_size?: number;
    ported_numbers?: {
        numbers?: string[];
        order_id?: string;
        replacing_numbers?: {
            source_number?: string;
            target_number?: string;
        }[];
        status?: "Not_Submitted" | "Waiting" | "Processing" | "Successfully" | "Rejected" | "Canceled" | "FOC";
        submission_date_time?: string;
    }[];
    total_records?: number;
};
type SettingsGetPortedNumberDetailsPathParams = {
    orderId: string;
};
type SettingsGetPortedNumberDetailsResponse = {
    contact_emails?: string;
    contact_number?: string;
    isp?: string;
    numbers?: string[];
    order_id?: string;
    original_billing_info?: {
        account_number?: string;
        address?: {
            city?: string;
            country?: string;
            house_number?: string;
            state_code?: string;
            street_name?: string;
            zip?: string;
        };
        authorizing_person?: string;
        billing_telephone_number?: string;
        company?: string;
        customer_requested_date?: string;
        pin?: string;
    };
    printed_name?: string;
    replacing_numbers?: {
        source_number?: string;
        target_number?: string;
    }[];
    status?: "Not_Submitted" | "Waiting" | "Processing" | "Successfully" | "Rejected" | "Canceled" | "FOC";
    submission_date_time?: string;
};
type SettingsGetPhoneAccountSettingsResponse = {
    byoc?: {
        enable?: boolean;
    };
    country?: {
        code?: string;
        name?: string;
    };
    multiple_sites?: {
        enabled?: boolean;
        site_code?: boolean;
    };
    show_device_ip_for_call_log?: {
        enable?: boolean;
    };
    multiple_party_conference?: {
        enable?: boolean;
    };
    billing_account?: {
        id?: string;
        name?: string;
    };
};
type SettingsUpdatePhoneAccountSettingsRequestBody = {
    byoc?: {
        enable?: boolean;
    };
    multiple_sites?: {
        enabled?: boolean;
        site_code?: {
            enable?: boolean;
            short_extension_length?: number;
        };
    };
    show_device_ip_for_call_log?: {
        enable?: boolean;
    };
    billing_account?: {
        id?: string;
    };
};
type SettingsListSIPGroupsQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type SettingsListSIPGroupsResponse = {
    next_page_token?: string;
    page_size?: number;
    sip_groups?: {
        description?: string;
        display_name?: string;
        id?: string;
        send_sip_group_name?: boolean;
        sip_trunk?: {
            id?: string;
            name?: string;
        };
    }[];
};
type SettingsListBYOCSIPTrunksQueryParams = {
    next_page_token?: string;
    page_size?: number;
};
type SettingsListBYOCSIPTrunksResponse = {
    byoc_sip_trunk?: {
        carrier?: string;
        carrier_account?: string;
        id?: string;
        name?: string;
        region?: string;
        sbc_label?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type SharedLineAppearanceListSharedLineAppearancesQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type SharedLineAppearanceListSharedLineAppearancesResponse = {
    next_page_token?: string;
    page_size?: number;
    shared_line_appearances?: {
        executive?: {
            name?: string;
            extension_number?: number;
            extension_type?: "user" | "commonArea";
        };
        assistants?: {
            id?: string;
            name?: string;
            extension_number?: number;
            extension_type?: "user" | "commonArea";
        }[];
        privileges?: ("place_calls" | "answer_calls" | "pickup_hold_calls")[];
    }[];
    total_records?: number;
};
type SharedLineGroupListSharedLineGroupsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type SharedLineGroupListSharedLineGroupsResponse = {
    next_page_token?: string;
    page_size?: number;
    shared_line_groups?: {
        display_name?: string;
        extension_id?: string;
        extension_number?: number;
        id?: string;
        phone_numbers?: {
            id?: string;
            number?: string;
            status?: "pending" | "available";
        }[];
        site?: {
            id?: string;
            name?: string;
        };
        status?: "active" | "inactive";
    }[];
    total_records?: number;
};
type SharedLineGroupCreateSharedLineGroupRequestBody = {
    description?: string;
    display_name: string;
    extension_number?: number;
    site_id?: string;
};
type SharedLineGroupCreateSharedLineGroupResponse = {
    id?: string;
    display_name?: string;
};
type SharedLineGroupGetSharedLineGroupPathParams = {
    sharedLineGroupId: string;
};
type SharedLineGroupGetSharedLineGroupResponse = {
    display_name?: string;
    extension_id?: string;
    extension_number?: number;
    id?: string;
    members?: {
        users?: {
            id?: string;
            name?: string;
            extension_id?: string;
        }[];
        common_areas?: {
            id?: string;
            name?: string;
            extension_id?: string;
        }[];
    };
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
    primary_number?: string;
    site?: {
        id?: string;
        name?: string;
    };
    status?: "active" | "inactive";
    timezone?: string;
    policy?: {
        voicemail_access_members?: (({
            access_user_id?: string;
            allow_download?: boolean;
            allow_delete?: boolean;
            allow_sharing?: boolean;
        } & {
            shared_id?: string;
        }) & {
            access_user_type?: "user" | "commonArea";
        })[];
    };
    cost_center?: string;
    department?: string;
    audio_prompt_language?: "en-US" | "en-GB" | "es-US" | "fr-CA" | "da-DK" | "de-DE" | "es-ES" | "fr-FR" | "it-IT" | "nl-NL" | "pt-PT" | "ja" | "ko-KR" | "pt-BR" | "zh-CN";
    recording_storage_location?: "US" | "AU" | "CA" | "DE" | "IN" | "JP" | "SG" | "BR" | "CN" | "MX";
    own_storage_name?: string;
    allow_privacy?: boolean;
};
type SharedLineGroupGetSharedLineGroupPolicyPathParams = {
    sharedLineGroupId: string;
};
type SharedLineGroupGetSharedLineGroupPolicyResponse = {
    check_voicemails_over_phone?: {
        enable: boolean;
        locked: boolean;
        locked_by?: "invalid" | "account" | "site";
        modified?: boolean;
    };
};
type SharedLineGroupUpdateSharedLineGroupPolicyPathParams = {
    sharedLineGroupId: string;
};
type SharedLineGroupUpdateSharedLineGroupPolicyRequestBody = {
    check_voicemails_over_phone?: {
        enable?: boolean;
        reset?: boolean;
    };
};
type SharedLineGroupDeleteSharedLineGroupPathParams = {
    slgId: string;
};
type SharedLineGroupUpdateSharedLineGroupPathParams = {
    slgId: string;
};
type SharedLineGroupUpdateSharedLineGroupRequestBody = {
    display_name?: string;
    extension_number?: number;
    primary_number?: string;
    status?: "active" | "inactive";
    timezone?: string;
    cost_center?: string;
    department?: string;
    audio_prompt_language?: "en-US" | "en-GB" | "es-US" | "fr-CA" | "da-DK" | "de-DE" | "es-ES" | "fr-FR" | "it-IT" | "nl-NL" | "pt-PT" | "ja" | "ko-KR" | "pt-BR" | "zh-CN";
    recording_storage_location?: "US" | "AU" | "CA" | "DE" | "IN" | "JP" | "SG" | "BR" | "CN" | "MX";
    allow_privacy?: boolean;
};
type SharedLineGroupAddMembersToSharedLineGroupPathParams = {
    slgId: string;
};
type SharedLineGroupAddMembersToSharedLineGroupRequestBody = {
    members?: {
        common_area_ids?: string[];
        users?: {
            email?: string;
            id?: string;
        }[];
    };
};
type SharedLineGroupUnassignMembersFromSharedLineGroupPathParams = {
    slgId: string;
};
type SharedLineGroupUnassignMemberFromSharedLineGroupPathParams = {
    slgId: string;
    memberId: string;
};
type SharedLineGroupAssignPhoneNumbersPathParams = {
    slgId: string;
};
type SharedLineGroupAssignPhoneNumbersRequestBody = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type SharedLineGroupUnassignAllPhoneNumbersPathParams = {
    slgId: string;
};
type SharedLineGroupUnassignPhoneNumberPathParams = {
    slgId: string;
    phoneNumberId: string;
};
type SharedLineGroupAddPolicySettingToSharedLineGroupPathParams = {
    slgId: string;
    policyType: string;
};
type SharedLineGroupAddPolicySettingToSharedLineGroupRequestBody = {
    voicemail_access_members?: {
        access_user_id?: string;
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_sharing?: boolean;
    }[];
};
type SharedLineGroupAddPolicySettingToSharedLineGroupResponse = {
    voicemail_access_members?: (({
        access_user_id?: string;
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_sharing?: boolean;
    } & {
        shared_id?: string;
    }) & {
        access_user_type?: "user" | "commonArea";
    })[];
};
type SharedLineGroupDeleteSLGPolicySettingPathParams = {
    slgId: string;
    policyType: string;
};
type SharedLineGroupDeleteSLGPolicySettingQueryParams = {
    shared_ids: string[];
};
type SharedLineGroupUpdateSLGPolicySettingPathParams = {
    slgId: string;
    policyType: string;
};
type SharedLineGroupUpdateSLGPolicySettingRequestBody = {
    voicemail_access_members?: ({
        access_user_id?: string;
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_sharing?: boolean;
    } & {
        shared_id?: string;
    })[];
};
type SitesListPhoneSitesQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type SitesListPhoneSitesResponse = {
    next_page_token?: string;
    page_size?: number;
    sites?: {
        country?: {
            code?: string;
            name?: string;
        };
        id?: string;
        main_auto_receptionist?: {
            extension_id?: string;
            extension_number?: number;
            id?: string;
            name?: string;
        };
        name?: string;
        site_code?: number;
    }[];
    total_records?: number;
};
type SitesCreatePhoneSiteRequestBody = {
    auto_receptionist_name: string;
    source_auto_receptionist_id?: string;
    default_emergency_address: {
        address_line1: string;
        address_line2?: string;
        city: string;
        country: string;
        state_code: string;
        zip: string;
    };
    name: string;
    short_extension?: {
        length?: number;
    };
    site_code?: number;
    sip_zone?: {
        id?: string;
    };
    force_off_net?: {
        enable?: boolean;
        allow_extension_only_users_call_users_outside_site?: boolean;
    };
    india_state_code?: string;
    india_city?: string;
    india_sdca_npa?: string;
    india_entity_name?: string;
};
type SitesCreatePhoneSiteResponse = {
    id?: string;
    name?: string;
};
type SitesGetPhoneSiteDetailsPathParams = {
    siteId: string;
};
type SitesGetPhoneSiteDetailsResponse = {
    country?: {
        code?: string;
        name?: string;
    };
    id?: string;
    main_auto_receptionist?: {
        extension_id?: string;
        extension_number?: number;
        id?: string;
        name?: string;
    };
    name?: string;
    short_extension?: {
        length?: number;
    };
    site_code?: number;
    policy?: {
        select_outbound_caller_id?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            allow_hide_outbound_caller_id?: boolean;
        };
        personal_audio_library?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            allow_music_on_hold_customization?: boolean;
            allow_voicemail_and_message_greeting_customization?: boolean;
        };
        voicemail?: {
            allow_delete?: boolean;
            allow_download?: boolean;
            allow_videomail?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        voicemail_transcription?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        voicemail_notification_by_email?: {
            include_voicemail_file?: boolean;
            include_voicemail_transcription?: boolean;
            forward_voicemail_to_email?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        shared_voicemail_notification_by_email?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        international_calling?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        zoom_phone_on_mobile?: {
            allow_calling_clients?: ("ios" | "android" | "intune" | "blackberry")[];
            allow_sms_mms_clients?: ("ios" | "android" | "intune" | "blackberry")[];
            allow_calling_sms_mms?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        sms?: {
            enable?: boolean;
            international_sms?: boolean;
            international_sms_countries?: string[];
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            allow_copy?: boolean;
            allow_paste?: boolean;
        };
        elevate_to_meeting?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        hand_off_to_room?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        mobile_switch_to_carrier?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        delegation?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        ad_hoc_call_recording?: {
            enable?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        auto_call_recording?: {
            allow_stop_resume_recording?: boolean;
            disconnect_on_recording_failure?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            recording_calls?: "inbound" | "outbound" | "both";
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
            inbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
            outbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
        };
        call_handling_forwarding_to_other_users?: {
            enable?: boolean;
            call_forwarding_type?: 1 | 2 | 3 | 4;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        check_voicemails_over_phone?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        call_queue_pickup_code?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        call_queue_opt_out_reason?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            call_queue_opt_out_reasons_list?: {
                code?: string;
                system?: boolean;
                enable?: boolean;
            }[];
        };
        show_user_last_transferred_call?: boolean;
        auto_delete_data_after_retention_duration?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            items?: {
                type?: "callLog" | "onDemandRecording" | "automaticRecording" | "voicemail" | "videomail" | "sms";
                duration?: number;
                time_unit?: "year" | "month" | "day";
            }[];
            delete_type?: 1 | 2;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
            forward_to?: {
                display_name?: string;
                extension_id?: string;
                extension_number?: number;
                extension_type?: "user" | "zoomRoom" | "commonArea" | "ciscoRoom/polycomRoom" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                id?: string;
            };
            sequence?: 0 | 1;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        call_overflow?: {
            call_overflow_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        call_transferring?: {
            call_transferring_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        audio_intercom?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        block_calls_without_caller_id?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        block_external_calls?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            block_business_hours?: boolean;
            block_closed_hours?: boolean;
            block_holiday_hours?: boolean;
            block_call_action?: 0 | 9;
            block_call_change_type?: 0 | 1;
            e2e_encryption?: {
                enable?: boolean;
                locked?: boolean;
                locked_by?: "invalid" | "account" | "site";
                modified?: boolean;
            };
        };
        force_off_net?: {
            enable?: boolean;
            allow_extension_only_users_call_users_outside_site?: boolean;
        };
        external_calling_on_zoom_room_common_area?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        zoom_phone_on_pwa?: {
            allow_calling?: boolean;
            allow_sms_mms?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        sms_auto_reply?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        allow_end_user_edit_call_handling?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        allow_caller_reach_operator?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        forward_call_outside_of_site?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        allow_mobile_home_phone_callout?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        obfuscate_sensitive_data_during_call?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        prevent_users_upload_audio_files?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        voicemail_tasks?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        voicemail_intent_based_prioritization?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        team_sms_thread_summary?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
        display_call_feedback_survey?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            feedback_type?: 1 | 2;
            feedback_mos?: {
                enable?: boolean;
                min?: number;
                max?: number;
            };
            feedback_duration?: {
                enable?: boolean;
                min?: number;
                max?: number;
            };
        };
        call_live_transcription?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            transcription_start_prompt?: {
                enable?: boolean;
                audio_id?: string;
                audio_name?: string;
            };
        };
        call_screening?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            exclude_user_company_contacts?: boolean;
        };
        sms_template?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            sms_template_list?: {
                sms_template_id?: string;
                name?: string;
                description?: string;
                content?: string;
                active?: boolean;
            }[];
        };
        advanced_encryption?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            disable_incoming_unencrypted_voicemail?: boolean;
        };
        customize_line_name?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            user_line_name?: "phoneNumber" | "extensionNumber" | "displayName" | "displayName;extensionNumber" | "firstName;extensionNumber" | "firstName;lastName;extensionNumber";
            common_area_line_name?: "phoneNumber" | "extensionNumber" | "displayName" | "displayName;extensionNumber";
        };
        auto_opt_out_in_call_queue?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            prompt_before_opt_out_call_queue?: boolean;
        };
        incoming_call_notification?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            block_type?: "block_activity" | "continue_with_alert";
        };
        call_summary?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
            auto_call_summary?: boolean;
            call_summary_start_prompt?: {
                enable?: boolean;
                audio_id?: string;
                audio_name?: string;
            };
        };
        schedule_firmware_update?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account";
            modified?: boolean;
            repeat_type?: "weekly" | "monthly";
            repeat_setting?: {
                weekly_setting?: {
                    weekday?: "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday";
                };
            } | ({
                week_and_day?: {
                    week_of_month?: number;
                    weekday?: "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday";
                };
            } | {
                specific_date?: {
                    day_of_month?: number;
                };
            });
            time_period_start?: number;
            time_period_end?: number;
            time_zone?: string;
            end_setting?: {
                never_end?: boolean;
                end_date?: string;
            };
        };
        zoom_phone_on_desktop?: {
            allow_calling_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
            allow_sms_mms_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
    };
    sip_zone?: {
        id?: string;
        name?: string;
    };
    caller_id_name?: string;
    india_state_code?: string;
    india_city?: string;
    india_sdca_npa?: string;
    india_entity_name?: string;
};
type SitesDeletePhoneSitePathParams = {
    siteId: string;
};
type SitesDeletePhoneSiteQueryParams = {
    transfer_site_id: string;
};
type SitesUpdatePhoneSiteDetailsPathParams = {
    siteId: string;
};
type SitesUpdatePhoneSiteDetailsRequestBody = {
    name?: string;
    site_code?: number;
    short_extension?: {
        length?: number;
        ranges?: {
            range_from?: string;
            range_to?: string;
        }[];
    };
    default_emergency_address?: {
        address_line1: string;
        address_line2?: string;
        city: string;
        country: string;
        state_code: string;
        zip: string;
    };
    sip_zone?: {
        id?: string;
    };
    caller_id_name?: string;
    policy?: {
        select_outbound_caller_id?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            allow_hide_outbound_caller_id?: boolean;
        };
        personal_audio_library?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            allow_music_on_hold_customization?: boolean;
            allow_voicemail_and_message_greeting_customization?: boolean;
        };
        voicemail?: {
            allow_delete?: boolean;
            allow_download?: boolean;
            allow_videomail?: boolean;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        voicemail_transcription?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        voicemail_notification_by_email?: {
            include_voicemail_file?: boolean;
            include_voicemail_transcription?: boolean;
            forward_voicemail_to_email?: boolean;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        shared_voicemail_notification_by_email?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        international_calling?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        zoom_phone_on_mobile?: {
            allow_calling_sms_mms?: boolean;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            allow_calling_clients?: ("ios" | "android" | "intune" | "blackberry")[];
            allow_sms_mms_clients?: ("ios" | "android" | "intune" | "blackberry")[];
        };
        sms?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            international_sms?: boolean;
            international_sms_countries?: string[];
            allow_copy?: boolean;
            allow_paste?: boolean;
        };
        elevate_to_meeting?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        hand_off_to_room?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        mobile_switch_to_carrier?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        delegation?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        ad_hoc_call_recording?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
        };
        auto_call_recording?: {
            allow_stop_resume_recording?: boolean;
            disconnect_on_recording_failure?: boolean;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            recording_calls?: "inbound" | "outbound" | "both";
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
            inbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
            outbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
        };
        call_handling_forwarding_to_other_users?: {
            enable?: boolean;
            call_forwarding_type?: 1 | 2 | 3 | 4;
            reset?: boolean;
            locked?: boolean;
        };
        check_voicemails_over_phone?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        call_queue_pickup_code?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        call_queue_opt_out_reason?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            call_queue_opt_out_reasons_list?: {
                code?: string;
                system?: boolean;
                enable?: boolean;
            }[];
        };
        show_user_last_transferred_call?: boolean;
        auto_delete_data_after_retention_duration?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            items?: {
                type?: "callLog" | "onDemandRecording" | "automaticRecording" | "voicemail" | "videomail" | "sms";
                duration?: number;
                time_unit?: "year" | "month" | "day";
            }[];
            delete_type?: 1 | 2;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
            forward_to_extension_id?: string;
            sequence?: 0 | 1;
        };
        call_overflow?: {
            call_overflow_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        call_transferring?: {
            call_transferring_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        audio_intercom?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        block_calls_without_caller_id?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        block_external_calls?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            block_business_hours?: boolean;
            block_closed_hours?: boolean;
            block_holiday_hours?: boolean;
            block_call_action?: 0 | 9;
            block_call_change_type?: 0 | 1;
            e2e_encryption?: {
                enable?: boolean;
                locked?: boolean;
                locked_by?: "invalid" | "account" | "site";
                modified?: boolean;
            };
        };
        force_off_net?: {
            enable?: boolean;
            allow_extension_only_users_call_users_outside_site?: boolean;
        };
        external_calling_on_zoom_room_common_area?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        zoom_phone_on_pwa?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            allow_calling?: boolean;
            allow_sms_mms?: boolean;
        };
        sms_auto_reply?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        allow_end_user_edit_call_handling?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        allow_caller_reach_operator?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        forward_call_outside_of_site?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        allow_mobile_home_phone_callout?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        obfuscate_sensitive_data_during_call?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        prevent_users_upload_audio_files?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        voicemail_tasks?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        voicemail_intent_based_prioritization?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        team_sms_thread_summary?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        display_call_feedback_survey?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            feedback_type?: 1 | 2;
            feedback_mos?: {
                enable?: boolean;
                min?: number;
                max?: number;
            };
            feedback_duration?: {
                enable?: boolean;
                min?: number;
                max?: number;
            };
        };
        call_live_transcription?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            transcription_start_prompt?: {
                enable?: boolean;
                audio_id?: string;
            };
        };
        call_screening?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            exclude_user_company_contacts?: boolean;
        };
        sms_template?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            sms_template_list?: {
                sms_template_id: string;
                active?: boolean;
            }[];
        };
        advanced_encryption?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            disable_incoming_unencrypted_voicemail?: boolean;
        };
        customize_line_name?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            user_line_name?: "phoneNumber" | "extensionNumber" | "displayName" | "displayName;extensionNumber" | "firstName;extensionNumber" | "firstName;lastName;extensionNumber";
            common_area_line_name?: "phoneNumber" | "extensionNumber" | "displayName" | "displayName;extensionNumber";
        };
        auto_opt_out_in_call_queue?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            prompt_before_opt_out_call_queue?: boolean;
        };
        incoming_call_notification?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            block_type?: "block_activity" | "continue_with_alert";
        };
        call_summary?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            auto_call_summary?: boolean;
            call_summary_start_prompt?: {
                enable?: boolean;
                audio_id?: string;
            };
        };
        schedule_firmware_update?: {
            enable?: boolean;
            reset?: boolean;
            repeat_type?: "weekly" | "monthly";
            repeat_setting?: {
                weekly_setting?: {
                    weekday?: "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday";
                };
            } | {
                monthly_setting?: {
                    week_and_day?: {
                        week_of_month?: number;
                        weekday?: "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday";
                    };
                } | {
                    specific_date?: {
                        day_of_month?: number;
                    };
                };
            };
            time_period_start?: number;
            time_period_end?: number;
            time_zone?: string;
            end_setting?: {
                never_end?: boolean;
                end_date?: string;
            };
        };
        zoom_phone_on_desktop?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            allow_calling_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
            allow_sms_mms_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
        };
    };
};
type SitesListCustomizedOutboundCallerIDPhoneNumbersPathParams = {
    siteId: string;
};
type SitesListCustomizedOutboundCallerIDPhoneNumbersQueryParams = {
    selected?: boolean;
    site_id?: string;
    extension_type?: "autoReceptionist" | "callQueue" | "sharedLineGroup";
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type SitesListCustomizedOutboundCallerIDPhoneNumbersResponse = {
    customize_numbers?: {
        customize_id?: string;
        phone_number_id?: string;
        phone_number?: string;
        display_name?: string;
        incoming?: boolean;
        outgoing?: boolean;
        extension_id?: string;
        extension_type?: string;
        extension_number?: string;
        extension_name?: string;
        site?: {
            id?: string;
            name?: string;
        };
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type SitesAddCustomizedOutboundCallerIDPhoneNumbersPathParams = {
    siteId: string;
};
type SitesAddCustomizedOutboundCallerIDPhoneNumbersRequestBody = {
    phone_number_ids?: string[];
};
type SitesAddCustomizedOutboundCallerIDPhoneNumbersResponse = never;
type SitesRemoveCustomizedOutboundCallerIDPhoneNumbersPathParams = {
    siteId: string;
};
type SitesRemoveCustomizedOutboundCallerIDPhoneNumbersQueryParams = {
    customize_ids?: string[];
};
type SitesGetPhoneSiteSettingPathParams = {
    siteId: string;
    settingType: "local_based_routing" | "business_hours" | "closed_hours" | "holiday_hours" | "security" | "outbound_caller_id" | "audio_prompt" | "desk_phone" | "dial_by_name" | "billing_account";
};
type SitesGetPhoneSiteSettingResponse = {
    location_based_routing?: {
        enable?: boolean;
        place_receive_pstn_calls?: boolean;
        enable_media_off_load_pstn_calls?: boolean;
    };
    business_hours?: {
        custom_hour_type?: 1 | 2;
        custom_hours?: {
            from?: string;
            to?: string;
            type?: 0 | 1 | 2;
            weekday?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
        }[];
        overflow?: {
            allow_caller_to_reach_operator?: boolean;
            operator?: {
                extension_id?: string;
                extension_number?: number;
                display_name?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "sharedLineGroup";
            };
            allow_caller_to_check_voicemail?: boolean;
        };
    };
    closed_hours?: {
        overflow?: {
            allow_caller_to_reach_operator?: boolean;
            operator?: {
                extension_id?: string;
                extension_number?: number;
                display_name?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "sharedLineGroup";
            };
            allow_caller_to_check_voicemail?: boolean;
        };
    };
    holiday_hours?: {
        holidays?: {
            holiday_id?: string;
            name?: string;
            from?: string;
            to?: string;
        }[];
        overflow?: {
            allow_caller_to_reach_operator?: boolean;
            operator?: {
                extension_id?: string;
                extension_number?: number;
                display_name?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "sharedLineGroup";
            };
            allow_caller_to_check_voicemail?: boolean;
        };
    };
    security?: {
        device_types?: string[];
    };
    outbound_caller_id?: {
        auto_receptionists_numbers?: boolean;
        call_queue_numbers?: boolean;
        share_line_group_numbers?: boolean;
        show_outbound_caller_id_for_internal_call?: boolean;
    };
    audio_prompt?: {
        language?: string;
        greeting_leave_voicemail_instruction?: {
            business_hours?: {
                audio_id?: string;
                name?: string;
            };
            closed_hours?: {
                audio_id?: string;
                name?: string;
            };
            holiday_hours?: {
                audio_id?: string;
                name?: string;
            };
        };
        greeting_menu_leave_or_check_voicemail?: {
            business_hours?: {
                audio_id?: string;
                name?: string;
            };
            closed_hours?: {
                audio_id?: string;
                name?: string;
            };
            holiday_hours?: {
                audio_id?: string;
                name?: string;
            };
        };
        greeting_menu_connect_to_operator_or_leave_voicemail?: {
            business_hours?: {
                audio_id?: string;
                name?: string;
            };
            closed_hours?: {
                audio_id?: string;
                name?: string;
            };
            holiday_hours?: {
                audio_id?: string;
                name?: string;
            };
        };
        greeting_menu_connect_to_operator_leave_or_check_voicemail?: {
            business_hours?: {
                audio_id?: string;
                name?: string;
            };
            closed_hours?: {
                audio_id?: string;
                name?: string;
            };
            holiday_hours?: {
                audio_id?: string;
                name?: string;
            };
        };
        leave_voicemail_introduction?: {
            business_hours?: {
                audio_id?: string;
                name?: string;
            };
            closed_hours?: {
                audio_id?: string;
                name?: string;
            };
            holiday_hours?: {
                audio_id?: string;
                name?: string;
            };
        };
        message_greeting?: {
            business_hours?: {
                audio_id?: string;
                name?: string;
            };
            closed_hours?: {
                audio_id?: string;
                name?: string;
            };
            holiday_hours?: {
                audio_id?: string;
                name?: string;
            };
        };
        audio_while_connecting?: {
            audio_id?: string;
            name?: string;
        };
        hold_music?: {
            audio_id?: string;
            name?: string;
        };
    };
    desk_phone?: {
        hot_desking_session_timeout?: {
            number: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 30;
            unit?: "minutes" | "hours";
        };
        general_setting?: {
            setting_type?: "account_setting" | "custom_setting";
            web_interface?: boolean;
        };
    };
    dial_by_name?: {
        status?: boolean;
        inherit?: boolean;
        rule?: "first_name" | "last_name";
    };
    billing_account?: {
        id?: string;
        name?: string;
    };
};
type SitesAddSiteSettingPathParams = {
    siteId: string;
    settingType: "holiday_hours" | "security";
};
type SitesAddSiteSettingRequestBody = {
    device_type?: string;
    holidays?: {
        name?: string;
        from?: string;
        to?: string;
    }[];
};
type SitesAddSiteSettingResponse = {
    holidays?: {
        holiday_id?: string;
        name?: string;
        from?: string;
        to?: string;
    }[];
};
type SitesDeleteSiteSettingPathParams = {
    siteId: string;
    settingType: "holiday_hours" | "security";
};
type SitesDeleteSiteSettingQueryParams = {
    device_type?: string;
    holiday_id?: string;
};
type SitesUpdateSiteSettingPathParams = {
    siteId: string;
    settingType: "local_based_routing" | "business_hours" | "closed_hours" | "holiday_hours" | "outbound_caller_id" | "audio_prompt" | "desk_phone" | "dial_by_name" | "billing_account";
};
type SitesUpdateSiteSettingRequestBody = {
    location_based_routing?: {
        enable?: boolean;
        place_receive_pstn_calls?: boolean;
        enable_media_off_load_pstn_calls?: boolean;
    };
    business_hours?: {
        custom_hour_type?: 1 | 2;
        custom_hours?: {
            from?: string;
            to?: string;
            type?: 0 | 1 | 2;
            weekday?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
        }[];
        overflow?: {
            allow_caller_to_reach_operator?: boolean;
            operator?: {
                extension_id?: string;
            };
            allow_caller_to_check_voicemail?: boolean;
        };
    };
    closed_hours?: {
        overflow?: {
            allow_caller_to_reach_operator?: boolean;
            operator?: {
                extension_id?: string;
            };
            allow_caller_to_check_voicemail?: boolean;
        };
    };
    holiday_hours?: {
        holidays?: {
            holiday_id?: string;
            name?: string;
            from?: string;
            to?: string;
        }[];
        overflow?: {
            allow_caller_to_reach_operator?: boolean;
            operator?: {
                extension_id?: string;
            };
            allow_caller_to_check_voicemail?: boolean;
        };
    };
    outbound_caller_id?: {
        auto_receptionists_numbers?: boolean;
        call_queue_numbers?: boolean;
        share_line_group_numbers?: boolean;
        show_outbound_caller_id_for_internal_call?: boolean;
    };
    audio_prompt?: {
        language?: string;
        greeting_leave_voicemail_instruction?: {
            business_hours?: {
                audio_id?: string;
            };
            closed_hours?: {
                audio_id?: string;
            };
            holiday_hours?: {
                audio_id?: string;
            };
        };
        greeting_menu_leave_or_check_voicemail?: {
            business_hours?: {
                audio_id?: string;
            };
            closed_hours?: {
                audio_id?: string;
            };
            holiday_hours?: {
                audio_id?: string;
            };
        };
        greeting_menu_connect_to_operator_or_leave_voicemail?: {
            business_hours?: {
                audio_id?: string;
            };
            closed_hours?: {
                audio_id?: string;
            };
            holiday_hours?: {
                audio_id?: string;
            };
        };
        greeting_menu_connect_to_operator_leave_or_check_voicemail?: {
            business_hours?: {
                audio_id?: string;
            };
            closed_hours?: {
                audio_id?: string;
            };
            holiday_hours?: {
                audio_id?: string;
            };
        };
        leave_voicemail_introduction?: {
            business_hours?: {
                audio_id?: string;
            };
            closed_hours?: {
                audio_id?: string;
            };
            holiday_hours?: {
                audio_id?: string;
            };
        };
        message_greeting?: {
            business_hours?: {
                audio_id?: string;
            };
            closed_hours?: {
                audio_id?: string;
            };
            holiday_hours?: {
                audio_id?: string;
            };
        };
        audio_while_connecting?: {
            audio_id?: string;
        };
        hold_music?: {
            audio_id?: string;
        };
    };
    desk_phone?: {
        hot_desking_session_timeout?: {
            number: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 30;
            unit?: "minutes" | "hours";
        };
    };
    general_setting?: {
        setting_type?: "account_setting" | "custom_setting";
        web_interface?: boolean;
    };
    dial_by_name?: {
        status?: boolean;
        inherit?: boolean;
        rule?: "first_name" | "last_name";
    };
    billing_account?: {
        id?: string;
    };
};
type UsersListPhoneUsersQueryParams = {
    page_size?: number;
    next_page_token?: string;
    site_id?: string;
    calling_type?: number;
    status?: "activate" | "deactivate" | "pending";
    department?: string;
    cost_center?: string;
    keyword?: string;
};
type UsersListPhoneUsersResponse = {
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    users?: {
        calling_plans?: {
            name?: string;
            type?: number;
            billing_account_id?: string;
            billing_account_name?: string;
            billing_subscription_id?: string;
            billing_subscription_name?: string;
        }[];
        email?: string;
        extension_id?: string;
        extension_number?: number;
        id?: string;
        name?: string;
        phone_user_id?: string;
        site?: {
            id?: string;
            name?: string;
        };
        status?: string;
        phone_numbers?: {
            id?: string;
            number?: string;
        }[];
        department?: string;
        cost_center?: string;
    }[];
};
type UsersUpdateMultipleUsersPropertiesInBatchRequestBody = {
    batch_type?: "move_site" | "assign_pending_user";
    user_ids?: string[];
    site_id?: string;
};
type UsersBatchAddUsersRequestBody = {
    users?: {
        email: string;
        first_name?: string;
        last_name?: string;
        calling_plans: string[];
        site_code?: string;
        site_name?: string;
        template_name?: string;
        extension_number: string;
        phone_numbers?: string[];
        outbound_caller_id?: string;
        select_outbound_caller_id?: boolean;
        sms?: boolean;
        desk_phones?: {
            brand?: string;
            model?: string;
            mac?: string;
            provision_template?: string;
        }[];
    }[];
};
type UsersBatchAddUsersResponse = {
    email?: string;
    id?: string;
}[];
type UsersGetUsersProfilePathParams = {
    userId: string;
};
type UsersGetUsersProfileResponse = {
    calling_plans?: {
        type?: number;
        billing_account_id?: string;
        billing_account_name?: string;
        billing_subscription_id?: string;
        billing_subscription_name?: string;
    }[];
    cost_center?: string;
    department?: string;
    email?: string;
    emergency_address?: {
        address_line1?: string;
        address_line2?: string;
        city?: string;
        country?: string;
        id?: string;
        state_code?: string;
        zip?: string;
    };
    extension_id?: string;
    extension_number?: number;
    id?: string;
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
    phone_user_id?: string;
    policy?: {
        ad_hoc_call_recording?: {
            enable?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        ad_hoc_call_recording_access_members?: ({
            access_user_id?: string;
            allow_delete?: boolean;
            allow_download?: boolean;
        } & {
            shared_id?: string;
        })[];
        auto_call_recording?: {
            allow_stop_resume_recording?: boolean;
            disconnect_on_recording_failure?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            recording_calls?: "inbound" | "outbound" | "both";
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
            inbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
            outbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
        };
        auto_call_recording_access_members?: ({
            access_user_id?: string;
            allow_delete?: boolean;
            allow_download?: boolean;
        } & {
            shared_id?: string;
        })[];
        call_overflow?: {
            call_overflow_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
            forward_to?: {
                display_name?: string;
                extension_id?: string;
                extension_number?: number;
                extension_type?: "user" | "zoomRoom" | "commonArea" | "ciscoRoom/polycomRoom" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                id?: string;
            };
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        call_transferring?: {
            call_transferring_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        delegation?: boolean;
        elevate_to_meeting?: boolean;
        emergency_address_management?: {
            enable?: boolean;
            prompt_default_address?: boolean;
        };
        emergency_calls_to_psap?: boolean;
        forwarding_to_external_numbers?: boolean;
        call_handling_forwarding_to_other_users?: {
            enable?: boolean;
            call_forwarding_type?: 1 | 2 | 3 | 4;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        hand_off_to_room?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        international_calling?: boolean;
        mobile_switch_to_carrier?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        select_outbound_caller_id?: {
            enable?: boolean;
            allow_hide_outbound_caller_id?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        sms?: {
            enable?: boolean;
            international_sms?: boolean;
            international_sms_countries?: string[];
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            allow_copy?: boolean;
            allow_paste?: boolean;
        };
        voicemail?: {
            allow_delete?: boolean;
            allow_download?: boolean;
            allow_transcription?: boolean;
            allow_videomail?: boolean;
            enable?: boolean;
        };
        voicemail_access_members?: ({
            access_user_id?: string;
            allow_delete?: boolean;
            allow_download?: boolean;
            allow_sharing?: boolean;
        } & {
            shared_id?: string;
        })[];
        zoom_phone_on_mobile?: {
            allow_calling_clients?: ("ios" | "android" | "intune" | "blackberry")[];
            allow_sms_mms_clients?: ("ios" | "android" | "intune" | "blackberry")[];
            allow_calling_sms_mms?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        personal_audio_library?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
            allow_music_on_hold_customization?: boolean;
            allow_voicemail_and_message_greeting_customization?: boolean;
        };
        voicemail_transcription?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        voicemail_notification_by_email?: {
            include_voicemail_file?: boolean;
            include_voicemail_transcription?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        shared_voicemail_notification_by_email?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        check_voicemails_over_phone?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        audio_intercom?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        peer_to_peer_media?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        e2e_encryption?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        outbound_calling?: {
            enable?: boolean;
            locked?: boolean;
            modified?: boolean;
        };
        outbound_sms?: {
            enable?: boolean;
            locked?: boolean;
            modified?: boolean;
        };
        allow_end_user_edit_call_handling?: {
            enable?: boolean;
            locked?: boolean;
            modified?: boolean;
        };
        voicemail_intent_based_prioritization?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: "account" | "user_group" | "site";
            modified?: boolean;
        };
        voicemail_tasks?: {
            enable?: boolean;
            locked?: boolean;
            modified?: boolean;
            locked_by?: "account" | "user_group" | "site";
        };
        zoom_phone_on_desktop?: {
            allow_calling_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
            allow_sms_mms_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
            enable?: boolean;
            locked?: boolean;
            locked_by?: "invalid" | "account" | "site";
            modified?: boolean;
        };
    };
    site_admin?: boolean;
    site_id?: string;
    status?: "activate" | "deactivate";
};
type UsersUpdateUsersProfilePathParams = {
    userId: string;
};
type UsersUpdateUsersProfileRequestBody = {
    emergency_address_id?: string;
    extension_number?: string;
    policy?: {
        ad_hoc_call_recording?: {
            enable?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            reset?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
        };
        auto_call_recording?: {
            allow_stop_resume_recording?: boolean;
            disconnect_on_recording_failure?: boolean;
            enable?: boolean;
            recording_calls?: "inbound" | "outbound" | "both";
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                play_beep_member?: "allMember" | "recordingSide";
            };
            reset?: boolean;
            inbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
            outbound_audio_notification?: {
                recording_start_prompt?: boolean;
                recording_explicit_consent?: boolean;
            };
        };
        call_overflow?: {
            call_overflow_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            reset?: boolean;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
            forward_to_extension_id?: string;
        };
        call_transferring?: {
            call_transferring_type?: 1 | 2 | 3 | 4;
            enable?: boolean;
            reset?: boolean;
        };
        delegation?: boolean;
        elevate_to_meeting?: boolean;
        emergency_address_management?: {
            enable?: boolean;
            prompt_default_address?: boolean;
        };
        emergency_calls_to_psap?: boolean;
        forwarding_to_external_numbers?: boolean;
        call_handling_forwarding_to_other_users?: {
            enable?: boolean;
            call_forwarding_type?: 1 | 2 | 3 | 4;
            reset?: boolean;
        };
        hand_off_to_room?: {
            enable?: boolean;
        };
        international_calling?: boolean;
        mobile_switch_to_carrier?: {
            enable?: boolean;
        };
        select_outbound_caller_id?: {
            enable?: boolean;
            allow_hide_outbound_caller_id?: boolean;
        };
        sms?: {
            enable?: boolean;
            international_sms?: boolean;
            international_sms_countries?: string[];
            allow_copy?: boolean;
            allow_paste?: boolean;
        };
        voicemail?: {
            allow_delete?: boolean;
            allow_download?: boolean;
            allow_transcription?: boolean;
            allow_videomail?: boolean;
            enable?: boolean;
        };
        voicemail_access_members?: {
            access_user_id?: string;
            allow_delete?: boolean;
            allow_download?: boolean;
            allow_sharing?: boolean;
        }[];
        zoom_phone_on_mobile?: {
            allow_calling_sms_mms?: boolean;
            enable?: boolean;
            allow_calling_clients?: ("ios" | "android" | "intune" | "blackberry")[];
            allow_sms_mms_clients?: ("ios" | "android" | "intune" | "blackberry")[];
        };
        personal_audio_library?: {
            allow_music_on_hold_customization?: boolean;
            allow_voicemail_and_message_greeting_customization?: boolean;
            enable?: boolean;
            reset?: boolean;
        };
        voicemail_transcription?: {
            enable?: boolean;
            reset?: boolean;
        };
        voicemail_notification_by_email?: {
            include_voicemail_file?: boolean;
            include_voicemail_transcription?: boolean;
            enable?: boolean;
            reset?: boolean;
        };
        shared_voicemail_notification_by_email?: {
            enable?: boolean;
            reset?: boolean;
        };
        check_voicemails_over_phone?: {
            enable?: boolean;
            reset?: boolean;
        };
        audio_intercom?: {
            enable?: boolean;
            reset?: boolean;
        };
        e2e_encryption?: {
            enable?: boolean;
            reset?: boolean;
        };
        zoom_phone_on_desktop?: {
            enable?: boolean;
            reset?: boolean;
            allow_calling_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
            allow_sms_mms_clients?: ("mac_os" | "windows" | "vdi_client" | "linux")[];
        };
    };
    site_id?: string;
    template_id?: string;
};
type UsersUpdateUsersCallingPlanPathParams = {
    userId: string;
};
type UsersUpdateUsersCallingPlanRequestBody = {
    source_type: number;
    target_type: number;
    source_billing_subscription_id?: string;
    target_billing_subscription_id?: string;
};
type UsersAssignCallingPlanToUserPathParams = {
    userId: string;
};
type UsersAssignCallingPlanToUserRequestBody = {
    calling_plans?: {
        type?: number;
        billing_account_id?: string;
        billing_subscription_id?: string;
    }[];
};
type UsersUnassignUsersCallingPlanPathParams = {
    userId: string;
    planType: string;
};
type UsersUnassignUsersCallingPlanQueryParams = {
    billing_account_id?: string;
};
type UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDPathParams = {
    userId: string;
};
type UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDQueryParams = {
    selected?: boolean;
    site_id?: string;
    extension_type?: "autoReceptionist" | "callQueue" | "sharedLineGroup";
    keyword?: string;
    page_size?: number;
    next_page_token?: string;
};
type UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDResponse = {
    customize_numbers?: {
        customize_id?: string;
        phone_number_id?: string;
        phone_number?: string;
        display_name?: string;
        incoming?: boolean;
        outgoing?: boolean;
        extension_id?: string;
        extension_type?: string;
        extension_number?: string;
        extension_name?: string;
        site?: {
            id?: string;
            name?: string;
        };
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDPathParams = {
    userId: string;
};
type UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDRequestBody = {
    phone_number_ids?: string[];
};
type UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersPathParams = {
    userId: string;
};
type UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersQueryParams = {
    customize_ids?: string[];
};
type UsersGetUserPolicyDetailsPathParams = {
    userId: string;
    policyType: "allow_emergency_calls";
};
type UsersGetUserPolicyDetailsResponse = {
    allow_emergency_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: "invalid" | "account" | "user_group" | "site";
        modified?: boolean;
        allow_emergency_calls_from_clients?: boolean;
        allow_emergency_calls_from_deskphones?: boolean;
    };
};
type UsersUpdateUserPolicyPathParams = {
    userId: string;
    policyType: "allow_emergency_calls";
};
type UsersUpdateUserPolicyRequestBody = {
    allow_emergency_calls?: {
        enable?: boolean;
        reset?: boolean;
        allow_emergency_calls_from_clients?: boolean;
        allow_emergency_calls_from_deskphones?: boolean;
    };
};
type UsersGetUsersProfileSettingsPathParams = {
    userId: string;
};
type UsersGetUsersProfileSettingsResponse = {
    area_code?: string;
    audio_prompt_language?: string;
    company_number?: string;
    country?: {
        code?: string;
        country_code?: string;
        name?: string;
    };
    delegation?: {
        assistants?: {
            display_name?: string;
            extension_id?: string;
            extension_number?: number;
            extension_type?: string;
            id?: string;
        }[];
        privacy?: boolean;
        privileges?: number[];
        locked?: boolean;
    };
    desk_phone?: {
        devices?: {
            device_type?: string;
            display_name?: string;
            id?: string;
            policy?: {
                call_control?: {
                    status?: "unsupported" | "on" | "off";
                };
                hot_desking?: {
                    status?: "unsupported" | "on" | "off";
                };
            };
            status?: "online" | "offline";
            mac_address?: string;
            private_ip?: string;
            public_ip?: string;
        }[];
        keys_positions?: {
            primary_number?: string;
        };
        phone_screen_lock?: boolean;
        pin_code?: string;
    };
    extension_number?: number;
    music_on_hold_id?: string;
    outbound_caller?: {
        number?: string;
    };
    outbound_caller_ids?: {
        is_default?: boolean;
        name?: string;
        number?: string;
    }[];
    status?: "Active" | "Inactive";
    voice_mail?: {
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
        shared_id?: string;
    }[];
    intercom?: {
        audio_intercoms?: {
            extension_id?: string;
            extension_number?: string;
            extension_type?: string;
            display_name?: string;
            status?: "active" | "pending";
            device_id?: string;
            device_status?: "online" | "offline" | "no device";
        }[];
        device?: {
            id?: string;
            name?: string;
        };
    };
    auto_call_recording_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    } & {
        shared_id?: string;
    })[];
    ad_hoc_call_recording_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    } & {
        shared_id?: string;
    })[];
};
type UsersUpdateUsersProfileSettingsPathParams = {
    userId: string;
};
type UsersUpdateUsersProfileSettingsRequestBody = {
    area_code?: string;
    audio_prompt_language?: string;
    country_iso_code?: string;
    music_on_hold_id?: string;
    outbound_caller_id?: string;
};
type UsersAddUsersSharedAccessSettingPathParams = {
    userId: string;
    settingType: string;
};
type UsersAddUsersSharedAccessSettingRequestBody = {
    delegation_assistant_extension_id?: string;
    device_id?: string;
    voice_mail?: {
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
    };
    voicemail_access_members?: {
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
        allow_sharing?: boolean;
    }[];
    auto_call_recording_access_members?: {
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    }[];
    ad_hoc_call_recording_access_members?: {
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    }[];
};
type UsersAddUsersSharedAccessSettingResponse = {
    delegation?: {
        assistants?: {
            display_name?: string;
            extension_id?: string;
            extension_number?: number;
            extension_type?: string;
            id?: string;
        }[];
        privacy?: boolean;
        privileges?: number[];
    };
    voice_mail?: {
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
        shared_id?: string;
    };
    voicemail_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
        allow_sharing?: boolean;
    } & {
        shared_id?: string;
    })[];
    auto_call_recording_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    } & {
        shared_id?: string;
    })[];
    ad_hoc_call_recording_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    } & {
        shared_id?: string;
    })[];
};
type UsersDeleteUsersSharedAccessSettingPathParams = {
    userId: string;
    settingType: string;
};
type UsersDeleteUsersSharedAccessSettingQueryParams = {
    shared_id?: string;
    assistant_extension_id?: string;
    device_id?: string;
    intercom_extension_id?: string;
};
type UsersUpdateUsersSharedAccessSettingPathParams = {
    settingType: string;
    userId: string;
};
type UsersUpdateUsersSharedAccessSettingRequestBody = {
    delegation?: {
        privacy?: boolean;
        privileges?: number[];
        locked?: boolean;
    };
    desk_phone?: {
        devices?: {
            id?: string;
            policy?: {
                call_control?: {
                    status?: "on" | "off";
                };
                hot_desking?: {
                    status?: "on" | "off";
                };
            };
        }[];
        phone_screen_lock?: boolean;
        pin_code?: string;
    };
    voice_mail?: {
        access_user_id?: string;
        delete?: boolean;
        download?: boolean;
        shared_id?: string;
    };
    intercom?: {
        extension_id?: string;
        device_id?: string;
    };
    voicemail_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
        allow_sharing?: boolean;
    } & {
        shared_id?: string;
    })[];
    auto_call_recording_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    } & {
        shared_id?: string;
    })[];
    ad_hoc_call_recording_access_members?: ({
        access_user_id?: string;
        allow_delete?: boolean;
        allow_download?: boolean;
    } & {
        shared_id?: string;
    })[];
};
type VoicemailsGetUserVoicemailDetailsFromCallLogPathParams = {
    userId: string;
    id: string;
};
type VoicemailsGetUserVoicemailDetailsFromCallLogResponse = {
    call_id?: string;
    call_log_id?: string;
    call_history_id?: string;
    callee_name?: string;
    callee_number?: string;
    callee_number_type?: 1 | 2 | 3;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: 1 | 2;
    date_time?: string;
    download_url?: string;
    duration?: number;
    id?: string;
    status?: "read" | "unread";
    transcription?: {
        content?: string;
        status?: 0 | 1 | 2 | 4 | 5 | 9 | 11 | 12 | 13 | 14 | 409 | 415 | 422 | 500 | 601 | 602 | 603 | 999;
        engine?: string;
    };
};
type VoicemailsGetUsersVoicemailsPathParams = {
    userId: string;
};
type VoicemailsGetUsersVoicemailsQueryParams = {
    page_size?: number;
    status?: "all" | "read" | "unread";
    next_page_token?: string;
    from?: string;
    to?: string;
    trash?: boolean;
};
type VoicemailsGetUsersVoicemailsResponse = {
    from?: string;
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    to?: string;
    total_records?: number;
    voice_mails?: {
        call_id?: string;
        call_log_id?: string;
        call_history_id?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: 1 | 2 | 3;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        date_time?: string;
        download_url?: string;
        duration?: number;
        id?: string;
        status?: "read" | "unread";
    }[];
};
type VoicemailsGetAccountVoicemailsQueryParams = {
    page_size?: number;
    status?: "all" | "read" | "unread";
    site_id?: string;
    owner_type?: "user" | "callQueue" | "sharedLineGroup" | "autoReceptionist" | "commonArea";
    voicemail_type?: "normal" | "spam" | "maybeSpam";
    next_page_token?: string;
    from?: string;
    to?: string;
    trashed?: boolean;
};
type VoicemailsGetAccountVoicemailsResponse = {
    from?: string;
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    to?: string;
    total_records?: number;
    voice_mails?: {
        call_id?: string;
        call_log_id?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: 1 | 2 | 3;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: 1 | 2;
        date_time?: string;
        download_url?: string;
        duration?: number;
        id?: string;
        status?: "read" | "unread";
        owner?: {
            extension_number?: number;
            id?: string;
            name?: string;
            type?: "user" | "callQueue" | "sharedLineGroup" | "autoReceptionist" | "commonArea";
            extension_status?: "inactive" | "deleted";
            extension_deleted_time?: string;
        };
        deleted_time?: string;
        days_left_auto_permantely_delete?: number;
        soft_deleted_type?: "Manual" | "Data Retention";
    }[];
};
type VoicemailsDownloadPhoneVoicemailPathParams = {
    fileId: string;
};
type VoicemailsGetVoicemailDetailsPathParams = {
    voicemailId: string;
};
type VoicemailsGetVoicemailDetailsResponse = {
    call_id?: string;
    call_log_id?: string;
    call_history_id?: string;
    callee_name?: string;
    callee_number?: string;
    callee_number_type?: 1 | 2 | 3;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: 1 | 2;
    date_time?: string;
    download_url?: string;
    duration?: number;
    id?: string;
    status?: "read" | "unread";
    transcription?: {
        content?: string;
        status?: 0 | 1 | 2 | 4 | 5 | 9 | 11 | 12 | 13 | 14 | 409 | 415 | 422 | 500 | 601 | 602 | 603 | 999;
        engine?: string;
    };
    deleted_time?: string;
    days_left_auto_permantely_delete?: number;
    soft_deleted_type?: "Manual" | "Data Retention";
    intent_detect_status?: "not_started" | "processing" | "success" | "ai_detection_failed" | "unknown_reason_failed";
    intent_results?: {
        intent_id?: string;
        confidence_score?: number;
    }[];
    voice_mail_task?: {
        status?: "processing" | "success" | "no_task" | "failure";
        content?: string;
        feedback?: "none" | "thumbs_up" | "thumbs_down";
    };
};
type VoicemailsDeleteVoicemailPathParams = {
    voicemailId: string;
};
type VoicemailsUpdateVoicemailReadStatusPathParams = {
    voicemailId: string;
};
type VoicemailsUpdateVoicemailReadStatusQueryParams = {
    read_status: "Read" | "Unread";
};
type ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseQueryParams = {
    page_size?: number;
    next_page_token?: string;
    site_id?: string;
    calling_type?: number;
    keyword?: string;
};
type ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseResponse = {
    next_page_token?: string;
    page_size?: number;
    rooms?: {
        calling_plans?: {
            name?: string;
            type?: number;
            billing_account_id?: string;
            billing_account_name?: string;
            billing_subscription_id?: string;
            billing_subscription_name?: string;
        }[];
        extension_id?: string;
        extension_number?: number;
        id?: string;
        name?: string;
        phone_numbers?: {
            id?: string;
            number?: string;
        }[];
        site?: {
            id?: string;
            name?: string;
        };
    }[];
    total_records?: number;
};
type ZoomRoomsAddZoomRoomToZoomPhoneRequestBody = {
    id?: string;
    site_id?: string;
    calling_plans?: {
        type?: number;
        billing_subscription_id?: string;
    }[];
};
type ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentQueryParams = {
    keyword?: string;
};
type ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentResponse = {
    rooms?: {
        id?: string;
        display_name?: string;
        location_id?: string;
        location_info?: string;
        department?: string;
        cost_center?: string;
    }[];
};
type ZoomRoomsGetZoomRoomUnderZoomPhoneLicensePathParams = {
    roomId: string;
};
type ZoomRoomsGetZoomRoomUnderZoomPhoneLicenseResponse = {
    calling_plans?: {
        name?: string;
        type?: number;
        billing_account_id?: string;
        billing_account_name?: string;
        billing_subscription_id?: string;
        billing_subscription_name?: string;
    }[];
    emergency_address?: {
        address_line1?: string;
        address_line2?: string;
        city?: string;
        country?: string;
        id?: string;
        state_code?: string;
        zip?: string;
    };
    extension_id?: string;
    extension_number?: number;
    id?: string;
    name?: string;
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
    policy?: {
        international_calling?: {
            enable?: boolean;
            locked_by?: "invalid" | "account" | "user_group" | "site" | "extension";
        };
        select_outbound_caller_id?: {
            enable?: boolean;
            locked_by?: "invalid" | "account" | "user_group" | "site" | "extension";
        };
    };
    site?: {
        id?: string;
        name?: string;
    };
};
type ZoomRoomsRemoveZoomRoomFromZPAccountPathParams = {
    roomId: string;
};
type ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicensePathParams = {
    roomId: string;
};
type ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicenseRequestBody = {
    extension_number?: number;
    policy?: {
        international_calling?: {
            enable?: boolean;
            reset?: boolean;
        };
        select_outbound_caller_id?: {
            enable?: boolean;
            reset?: boolean;
        };
    };
    site_id?: string;
};
type ZoomRoomsAssignCallingPlansToZoomRoomPathParams = {
    roomId: string;
};
type ZoomRoomsAssignCallingPlansToZoomRoomRequestBody = {
    calling_plans?: {
        type?: number;
        billing_account_id?: string;
        billing_subscription_id?: string;
    }[];
};
type ZoomRoomsRemoveCallingPlanFromZoomRoomPathParams = {
    roomId: string;
    type: number;
};
type ZoomRoomsRemoveCallingPlanFromZoomRoomQueryParams = {
    billing_account_id?: string;
};
type ZoomRoomsAssignPhoneNumbersToZoomRoomPathParams = {
    roomId: string;
};
type ZoomRoomsAssignPhoneNumbersToZoomRoomRequestBody = {
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
};
type ZoomRoomsAssignPhoneNumbersToZoomRoomResponse = object;
type ZoomRoomsRemovePhoneNumberFromZoomRoomPathParams = {
    roomId: string;
    phoneNumberId: string;
};
declare class PhoneEndpoints extends WebEndpoints {
    readonly accounts: {
        listAccountsZoomPhoneSettings: (_: object & {
            query?: AccountsListAccountsZoomPhoneSettingsQueryParams;
        }) => Promise<BaseResponse<AccountsListAccountsZoomPhoneSettingsResponse>>;
        listAccountsCustomizedOutboundCallerIDPhoneNumbers: (_: object & {
            query?: AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersResponse>>;
        addPhoneNumbersForAccountsCustomizedOutboundCallerID: (_: object & {
            body?: AccountsAddPhoneNumbersForAccountsCustomizedOutboundCallerIDRequestBody;
        }) => Promise<BaseResponse<never>>;
        deletePhoneNumbersForAccountsCustomizedOutboundCallerID: (_: object & {
            query?: AccountsDeletePhoneNumbersForAccountsCustomizedOutboundCallerIDQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly alerts: {
        listAlertSettingsWithPagingQuery: (_: object & {
            query?: AlertsListAlertSettingsWithPagingQueryQueryParams;
        }) => Promise<BaseResponse<AlertsListAlertSettingsWithPagingQueryResponse>>;
        addAlertSetting: (_: object & {
            body: AlertsAddAlertSettingRequestBody;
        }) => Promise<BaseResponse<AlertsAddAlertSettingResponse>>;
        getAlertSettingDetails: (_: {
            path: AlertsGetAlertSettingDetailsPathParams;
        } & object) => Promise<BaseResponse<AlertsGetAlertSettingDetailsResponse>>;
        deleteAlertSetting: (_: {
            path: AlertsDeleteAlertSettingPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateAlertSetting: (_: {
            path: AlertsUpdateAlertSettingPathParams;
        } & {
            body?: AlertsUpdateAlertSettingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly audioLibrary: {
        getAudioItem: (_: {
            path: AudioLibraryGetAudioItemPathParams;
        } & object) => Promise<BaseResponse<AudioLibraryGetAudioItemResponse>>;
        deleteAudioItem: (_: {
            path: AudioLibraryDeleteAudioItemPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateAudioItem: (_: {
            path: AudioLibraryUpdateAudioItemPathParams;
        } & {
            body: AudioLibraryUpdateAudioItemRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listAudioItems: (_: {
            path: AudioLibraryListAudioItemsPathParams;
        } & object) => Promise<BaseResponse<AudioLibraryListAudioItemsResponse>>;
        addAudioItemForTextToSpeechConversion: (_: {
            path: AudioLibraryAddAudioItemForTextToSpeechConversionPathParams;
        } & {
            body?: AudioLibraryAddAudioItemForTextToSpeechConversionRequestBody;
        } & object) => Promise<BaseResponse<AudioLibraryAddAudioItemForTextToSpeechConversionResponse>>;
        addAudioItems: (_: {
            path: AudioLibraryAddAudioItemsPathParams;
        } & {
            body?: AudioLibraryAddAudioItemsRequestBody;
        } & object) => Promise<BaseResponse<AudioLibraryAddAudioItemsResponse>>;
    };
    readonly autoReceptionists: {
        listAutoReceptionists: (_: object & {
            query?: AutoReceptionistsListAutoReceptionistsQueryParams;
        }) => Promise<BaseResponse<AutoReceptionistsListAutoReceptionistsResponse>>;
        addAutoReceptionist: (_: object & {
            body: AutoReceptionistsAddAutoReceptionistRequestBody;
        }) => Promise<BaseResponse<AutoReceptionistsAddAutoReceptionistResponse>>;
        getAutoReceptionist: (_: {
            path: AutoReceptionistsGetAutoReceptionistPathParams;
        } & object) => Promise<BaseResponse<AutoReceptionistsGetAutoReceptionistResponse>>;
        deleteNonPrimaryAutoReceptionist: (_: {
            path: AutoReceptionistsDeleteNonPrimaryAutoReceptionistPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateAutoReceptionist: (_: {
            path: AutoReceptionistsUpdateAutoReceptionistPathParams;
        } & {
            body?: AutoReceptionistsUpdateAutoReceptionistRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        assignPhoneNumbers: (_: {
            path: AutoReceptionistsAssignPhoneNumbersPathParams;
        } & {
            body?: AutoReceptionistsAssignPhoneNumbersRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignAllPhoneNumbers: (_: {
            path: AutoReceptionistsUnassignAllPhoneNumbersPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignPhoneNumber: (_: {
            path: AutoReceptionistsUnassignPhoneNumberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getAutoReceptionistPolicy: (_: {
            path: AutoReceptionistsGetAutoReceptionistPolicyPathParams;
        } & object) => Promise<BaseResponse<AutoReceptionistsGetAutoReceptionistPolicyResponse>>;
        updateAutoReceptionistPolicy: (_: {
            path: AutoReceptionistsUpdateAutoReceptionistPolicyPathParams;
        } & {
            body?: AutoReceptionistsUpdateAutoReceptionistPolicyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        addPolicySubsetting: (_: {
            path: AutoReceptionistsAddPolicySubsettingPathParams;
        } & {
            body?: AutoReceptionistsAddPolicySubsettingRequestBody;
        } & object) => Promise<BaseResponse<AutoReceptionistsAddPolicySubsettingResponse>>;
        deletePolicySubsetting: (_: {
            path: AutoReceptionistsDeletePolicySubsettingPathParams;
        } & object & {
            query: AutoReceptionistsDeletePolicySubsettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updatePolicySubsetting: (_: {
            path: AutoReceptionistsUpdatePolicySubsettingPathParams;
        } & {
            body?: AutoReceptionistsUpdatePolicySubsettingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly billingAccount: {
        listBillingAccounts: (_: object & {
            query?: BillingAccountListBillingAccountsQueryParams;
        }) => Promise<BaseResponse<BillingAccountListBillingAccountsResponse>>;
        getBillingAccountDetails: (_: {
            path: BillingAccountGetBillingAccountDetailsPathParams;
        } & object) => Promise<BaseResponse<BillingAccountGetBillingAccountDetailsResponse>>;
    };
    readonly blockedList: {
        listBlockedLists: (_: object & {
            query?: BlockedListListBlockedListsQueryParams;
        }) => Promise<BaseResponse<BlockedListListBlockedListsResponse>>;
        createBlockedList: (_: object & {
            body?: BlockedListCreateBlockedListRequestBody;
        }) => Promise<BaseResponse<BlockedListCreateBlockedListResponse>>;
        getBlockedListDetails: (_: {
            path: BlockedListGetBlockedListDetailsPathParams;
        } & object) => Promise<BaseResponse<BlockedListGetBlockedListDetailsResponse>>;
        deleteBlockedList: (_: {
            path: BlockedListDeleteBlockedListPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateBlockedList: (_: {
            path: BlockedListUpdateBlockedListPathParams;
        } & {
            body?: BlockedListUpdateBlockedListRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly callHandling: {
        getCallHandlingSettings: (_: {
            path: CallHandlingGetCallHandlingSettingsPathParams;
        } & object) => Promise<BaseResponse<CallHandlingGetCallHandlingSettingsResponse>>;
        addCallHandlingSetting: (_: {
            path: CallHandlingAddCallHandlingSettingPathParams;
        } & (({
            body?: {
                settings?: {
                    holiday_id?: string;
                    description?: string;
                    phone_number?: string;
                };
                sub_setting_type?: "call_forwarding";
            };
        } | {
            body?: {
                settings?: {
                    name?: string;
                    from?: string;
                    to?: string;
                };
                sub_setting_type?: "holiday";
            };
        }) & object)) => Promise<BaseResponse<CallHandlingAddCallHandlingSettingResponse>>;
        deleteCallHandlingSetting: (_: {
            path: CallHandlingDeleteCallHandlingSettingPathParams;
        } & object & {
            query?: CallHandlingDeleteCallHandlingSettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateCallHandlingSetting: (_: {
            path: CallHandlingUpdateCallHandlingSettingPathParams;
        } & (({
            body?: {
                settings?: {
                    call_forwarding_settings?: {
                        description?: string;
                        enable?: boolean;
                        id?: string;
                        phone_number?: string;
                        external_contact?: {
                            external_contact_id?: string;
                        };
                    }[];
                    require_press_1_before_connecting?: boolean;
                };
                sub_setting_type?: "call_forwarding";
            };
        } | {
            body?: {
                settings?: {
                    from?: string;
                    holiday_id?: string;
                    name?: string;
                    to?: string;
                };
                sub_setting_type?: "holiday";
            };
        } | {
            body?: {
                settings?: {
                    allow_members_to_reset?: boolean;
                    custom_hours_settings?: {
                        from?: string;
                        to?: string;
                        type?: 0 | 1 | 2;
                        weekday?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
                    }[];
                    type?: 1 | 2;
                };
                sub_setting_type?: "custom_hours";
            };
        } | {
            body?: {
                settings?: {
                    allow_callers_check_voicemail?: boolean;
                    allow_members_to_reset?: boolean;
                    audio_while_connecting_id?: string;
                    call_distribution?: {
                        handle_multiple_calls?: boolean;
                        ring_duration?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
                        ring_mode?: "simultaneous" | "sequential" | "rotating" | "longest_idle";
                        skip_offline_device_phone_number?: boolean;
                    };
                    call_not_answer_action?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 14 | 15 | 18 | 19;
                    busy_on_another_call_action?: 1 | 2 | 4 | 6 | 7 | 8 | 9 | 10 | 12 | 21 | 22;
                    busy_require_press_1_before_connecting?: boolean;
                    un_answered_require_press_1_before_connecting?: boolean;
                    overflow_play_callee_voicemail_greeting?: boolean;
                    play_callee_voicemail_greeting?: boolean;
                    busy_play_callee_voicemail_greeting?: boolean;
                    phone_number?: string;
                    description?: string;
                    busy_phone_number?: string;
                    busy_description?: string;
                    connect_to_operator?: boolean;
                    forward_to_extension_id?: string;
                    busy_forward_to_extension_id?: string;
                    greeting_prompt_id?: string;
                    max_call_in_queue?: number;
                    max_wait_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60 | 120 | 180 | 240 | 300 | 600 | 900 | 1200 | 1500 | 1800;
                    music_on_hold_id?: string;
                    operator_extension_id?: string;
                    receive_call?: boolean;
                    ring_mode?: "simultaneous" | "sequential";
                    voicemail_greeting_id?: string;
                    voicemail_leaving_instruction_id?: string;
                    message_greeting_id?: string;
                    forward_to_zcc_phone_number?: string;
                    forward_to_partner_contact_center_id?: string;
                    forward_to_teams_id?: string;
                    wrap_up_time?: 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60 | 120 | 180 | 240 | 300;
                };
                sub_setting_type?: "call_handling";
            };
        }) & object)) => Promise<BaseResponse<unknown>>;
    };
    readonly callLogs: {
        getAccountsCallHistory: (_: object & {
            query?: CallLogsGetAccountsCallHistoryQueryParams;
        }) => Promise<BaseResponse<CallLogsGetAccountsCallHistoryResponse>>;
        getCallPath: (_: {
            path: CallLogsGetCallPathPathParams;
        } & object) => Promise<BaseResponse<CallLogsGetCallPathResponse>>;
        addClientCodeToCallHistory: (_: {
            path: CallLogsAddClientCodeToCallHistoryPathParams;
        } & {
            body: CallLogsAddClientCodeToCallHistoryRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getCallHistoryDetail: (_: {
            path: CallLogsGetCallHistoryDetailPathParams;
        } & object) => Promise<BaseResponse<CallLogsGetCallHistoryDetailResponse>>;
        getAccountsCallLogs: (_: object & {
            query?: CallLogsGetAccountsCallLogsQueryParams;
        }) => Promise<BaseResponse<CallLogsGetAccountsCallLogsResponse>>;
        getCallLogDetails: (_: {
            path: CallLogsGetCallLogDetailsPathParams;
        } & object) => Promise<BaseResponse<CallLogsGetCallLogDetailsResponse>>;
        addClientCodeToCallLog: (_: {
            path: CallLogsAddClientCodeToCallLogPathParams;
        } & {
            body: CallLogsAddClientCodeToCallLogRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUserAICallSummaryDetail: (_: {
            path: CallLogsGetUserAICallSummaryDetailPathParams;
        } & object) => Promise<BaseResponse<CallLogsGetUserAICallSummaryDetailResponse>>;
        getUsersCallHistory: (_: {
            path: CallLogsGetUsersCallHistoryPathParams;
        } & object & {
            query?: CallLogsGetUsersCallHistoryQueryParams;
        }) => Promise<BaseResponse<CallLogsGetUsersCallHistoryResponse>>;
        syncUsersCallHistory: (_: {
            path: CallLogsSyncUsersCallHistoryPathParams;
        } & object & {
            query?: CallLogsSyncUsersCallHistoryQueryParams;
        }) => Promise<BaseResponse<CallLogsSyncUsersCallHistoryResponse>>;
        deleteUsersCallHistory: (_: {
            path: CallLogsDeleteUsersCallHistoryPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getUsersCallLogs: (_: {
            path: CallLogsGetUsersCallLogsPathParams;
        } & object & {
            query?: CallLogsGetUsersCallLogsQueryParams;
        }) => Promise<BaseResponse<CallLogsGetUsersCallLogsResponse>>;
        syncUsersCallLogs: (_: {
            path: CallLogsSyncUsersCallLogsPathParams;
        } & object & {
            query?: CallLogsSyncUsersCallLogsQueryParams;
        }) => Promise<BaseResponse<CallLogsSyncUsersCallLogsResponse>>;
        deleteUsersCallLog: (_: {
            path: CallLogsDeleteUsersCallLogPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly callQueues: {
        listCallQueueAnalytics: (_: object & {
            query?: CallQueuesListCallQueueAnalyticsQueryParams;
        }) => Promise<BaseResponse<CallQueuesListCallQueueAnalyticsResponse>>;
        listCallQueues: (_: object & {
            query?: CallQueuesListCallQueuesQueryParams;
        }) => Promise<BaseResponse<CallQueuesListCallQueuesResponse>>;
        createCallQueue: (_: object & {
            body: CallQueuesCreateCallQueueRequestBody;
        }) => Promise<BaseResponse<CallQueuesCreateCallQueueResponse>>;
        getCallQueueDetails: (_: {
            path: CallQueuesGetCallQueueDetailsPathParams;
        } & object) => Promise<BaseResponse<CallQueuesGetCallQueueDetailsResponse>>;
        deleteCallQueue: (_: {
            path: CallQueuesDeleteCallQueuePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateCallQueueDetails: (_: {
            path: CallQueuesUpdateCallQueueDetailsPathParams;
        } & {
            body?: CallQueuesUpdateCallQueueDetailsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listCallQueueMembers: (_: {
            path: CallQueuesListCallQueueMembersPathParams;
        } & object) => Promise<BaseResponse<CallQueuesListCallQueueMembersResponse>>;
        addMembersToCallQueue: (_: {
            path: CallQueuesAddMembersToCallQueuePathParams;
        } & {
            body?: CallQueuesAddMembersToCallQueueRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignAllMembers: (_: {
            path: CallQueuesUnassignAllMembersPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignMember: (_: {
            path: CallQueuesUnassignMemberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        assignNumbersToCallQueue: (_: {
            path: CallQueuesAssignNumbersToCallQueuePathParams;
        } & {
            body?: CallQueuesAssignNumbersToCallQueueRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignAllPhoneNumbers: (_: {
            path: CallQueuesUnassignAllPhoneNumbersPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignPhoneNumber: (_: {
            path: CallQueuesUnassignPhoneNumberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        addPolicySubsettingToCallQueue: (_: {
            path: CallQueuesAddPolicySubsettingToCallQueuePathParams;
        } & {
            body?: CallQueuesAddPolicySubsettingToCallQueueRequestBody;
        } & object) => Promise<BaseResponse<CallQueuesAddPolicySubsettingToCallQueueResponse>>;
        deleteCQPolicySetting: (_: {
            path: CallQueuesDeleteCQPolicySettingPathParams;
        } & object & {
            query: CallQueuesDeleteCQPolicySettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateCallQueuesPolicySubsetting: (_: {
            path: CallQueuesUpdateCallQueuesPolicySubsettingPathParams;
        } & {
            body?: CallQueuesUpdateCallQueuesPolicySubsettingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getCallQueueRecordings: (_: {
            path: CallQueuesGetCallQueueRecordingsPathParams;
        } & object & {
            query?: CallQueuesGetCallQueueRecordingsQueryParams;
        }) => Promise<BaseResponse<CallQueuesGetCallQueueRecordingsResponse>>;
    };
    readonly carrierReseller: {
        listPhoneNumbers: (_: object & {
            query?: CarrierResellerListPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<CarrierResellerListPhoneNumbersResponse>>;
        createPhoneNumbers: (_: object & {
            body: CarrierResellerCreatePhoneNumbersRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        activatePhoneNumbers: (_: object & {
            body: CarrierResellerActivatePhoneNumbersRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        deletePhoneNumber: (_: {
            path: CarrierResellerDeletePhoneNumberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly commonAreas: {
        listCommonAreas: (_: object & {
            query?: CommonAreasListCommonAreasQueryParams;
        }) => Promise<BaseResponse<CommonAreasListCommonAreasResponse>>;
        addCommonArea: (_: object & {
            body: CommonAreasAddCommonAreaRequestBody;
        }) => Promise<BaseResponse<CommonAreasAddCommonAreaResponse>>;
        generateActivationCodesForCommonAreas: (_: object & {
            body: CommonAreasGenerateActivationCodesForCommonAreasRequestBody;
        }) => Promise<BaseResponse<CommonAreasGenerateActivationCodesForCommonAreasResponse>>;
        listActivationCodes: (_: object & {
            query?: CommonAreasListActivationCodesQueryParams;
        }) => Promise<BaseResponse<CommonAreasListActivationCodesResponse>>;
        applyTemplateToCommonAreas: (_: {
            path: CommonAreasApplyTemplateToCommonAreasPathParams;
        } & {
            body?: CommonAreasApplyTemplateToCommonAreasRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getCommonAreaDetails: (_: {
            path: CommonAreasGetCommonAreaDetailsPathParams;
        } & object) => Promise<BaseResponse<CommonAreasGetCommonAreaDetailsResponse>>;
        deleteCommonArea: (_: {
            path: CommonAreasDeleteCommonAreaPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateCommonArea: (_: {
            path: CommonAreasUpdateCommonAreaPathParams;
        } & {
            body?: CommonAreasUpdateCommonAreaRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        assignCallingPlansToCommonArea: (_: {
            path: CommonAreasAssignCallingPlansToCommonAreaPathParams;
        } & {
            body: CommonAreasAssignCallingPlansToCommonAreaRequestBody;
        } & object) => Promise<BaseResponse<CommonAreasAssignCallingPlansToCommonAreaResponse>>;
        unassignCallingPlanFromCommonArea: (_: {
            path: CommonAreasUnassignCallingPlanFromCommonAreaPathParams;
        } & object & {
            query?: CommonAreasUnassignCallingPlanFromCommonAreaQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        assignPhoneNumbersToCommonArea: (_: {
            path: CommonAreasAssignPhoneNumbersToCommonAreaPathParams;
        } & {
            body: CommonAreasAssignPhoneNumbersToCommonAreaRequestBody;
        } & object) => Promise<BaseResponse<CommonAreasAssignPhoneNumbersToCommonAreaResponse>>;
        unassignPhoneNumbersFromCommonArea: (_: {
            path: CommonAreasUnassignPhoneNumbersFromCommonAreaPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateCommonAreaPinCode: (_: {
            path: CommonAreasUpdateCommonAreaPinCodePathParams;
        } & {
            body: CommonAreasUpdateCommonAreaPinCodeRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getCommonAreaSettings: (_: {
            path: CommonAreasGetCommonAreaSettingsPathParams;
        } & object) => Promise<BaseResponse<CommonAreasGetCommonAreaSettingsResponse>>;
        addCommonAreaSetting: (_: {
            path: CommonAreasAddCommonAreaSettingPathParams;
        } & {
            body?: CommonAreasAddCommonAreaSettingRequestBody;
        } & object) => Promise<BaseResponse<CommonAreasAddCommonAreaSettingResponse>>;
        deleteCommonAreaSetting: (_: {
            path: CommonAreasDeleteCommonAreaSettingPathParams;
        } & object & {
            query: CommonAreasDeleteCommonAreaSettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateCommonAreaSetting: (_: {
            path: CommonAreasUpdateCommonAreaSettingPathParams;
        } & {
            body?: CommonAreasUpdateCommonAreaSettingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly dashboard: {
        listCallLogs: (_: object & {
            query?: DashboardListCallLogsQueryParams;
        }) => Promise<BaseResponse<DashboardListCallLogsResponse>>;
        getCallQoS: (_: {
            path: DashboardGetCallQoSPathParams;
        } & object) => Promise<BaseResponse<DashboardGetCallQoSResponse>>;
        getCallDetailsFromCallLog: (_: {
            path: DashboardGetCallDetailsFromCallLogPathParams;
        } & object) => Promise<BaseResponse<DashboardGetCallDetailsFromCallLogResponse>>;
        listDefaultEmergencyAddressUsers: (_: object & {
            query: DashboardListDefaultEmergencyAddressUsersQueryParams;
        }) => Promise<BaseResponse<DashboardListDefaultEmergencyAddressUsersResponse>>;
        listDetectablePersonalLocationUsers: (_: object & {
            query: DashboardListDetectablePersonalLocationUsersQueryParams;
        }) => Promise<BaseResponse<DashboardListDetectablePersonalLocationUsersResponse>>;
        listUsersPermissionForLocationSharing: (_: object & {
            query?: DashboardListUsersPermissionForLocationSharingQueryParams;
        }) => Promise<BaseResponse<DashboardListUsersPermissionForLocationSharingResponse>>;
        listNomadicEmergencyServicesUsers: (_: object & {
            query: DashboardListNomadicEmergencyServicesUsersQueryParams;
        }) => Promise<BaseResponse<DashboardListNomadicEmergencyServicesUsersResponse>>;
        listRealTimeLocationForIPPhones: (_: object & {
            query: DashboardListRealTimeLocationForIPPhonesQueryParams;
        }) => Promise<BaseResponse<DashboardListRealTimeLocationForIPPhonesResponse>>;
        listRealTimeLocationForUsers: (_: object & {
            query: DashboardListRealTimeLocationForUsersQueryParams;
        }) => Promise<BaseResponse<DashboardListRealTimeLocationForUsersResponse>>;
        listTrackedLocations: (_: object & {
            query?: DashboardListTrackedLocationsQueryParams;
        }) => Promise<BaseResponse<DashboardListTrackedLocationsResponse>>;
        listPastCallMetrics: (_: object & {
            query?: DashboardListPastCallMetricsQueryParams;
        }) => Promise<BaseResponse<DashboardListPastCallMetricsResponse>>;
    };
    readonly deviceLineKeys: {
        getDeviceLineKeysInformation: (_: {
            path: DeviceLineKeysGetDeviceLineKeysInformationPathParams;
        } & object) => Promise<BaseResponse<DeviceLineKeysGetDeviceLineKeysInformationResponse>>;
        batchUpdateDeviceLineKeyPosition: (_: {
            path: DeviceLineKeysBatchUpdateDeviceLineKeyPositionPathParams;
        } & {
            body?: DeviceLineKeysBatchUpdateDeviceLineKeyPositionRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly dialByNameDirectory: {
        listUsersInDirectory: (_: object & {
            query: DialByNameDirectoryListUsersInDirectoryQueryParams;
        }) => Promise<BaseResponse<DialByNameDirectoryListUsersInDirectoryResponse>>;
        addUsersToDirectory: (_: object & {
            body: DialByNameDirectoryAddUsersToDirectoryRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        deleteUsersFromDirectory: (_: object & {
            query: DialByNameDirectoryDeleteUsersFromDirectoryQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listUsersInDirectoryBySite: (_: {
            path: DialByNameDirectoryListUsersInDirectoryBySitePathParams;
        } & object & {
            query?: DialByNameDirectoryListUsersInDirectoryBySiteQueryParams;
        }) => Promise<BaseResponse<DialByNameDirectoryListUsersInDirectoryBySiteResponse>>;
        addUsersToDirectoryOfSite: (_: {
            path: DialByNameDirectoryAddUsersToDirectoryOfSitePathParams;
        } & {
            body?: DialByNameDirectoryAddUsersToDirectoryOfSiteRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteUsersFromDirectoryOfSite: (_: {
            path: DialByNameDirectoryDeleteUsersFromDirectoryOfSitePathParams;
        } & object & {
            query?: DialByNameDirectoryDeleteUsersFromDirectoryOfSiteQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly emergencyAddresses: {
        listEmergencyAddresses: (_: object & {
            query?: EmergencyAddressesListEmergencyAddressesQueryParams;
        }) => Promise<BaseResponse<EmergencyAddressesListEmergencyAddressesResponse>>;
        addEmergencyAddress: (_: object & {
            body: EmergencyAddressesAddEmergencyAddressRequestBody;
        }) => Promise<BaseResponse<EmergencyAddressesAddEmergencyAddressResponse>>;
        getEmergencyAddressDetails: (_: {
            path: EmergencyAddressesGetEmergencyAddressDetailsPathParams;
        } & object) => Promise<BaseResponse<EmergencyAddressesGetEmergencyAddressDetailsResponse>>;
        deleteEmergencyAddress: (_: {
            path: EmergencyAddressesDeleteEmergencyAddressPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateEmergencyAddress: (_: {
            path: EmergencyAddressesUpdateEmergencyAddressPathParams;
        } & {
            body?: EmergencyAddressesUpdateEmergencyAddressRequestBody;
        } & object) => Promise<BaseResponse<EmergencyAddressesUpdateEmergencyAddressResponse>>;
    };
    readonly emergencyServiceLocations: {
        batchAddEmergencyServiceLocations: (_: object & {
            body: EmergencyServiceLocationsBatchAddEmergencyServiceLocationsRequestBody;
        }) => Promise<BaseResponse<EmergencyServiceLocationsBatchAddEmergencyServiceLocationsResponse>>;
        listEmergencyServiceLocations: (_: object & {
            query?: EmergencyServiceLocationsListEmergencyServiceLocationsQueryParams;
        }) => Promise<BaseResponse<EmergencyServiceLocationsListEmergencyServiceLocationsResponse>>;
        addEmergencyServiceLocation: (_: object & {
            body: EmergencyServiceLocationsAddEmergencyServiceLocationRequestBody;
        }) => Promise<BaseResponse<EmergencyServiceLocationsAddEmergencyServiceLocationResponse>>;
        getEmergencyServiceLocationDetails: (_: {
            path: EmergencyServiceLocationsGetEmergencyServiceLocationDetailsPathParams;
        } & object) => Promise<BaseResponse<EmergencyServiceLocationsGetEmergencyServiceLocationDetailsResponse>>;
        deleteEmergencyLocation: (_: {
            path: EmergencyServiceLocationsDeleteEmergencyLocationPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateEmergencyServiceLocation: (_: {
            path: EmergencyServiceLocationsUpdateEmergencyServiceLocationPathParams;
        } & {
            body?: EmergencyServiceLocationsUpdateEmergencyServiceLocationRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly externalContacts: {
        listExternalContacts: (_: object & {
            query?: ExternalContactsListExternalContactsQueryParams;
        }) => Promise<BaseResponse<ExternalContactsListExternalContactsResponse>>;
        addExternalContact: (_: object & {
            body: ExternalContactsAddExternalContactRequestBody;
        }) => Promise<BaseResponse<ExternalContactsAddExternalContactResponse>>;
        getExternalContactDetails: (_: {
            path: ExternalContactsGetExternalContactDetailsPathParams;
        } & object) => Promise<BaseResponse<ExternalContactsGetExternalContactDetailsResponse>>;
        deleteExternalContact: (_: {
            path: ExternalContactsDeleteExternalContactPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateExternalContact: (_: {
            path: ExternalContactsUpdateExternalContactPathParams;
        } & {
            body?: ExternalContactsUpdateExternalContactRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly firmwareUpdateRules: {
        listFirmwareUpdateRules: (_: object & {
            query?: FirmwareUpdateRulesListFirmwareUpdateRulesQueryParams;
        }) => Promise<BaseResponse<FirmwareUpdateRulesListFirmwareUpdateRulesResponse>>;
        addFirmwareUpdateRule: (_: object & {
            body: FirmwareUpdateRulesAddFirmwareUpdateRuleRequestBody;
        }) => Promise<BaseResponse<FirmwareUpdateRulesAddFirmwareUpdateRuleResponse>>;
        getFirmwareUpdateRuleInformation: (_: {
            path: FirmwareUpdateRulesGetFirmwareUpdateRuleInformationPathParams;
        } & object) => Promise<BaseResponse<FirmwareUpdateRulesGetFirmwareUpdateRuleInformationResponse>>;
        deleteFirmwareUpdateRule: (_: {
            path: FirmwareUpdateRulesDeleteFirmwareUpdateRulePathParams;
        } & object & {
            query?: FirmwareUpdateRulesDeleteFirmwareUpdateRuleQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateFirmwareUpdateRule: (_: {
            path: FirmwareUpdateRulesUpdateFirmwareUpdateRulePathParams;
        } & {
            body: FirmwareUpdateRulesUpdateFirmwareUpdateRuleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listUpdatableFirmwares: (_: object & {
            query?: FirmwareUpdateRulesListUpdatableFirmwaresQueryParams;
        }) => Promise<BaseResponse<FirmwareUpdateRulesListUpdatableFirmwaresResponse>>;
    };
    readonly groupCallPickup: {
        listGroupCallPickupObjects: (_: object & {
            query?: GroupCallPickupListGroupCallPickupObjectsQueryParams;
        }) => Promise<BaseResponse<GroupCallPickupListGroupCallPickupObjectsResponse>>;
        addGroupCallPickupObject: (_: object & {
            body: GroupCallPickupAddGroupCallPickupObjectRequestBody;
        }) => Promise<BaseResponse<GroupCallPickupAddGroupCallPickupObjectResponse>>;
        getCallPickupGroupByID: (_: {
            path: GroupCallPickupGetCallPickupGroupByIDPathParams;
        } & object) => Promise<BaseResponse<GroupCallPickupGetCallPickupGroupByIDResponse>>;
        deleteGroupCallPickupObjects: (_: {
            path: GroupCallPickupDeleteGroupCallPickupObjectsPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateGroupCallPickupInformation: (_: {
            path: GroupCallPickupUpdateGroupCallPickupInformationPathParams;
        } & {
            body?: GroupCallPickupUpdateGroupCallPickupInformationRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listCallPickupGroupMembers: (_: {
            path: GroupCallPickupListCallPickupGroupMembersPathParams;
        } & object & {
            query?: GroupCallPickupListCallPickupGroupMembersQueryParams;
        }) => Promise<BaseResponse<GroupCallPickupListCallPickupGroupMembersResponse>>;
        addMembersToCallPickupGroup: (_: {
            path: GroupCallPickupAddMembersToCallPickupGroupPathParams;
        } & {
            body?: GroupCallPickupAddMembersToCallPickupGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        removeMembersFromCallPickupGroup: (_: {
            path: GroupCallPickupRemoveMembersFromCallPickupGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly groups: {
        getGroupPolicyDetails: (_: {
            path: GroupsGetGroupPolicyDetailsPathParams;
        } & object) => Promise<BaseResponse<GroupsGetGroupPolicyDetailsResponse>>;
        updateGroupPolicy: (_: {
            path: GroupsUpdateGroupPolicyPathParams;
        } & {
            body?: GroupsUpdateGroupPolicyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getGroupPhoneSettings: (_: {
            path: GroupsGetGroupPhoneSettingsPathParams;
        } & object & {
            query?: GroupsGetGroupPhoneSettingsQueryParams;
        }) => Promise<BaseResponse<GroupsGetGroupPhoneSettingsResponse>>;
    };
    readonly iVR: {
        getAutoReceptionistIVR: (_: {
            path: IVRGetAutoReceptionistIVRPathParams;
        } & object & {
            query?: IVRGetAutoReceptionistIVRQueryParams;
        }) => Promise<BaseResponse<IVRGetAutoReceptionistIVRResponse>>;
        updateAutoReceptionistIVR: (_: {
            path: IVRUpdateAutoReceptionistIVRPathParams;
        } & {
            body?: IVRUpdateAutoReceptionistIVRRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly inboundBlockedList: {
        listExtensionsInboundBlockRules: (_: {
            path: InboundBlockedListListExtensionsInboundBlockRulesPathParams;
        } & object & {
            query?: InboundBlockedListListExtensionsInboundBlockRulesQueryParams;
        }) => Promise<BaseResponse<InboundBlockedListListExtensionsInboundBlockRulesResponse>>;
        addExtensionsInboundBlockRule: (_: {
            path: InboundBlockedListAddExtensionsInboundBlockRulePathParams;
        } & {
            body: InboundBlockedListAddExtensionsInboundBlockRuleRequestBody;
        } & object) => Promise<BaseResponse<InboundBlockedListAddExtensionsInboundBlockRuleResponse>>;
        deleteExtensionsInboundBlockRule: (_: {
            path: InboundBlockedListDeleteExtensionsInboundBlockRulePathParams;
        } & object & {
            query: InboundBlockedListDeleteExtensionsInboundBlockRuleQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listAccountsInboundBlockedStatistics: (_: object & {
            query?: InboundBlockedListListAccountsInboundBlockedStatisticsQueryParams;
        }) => Promise<BaseResponse<InboundBlockedListListAccountsInboundBlockedStatisticsResponse>>;
        deleteAccountsInboundBlockedStatistics: (_: object & {
            query: InboundBlockedListDeleteAccountsInboundBlockedStatisticsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        markPhoneNumberAsBlockedForAllExtensions: (_: object & {
            body: InboundBlockedListMarkPhoneNumberAsBlockedForAllExtensionsRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        listAccountsInboundBlockRules: (_: object & {
            query?: InboundBlockedListListAccountsInboundBlockRulesQueryParams;
        }) => Promise<BaseResponse<InboundBlockedListListAccountsInboundBlockRulesResponse>>;
        addAccountsInboundBlockRule: (_: object & {
            body: InboundBlockedListAddAccountsInboundBlockRuleRequestBody;
        }) => Promise<BaseResponse<InboundBlockedListAddAccountsInboundBlockRuleResponse>>;
        deleteAccountsInboundBlockRule: (_: object & {
            query: InboundBlockedListDeleteAccountsInboundBlockRuleQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateAccountsInboundBlockRule: (_: {
            path: InboundBlockedListUpdateAccountsInboundBlockRulePathParams;
        } & {
            body: InboundBlockedListUpdateAccountsInboundBlockRuleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly lineKeys: {
        getLineKeyPositionAndSettingsInformation: (_: {
            path: LineKeysGetLineKeyPositionAndSettingsInformationPathParams;
        } & object) => Promise<BaseResponse<LineKeysGetLineKeyPositionAndSettingsInformationResponse>>;
        batchUpdateLineKeyPositionAndSettingsInformation: (_: {
            path: LineKeysBatchUpdateLineKeyPositionAndSettingsInformationPathParams;
        } & {
            body?: LineKeysBatchUpdateLineKeyPositionAndSettingsInformationRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteLineKeySetting: (_: {
            path: LineKeysDeleteLineKeySettingPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly monitoringGroups: {
        getListOfMonitoringGroupsOnAccount: (_: object & {
            query?: MonitoringGroupsGetListOfMonitoringGroupsOnAccountQueryParams;
        }) => Promise<BaseResponse<MonitoringGroupsGetListOfMonitoringGroupsOnAccountResponse>>;
        createMonitoringGroup: (_: object & {
            body?: MonitoringGroupsCreateMonitoringGroupRequestBody;
        }) => Promise<BaseResponse<MonitoringGroupsCreateMonitoringGroupResponse>>;
        getMonitoringGroupByID: (_: {
            path: MonitoringGroupsGetMonitoringGroupByIDPathParams;
        } & object) => Promise<BaseResponse<MonitoringGroupsGetMonitoringGroupByIDResponse>>;
        deleteMonitoringGroup: (_: {
            path: MonitoringGroupsDeleteMonitoringGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateMonitoringGroup: (_: {
            path: MonitoringGroupsUpdateMonitoringGroupPathParams;
        } & {
            body?: MonitoringGroupsUpdateMonitoringGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getMembersOfMonitoringGroup: (_: {
            path: MonitoringGroupsGetMembersOfMonitoringGroupPathParams;
        } & object & {
            query: MonitoringGroupsGetMembersOfMonitoringGroupQueryParams;
        }) => Promise<BaseResponse<MonitoringGroupsGetMembersOfMonitoringGroupResponse>>;
        addMembersToMonitoringGroup: (_: {
            path: MonitoringGroupsAddMembersToMonitoringGroupPathParams;
        } & {
            body: MonitoringGroupsAddMembersToMonitoringGroupRequestBody;
        } & {
            query: MonitoringGroupsAddMembersToMonitoringGroupQueryParams;
        }) => Promise<BaseResponse<never>>;
        removeAllMonitorsOrMonitoredMembersFromMonitoringGroup: (_: {
            path: MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupPathParams;
        } & object & {
            query: MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        removeMemberFromMonitoringGroup: (_: {
            path: MonitoringGroupsRemoveMemberFromMonitoringGroupPathParams;
        } & object & {
            query?: MonitoringGroupsRemoveMemberFromMonitoringGroupQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly outboundCalling: {
        getCommonAreaLevelOutboundCallingCountriesAndRegions: (_: {
            path: OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsPathParams;
        } & object & {
            query?: OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsQueryParams;
        }) => Promise<BaseResponse<OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsResponse>>;
        updateCommonAreaLevelOutboundCallingCountriesOrRegions: (_: {
            path: OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsPathParams;
        } & {
            body?: OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listCommonAreaLevelOutboundCallingExceptionRules: (_: {
            path: OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesPathParams;
        } & object & {
            query?: OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesQueryParams;
        }) => Promise<BaseResponse<OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesResponse>>;
        addCommonAreaLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRulePathParams;
        } & {
            body?: OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleRequestBody;
        } & object) => Promise<BaseResponse<OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleResponse>>;
        deleteCommonAreaLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingDeleteCommonAreaLevelOutboundCallingExceptionRulePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateCommonAreaLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRulePathParams;
        } & {
            body?: OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRuleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getAccountLevelOutboundCallingCountriesAndRegions: (_: object & {
            query?: OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsQueryParams;
        }) => Promise<BaseResponse<OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsResponse>>;
        updateAccountLevelOutboundCallingCountriesOrRegions: (_: object & {
            body?: OutboundCallingUpdateAccountLevelOutboundCallingCountriesOrRegionsRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        listAccountLevelOutboundCallingExceptionRules: (_: object & {
            query?: OutboundCallingListAccountLevelOutboundCallingExceptionRulesQueryParams;
        }) => Promise<BaseResponse<OutboundCallingListAccountLevelOutboundCallingExceptionRulesResponse>>;
        addAccountLevelOutboundCallingExceptionRule: (_: object & {
            body?: OutboundCallingAddAccountLevelOutboundCallingExceptionRuleRequestBody;
        }) => Promise<BaseResponse<OutboundCallingAddAccountLevelOutboundCallingExceptionRuleResponse>>;
        deleteAccountLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingDeleteAccountLevelOutboundCallingExceptionRulePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateAccountLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingUpdateAccountLevelOutboundCallingExceptionRulePathParams;
        } & {
            body?: OutboundCallingUpdateAccountLevelOutboundCallingExceptionRuleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getSiteLevelOutboundCallingCountriesAndRegions: (_: {
            path: OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsPathParams;
        } & object & {
            query?: OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsQueryParams;
        }) => Promise<BaseResponse<OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsResponse>>;
        updateSiteLevelOutboundCallingCountriesOrRegions: (_: {
            path: OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsPathParams;
        } & {
            body?: OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listSiteLevelOutboundCallingExceptionRules: (_: {
            path: OutboundCallingListSiteLevelOutboundCallingExceptionRulesPathParams;
        } & object & {
            query?: OutboundCallingListSiteLevelOutboundCallingExceptionRulesQueryParams;
        }) => Promise<BaseResponse<OutboundCallingListSiteLevelOutboundCallingExceptionRulesResponse>>;
        addSiteLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingAddSiteLevelOutboundCallingExceptionRulePathParams;
        } & {
            body?: OutboundCallingAddSiteLevelOutboundCallingExceptionRuleRequestBody;
        } & object) => Promise<BaseResponse<OutboundCallingAddSiteLevelOutboundCallingExceptionRuleResponse>>;
        deleteSiteLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingDeleteSiteLevelOutboundCallingExceptionRulePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateSiteLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingUpdateSiteLevelOutboundCallingExceptionRulePathParams;
        } & {
            body?: OutboundCallingUpdateSiteLevelOutboundCallingExceptionRuleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUserLevelOutboundCallingCountriesAndRegions: (_: {
            path: OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsPathParams;
        } & object & {
            query?: OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsQueryParams;
        }) => Promise<BaseResponse<OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsResponse>>;
        updateUserLevelOutboundCallingCountriesOrRegions: (_: {
            path: OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsPathParams;
        } & {
            body?: OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listUserLevelOutboundCallingExceptionRules: (_: {
            path: OutboundCallingListUserLevelOutboundCallingExceptionRulesPathParams;
        } & object & {
            query?: OutboundCallingListUserLevelOutboundCallingExceptionRulesQueryParams;
        }) => Promise<BaseResponse<OutboundCallingListUserLevelOutboundCallingExceptionRulesResponse>>;
        addUserLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingAddUserLevelOutboundCallingExceptionRulePathParams;
        } & {
            body?: OutboundCallingAddUserLevelOutboundCallingExceptionRuleRequestBody;
        } & object) => Promise<BaseResponse<OutboundCallingAddUserLevelOutboundCallingExceptionRuleResponse>>;
        deleteUserLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingDeleteUserLevelOutboundCallingExceptionRulePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateUserLevelOutboundCallingExceptionRule: (_: {
            path: OutboundCallingUpdateUserLevelOutboundCallingExceptionRulePathParams;
        } & {
            body?: OutboundCallingUpdateUserLevelOutboundCallingExceptionRuleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly phoneDevices: {
        listDevices: (_: object & {
            query: PhoneDevicesListDevicesQueryParams;
        }) => Promise<BaseResponse<PhoneDevicesListDevicesResponse>>;
        addDevice: (_: object & {
            body: PhoneDevicesAddDeviceRequestBody;
        }) => Promise<BaseResponse<PhoneDevicesAddDeviceResponse>>;
        syncDeskphones: (_: object & {
            body: PhoneDevicesSyncDeskphonesRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        getDeviceDetails: (_: {
            path: PhoneDevicesGetDeviceDetailsPathParams;
        } & object) => Promise<BaseResponse<PhoneDevicesGetDeviceDetailsResponse>>;
        deleteDevice: (_: {
            path: PhoneDevicesDeleteDevicePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateDevice: (_: {
            path: PhoneDevicesUpdateDevicePathParams;
        } & {
            body?: PhoneDevicesUpdateDeviceRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        assignEntityToDevice: (_: {
            path: PhoneDevicesAssignEntityToDevicePathParams;
        } & {
            body: PhoneDevicesAssignEntityToDeviceRequestBody;
        } & object) => Promise<BaseResponse<never>>;
        unassignEntityFromDevice: (_: {
            path: PhoneDevicesUnassignEntityFromDevicePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateProvisionTemplateOfDevice: (_: {
            path: PhoneDevicesUpdateProvisionTemplateOfDevicePathParams;
        } & {
            body?: PhoneDevicesUpdateProvisionTemplateOfDeviceRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        rebootDeskPhone: (_: {
            path: PhoneDevicesRebootDeskPhonePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listSmartphones: (_: object & {
            query?: PhoneDevicesListSmartphonesQueryParams;
        }) => Promise<BaseResponse<PhoneDevicesListSmartphonesResponse>>;
    };
    readonly phoneNumbers: {
        addBYOCPhoneNumbers: (_: object & {
            body: PhoneNumbersAddBYOCPhoneNumbersRequestBody;
        }) => Promise<BaseResponse<PhoneNumbersAddBYOCPhoneNumbersResponse>>;
        listPhoneNumbers: (_: object & {
            query?: PhoneNumbersListPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<PhoneNumbersListPhoneNumbersResponse>>;
        deleteUnassignedPhoneNumbers: (_: object & {
            query: PhoneNumbersDeleteUnassignedPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateSitesUnassignedPhoneNumbers: (_: {
            path: PhoneNumbersUpdateSitesUnassignedPhoneNumbersPathParams;
        } & {
            body?: PhoneNumbersUpdateSitesUnassignedPhoneNumbersRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getPhoneNumber: (_: {
            path: PhoneNumbersGetPhoneNumberPathParams;
        } & object) => Promise<BaseResponse<PhoneNumbersGetPhoneNumberResponse>>;
        updatePhoneNumber: (_: {
            path: PhoneNumbersUpdatePhoneNumberPathParams;
        } & {
            body?: PhoneNumbersUpdatePhoneNumberRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        assignPhoneNumberToUser: (_: {
            path: PhoneNumbersAssignPhoneNumberToUserPathParams;
        } & {
            body?: PhoneNumbersAssignPhoneNumberToUserRequestBody;
        } & object) => Promise<BaseResponse<PhoneNumbersAssignPhoneNumberToUserResponse>>;
        unassignPhoneNumber: (_: {
            path: PhoneNumbersUnassignPhoneNumberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly phonePlans: {
        listCallingPlans: (_: object) => Promise<BaseResponse<PhonePlansListCallingPlansResponse>>;
        listPlanInformation: (_: object) => Promise<BaseResponse<PhonePlansListPlanInformationResponse>>;
    };
    readonly phoneRoles: {
        listPhoneRoles: (_: object) => Promise<BaseResponse<PhoneRolesListPhoneRolesResponse>>;
        duplicatePhoneRole: (_: object & {
            body: PhoneRolesDuplicatePhoneRoleRequestBody;
        }) => Promise<BaseResponse<PhoneRolesDuplicatePhoneRoleResponse>>;
        getRoleInformation: (_: {
            path: PhoneRolesGetRoleInformationPathParams;
        } & object) => Promise<BaseResponse<PhoneRolesGetRoleInformationResponse>>;
        deletePhoneRole: (_: {
            path: PhoneRolesDeletePhoneRolePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updatePhoneRole: (_: {
            path: PhoneRolesUpdatePhoneRolePathParams;
        } & {
            body?: PhoneRolesUpdatePhoneRoleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listMembersInRole: (_: {
            path: PhoneRolesListMembersInRolePathParams;
        } & object & {
            query?: PhoneRolesListMembersInRoleQueryParams;
        }) => Promise<BaseResponse<PhoneRolesListMembersInRoleResponse>>;
        addMembersToRoles: (_: {
            path: PhoneRolesAddMembersToRolesPathParams;
        } & {
            body?: PhoneRolesAddMembersToRolesRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteMembersInRole: (_: {
            path: PhoneRolesDeleteMembersInRolePathParams;
        } & object & {
            query: PhoneRolesDeleteMembersInRoleQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listPhoneRoleTargets: (_: {
            path: PhoneRolesListPhoneRoleTargetsPathParams;
        } & object & {
            query?: PhoneRolesListPhoneRoleTargetsQueryParams;
        }) => Promise<BaseResponse<PhoneRolesListPhoneRoleTargetsResponse>>;
        addPhoneRoleTargets: (_: {
            path: PhoneRolesAddPhoneRoleTargetsPathParams;
        } & {
            body: PhoneRolesAddPhoneRoleTargetsRequestBody;
        } & object) => Promise<BaseResponse<PhoneRolesAddPhoneRoleTargetsResponse>>;
        deletePhoneRoleTargets: (_: {
            path: PhoneRolesDeletePhoneRoleTargetsPathParams;
        } & {
            body: PhoneRolesDeletePhoneRoleTargetsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly privateDirectory: {
        listPrivateDirectoryMembers: (_: object & {
            query?: PrivateDirectoryListPrivateDirectoryMembersQueryParams;
        }) => Promise<BaseResponse<PrivateDirectoryListPrivateDirectoryMembersResponse>>;
        addMembersToPrivateDirectory: (_: object & {
            body: PrivateDirectoryAddMembersToPrivateDirectoryRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        removeMemberFromPrivateDirectory: (_: {
            path: PrivateDirectoryRemoveMemberFromPrivateDirectoryPathParams;
        } & object & {
            query?: PrivateDirectoryRemoveMemberFromPrivateDirectoryQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updatePrivateDirectoryMember: (_: {
            path: PrivateDirectoryUpdatePrivateDirectoryMemberPathParams;
        } & {
            body: PrivateDirectoryUpdatePrivateDirectoryMemberRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly providerExchange: {
        listCarrierPeeringPhoneNumbers: (_: object & {
            query?: ProviderExchangeListCarrierPeeringPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<ProviderExchangeListCarrierPeeringPhoneNumbersResponse>>;
        listPeeringPhoneNumbers: (_: object & {
            query?: ProviderExchangeListPeeringPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<ProviderExchangeListPeeringPhoneNumbersResponse>>;
        addPeeringPhoneNumbers: (_: object & {
            body?: ProviderExchangeAddPeeringPhoneNumbersRequestBody;
        }) => Promise<BaseResponse<ProviderExchangeAddPeeringPhoneNumbersResponse>>;
        removePeeringPhoneNumbers: (_: object & {
            query: ProviderExchangeRemovePeeringPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<ProviderExchangeRemovePeeringPhoneNumbersResponse>>;
        updatePeeringPhoneNumbers: (_: object & {
            body?: ProviderExchangeUpdatePeeringPhoneNumbersRequestBody;
        }) => Promise<BaseResponse<ProviderExchangeUpdatePeeringPhoneNumbersResponse>>;
    };
    readonly provisionTemplates: {
        listProvisionTemplates: (_: object & {
            query?: ProvisionTemplatesListProvisionTemplatesQueryParams;
        }) => Promise<BaseResponse<ProvisionTemplatesListProvisionTemplatesResponse>>;
        addProvisionTemplate: (_: object & {
            body: ProvisionTemplatesAddProvisionTemplateRequestBody;
        }) => Promise<BaseResponse<ProvisionTemplatesAddProvisionTemplateResponse>>;
        getProvisionTemplate: (_: {
            path: ProvisionTemplatesGetProvisionTemplatePathParams;
        } & object) => Promise<BaseResponse<ProvisionTemplatesGetProvisionTemplateResponse>>;
        deleteProvisionTemplate: (_: {
            path: ProvisionTemplatesDeleteProvisionTemplatePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateProvisionTemplate: (_: {
            path: ProvisionTemplatesUpdateProvisionTemplatePathParams;
        } & {
            body?: ProvisionTemplatesUpdateProvisionTemplateRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly recordings: {
        getRecordingByCallID: (_: {
            path: RecordingsGetRecordingByCallIDPathParams;
        } & object) => Promise<BaseResponse<RecordingsGetRecordingByCallIDResponse>>;
        downloadPhoneRecording: (_: {
            path: RecordingsDownloadPhoneRecordingPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        downloadPhoneRecordingTranscript: (_: {
            path: RecordingsDownloadPhoneRecordingTranscriptPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getCallRecordings: (_: object & {
            query?: RecordingsGetCallRecordingsQueryParams;
        }) => Promise<BaseResponse<RecordingsGetCallRecordingsResponse>>;
        deleteCallRecording: (_: {
            path: RecordingsDeleteCallRecordingPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateAutoDeleteField: (_: {
            path: RecordingsUpdateAutoDeleteFieldPathParams;
        } & {
            body?: RecordingsUpdateAutoDeleteFieldRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateRecordingStatus: (_: {
            path: RecordingsUpdateRecordingStatusPathParams;
        } & {
            body?: RecordingsUpdateRecordingStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUsersRecordings: (_: {
            path: RecordingsGetUsersRecordingsPathParams;
        } & object & {
            query?: RecordingsGetUsersRecordingsQueryParams;
        }) => Promise<BaseResponse<RecordingsGetUsersRecordingsResponse>>;
    };
    readonly reports: {
        getCallChargesUsageReport: (_: object & {
            query?: ReportsGetCallChargesUsageReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetCallChargesUsageReportResponse>>;
        getOperationLogsReport: (_: object & {
            query?: ReportsGetOperationLogsReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetOperationLogsReportResponse>>;
        getSMSMMSChargesUsageReport: (_: object & {
            query?: ReportsGetSMSMMSChargesUsageReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetSMSMMSChargesUsageReportResponse>>;
    };
    readonly routingRules: {
        listDirectoryBackupRoutingRules: (_: object & {
            query?: RoutingRulesListDirectoryBackupRoutingRulesQueryParams;
        }) => Promise<BaseResponse<RoutingRulesListDirectoryBackupRoutingRulesResponse>>;
        addDirectoryBackupRoutingRule: (_: object & {
            body?: RoutingRulesAddDirectoryBackupRoutingRuleRequestBody;
        }) => Promise<BaseResponse<RoutingRulesAddDirectoryBackupRoutingRuleResponse>>;
        getDirectoryBackupRoutingRule: (_: {
            path: RoutingRulesGetDirectoryBackupRoutingRulePathParams;
        } & object) => Promise<BaseResponse<RoutingRulesGetDirectoryBackupRoutingRuleResponse>>;
        deleteDirectoryBackupRoutingRule: (_: {
            path: RoutingRulesDeleteDirectoryBackupRoutingRulePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateDirectoryBackupRoutingRule: (_: {
            path: RoutingRulesUpdateDirectoryBackupRoutingRulePathParams;
        } & {
            body?: RoutingRulesUpdateDirectoryBackupRoutingRuleRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly sMS: {
        postSMSMessage: (_: object & {
            body: SMSPostSMSMessageRequestBody;
        }) => Promise<BaseResponse<SMSPostSMSMessageResponse>>;
        getAccountsSMSSessions: (_: object & {
            query?: SMSGetAccountsSMSSessionsQueryParams;
        }) => Promise<BaseResponse<SMSGetAccountsSMSSessionsResponse>>;
        getSMSSessionDetails: (_: {
            path: SMSGetSMSSessionDetailsPathParams;
        } & object & {
            query?: SMSGetSMSSessionDetailsQueryParams;
        }) => Promise<BaseResponse<SMSGetSMSSessionDetailsResponse>>;
        getSMSByMessageID: (_: {
            path: SMSGetSMSByMessageIDPathParams;
        } & object) => Promise<BaseResponse<SMSGetSMSByMessageIDResponse>>;
        syncSMSBySessionID: (_: {
            path: SMSSyncSMSBySessionIDPathParams;
        } & object & {
            query?: SMSSyncSMSBySessionIDQueryParams;
        }) => Promise<BaseResponse<SMSSyncSMSBySessionIDResponse>>;
        getUsersSMSSessions: (_: {
            path: SMSGetUsersSMSSessionsPathParams;
        } & object & {
            query?: SMSGetUsersSMSSessionsQueryParams;
        }) => Promise<BaseResponse<SMSGetUsersSMSSessionsResponse>>;
        listUsersSMSSessionsInDescendingOrder: (_: {
            path: SMSListUsersSMSSessionsInDescendingOrderPathParams;
        } & object & {
            query: SMSListUsersSMSSessionsInDescendingOrderQueryParams;
        }) => Promise<BaseResponse<SMSListUsersSMSSessionsInDescendingOrderResponse>>;
    };
    readonly sMSCampaign: {
        listSMSCampaigns: (_: object & {
            query?: SMSCampaignListSMSCampaignsQueryParams;
        }) => Promise<BaseResponse<SMSCampaignListSMSCampaignsResponse>>;
        getSMSCampaign: (_: {
            path: SMSCampaignGetSMSCampaignPathParams;
        } & object) => Promise<BaseResponse<SMSCampaignGetSMSCampaignResponse>>;
        assignPhoneNumberToSMSCampaign: (_: {
            path: SMSCampaignAssignPhoneNumberToSMSCampaignPathParams;
        } & {
            body: SMSCampaignAssignPhoneNumberToSMSCampaignRequestBody;
        } & object) => Promise<BaseResponse<SMSCampaignAssignPhoneNumberToSMSCampaignResponse>>;
        listOptStatusesOfPhoneNumbersAssignedToSMSCampaign: (_: {
            path: SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams;
        } & object & {
            query: SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignQueryParams;
        }) => Promise<BaseResponse<SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignResponse>>;
        updateOptStatusesOfPhoneNumbersAssignedToSMSCampaign: (_: {
            path: SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams;
        } & {
            body: SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignPhoneNumber: (_: {
            path: SMSCampaignUnassignPhoneNumberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listUsersOptStatusesOfPhoneNumbers: (_: {
            path: SMSCampaignListUsersOptStatusesOfPhoneNumbersPathParams;
        } & object & {
            query: SMSCampaignListUsersOptStatusesOfPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<SMSCampaignListUsersOptStatusesOfPhoneNumbersResponse>>;
    };
    readonly settingTemplates: {
        listSettingTemplates: (_: object & {
            query?: SettingTemplatesListSettingTemplatesQueryParams;
        }) => Promise<BaseResponse<SettingTemplatesListSettingTemplatesResponse>>;
        addSettingTemplate: (_: object & {
            body: SettingTemplatesAddSettingTemplateRequestBody;
        }) => Promise<BaseResponse<SettingTemplatesAddSettingTemplateResponse>>;
        getSettingTemplateDetails: (_: {
            path: SettingTemplatesGetSettingTemplateDetailsPathParams;
        } & object & {
            query?: SettingTemplatesGetSettingTemplateDetailsQueryParams;
        }) => Promise<BaseResponse<SettingTemplatesGetSettingTemplateDetailsResponse>>;
        updateSettingTemplate: (_: {
            path: SettingTemplatesUpdateSettingTemplatePathParams;
        } & {
            body?: SettingTemplatesUpdateSettingTemplateRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly settings: {
        getAccountPolicyDetails: (_: {
            path: SettingsGetAccountPolicyDetailsPathParams;
        } & object) => Promise<BaseResponse<SettingsGetAccountPolicyDetailsResponse>>;
        updateAccountPolicy: (_: {
            path: SettingsUpdateAccountPolicyPathParams;
        } & {
            body?: SettingsUpdateAccountPolicyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listPortedNumbers: (_: object & {
            query?: SettingsListPortedNumbersQueryParams;
        }) => Promise<BaseResponse<SettingsListPortedNumbersResponse>>;
        getPortedNumberDetails: (_: {
            path: SettingsGetPortedNumberDetailsPathParams;
        } & object) => Promise<BaseResponse<SettingsGetPortedNumberDetailsResponse>>;
        getPhoneAccountSettings: (_: object) => Promise<BaseResponse<SettingsGetPhoneAccountSettingsResponse>>;
        updatePhoneAccountSettings: (_: object & {
            body?: SettingsUpdatePhoneAccountSettingsRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        listSIPGroups: (_: object & {
            query?: SettingsListSIPGroupsQueryParams;
        }) => Promise<BaseResponse<SettingsListSIPGroupsResponse>>;
        listBYOCSIPTrunks: (_: object & {
            query?: SettingsListBYOCSIPTrunksQueryParams;
        }) => Promise<BaseResponse<SettingsListBYOCSIPTrunksResponse>>;
    };
    readonly sharedLineAppearance: {
        listSharedLineAppearances: (_: object & {
            query?: SharedLineAppearanceListSharedLineAppearancesQueryParams;
        }) => Promise<BaseResponse<SharedLineAppearanceListSharedLineAppearancesResponse>>;
    };
    readonly sharedLineGroup: {
        listSharedLineGroups: (_: object & {
            query?: SharedLineGroupListSharedLineGroupsQueryParams;
        }) => Promise<BaseResponse<SharedLineGroupListSharedLineGroupsResponse>>;
        createSharedLineGroup: (_: object & {
            body: SharedLineGroupCreateSharedLineGroupRequestBody;
        }) => Promise<BaseResponse<SharedLineGroupCreateSharedLineGroupResponse>>;
        getSharedLineGroup: (_: {
            path: SharedLineGroupGetSharedLineGroupPathParams;
        } & object) => Promise<BaseResponse<SharedLineGroupGetSharedLineGroupResponse>>;
        getSharedLineGroupPolicy: (_: {
            path: SharedLineGroupGetSharedLineGroupPolicyPathParams;
        } & object) => Promise<BaseResponse<SharedLineGroupGetSharedLineGroupPolicyResponse>>;
        updateSharedLineGroupPolicy: (_: {
            path: SharedLineGroupUpdateSharedLineGroupPolicyPathParams;
        } & {
            body?: SharedLineGroupUpdateSharedLineGroupPolicyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteSharedLineGroup: (_: {
            path: SharedLineGroupDeleteSharedLineGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateSharedLineGroup: (_: {
            path: SharedLineGroupUpdateSharedLineGroupPathParams;
        } & {
            body?: SharedLineGroupUpdateSharedLineGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        addMembersToSharedLineGroup: (_: {
            path: SharedLineGroupAddMembersToSharedLineGroupPathParams;
        } & {
            body?: SharedLineGroupAddMembersToSharedLineGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignMembersFromSharedLineGroup: (_: {
            path: SharedLineGroupUnassignMembersFromSharedLineGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignMemberFromSharedLineGroup: (_: {
            path: SharedLineGroupUnassignMemberFromSharedLineGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        assignPhoneNumbers: (_: {
            path: SharedLineGroupAssignPhoneNumbersPathParams;
        } & {
            body?: SharedLineGroupAssignPhoneNumbersRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignAllPhoneNumbers: (_: {
            path: SharedLineGroupUnassignAllPhoneNumbersPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignPhoneNumber: (_: {
            path: SharedLineGroupUnassignPhoneNumberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        addPolicySettingToSharedLineGroup: (_: {
            path: SharedLineGroupAddPolicySettingToSharedLineGroupPathParams;
        } & {
            body?: SharedLineGroupAddPolicySettingToSharedLineGroupRequestBody;
        } & object) => Promise<BaseResponse<SharedLineGroupAddPolicySettingToSharedLineGroupResponse>>;
        deleteSLGPolicySetting: (_: {
            path: SharedLineGroupDeleteSLGPolicySettingPathParams;
        } & object & {
            query: SharedLineGroupDeleteSLGPolicySettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateSLGPolicySetting: (_: {
            path: SharedLineGroupUpdateSLGPolicySettingPathParams;
        } & {
            body?: SharedLineGroupUpdateSLGPolicySettingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly sites: {
        listPhoneSites: (_: object & {
            query?: SitesListPhoneSitesQueryParams;
        }) => Promise<BaseResponse<SitesListPhoneSitesResponse>>;
        createPhoneSite: (_: object & {
            body: SitesCreatePhoneSiteRequestBody;
        }) => Promise<BaseResponse<SitesCreatePhoneSiteResponse>>;
        getPhoneSiteDetails: (_: {
            path: SitesGetPhoneSiteDetailsPathParams;
        } & object) => Promise<BaseResponse<SitesGetPhoneSiteDetailsResponse>>;
        deletePhoneSite: (_: {
            path: SitesDeletePhoneSitePathParams;
        } & object & {
            query: SitesDeletePhoneSiteQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updatePhoneSiteDetails: (_: {
            path: SitesUpdatePhoneSiteDetailsPathParams;
        } & {
            body?: SitesUpdatePhoneSiteDetailsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listCustomizedOutboundCallerIDPhoneNumbers: (_: {
            path: SitesListCustomizedOutboundCallerIDPhoneNumbersPathParams;
        } & object & {
            query?: SitesListCustomizedOutboundCallerIDPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<SitesListCustomizedOutboundCallerIDPhoneNumbersResponse>>;
        addCustomizedOutboundCallerIDPhoneNumbers: (_: {
            path: SitesAddCustomizedOutboundCallerIDPhoneNumbersPathParams;
        } & {
            body?: SitesAddCustomizedOutboundCallerIDPhoneNumbersRequestBody;
        } & object) => Promise<BaseResponse<never>>;
        removeCustomizedOutboundCallerIDPhoneNumbers: (_: {
            path: SitesRemoveCustomizedOutboundCallerIDPhoneNumbersPathParams;
        } & object & {
            query?: SitesRemoveCustomizedOutboundCallerIDPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getPhoneSiteSetting: (_: {
            path: SitesGetPhoneSiteSettingPathParams;
        } & object) => Promise<BaseResponse<SitesGetPhoneSiteSettingResponse>>;
        addSiteSetting: (_: {
            path: SitesAddSiteSettingPathParams;
        } & {
            body?: SitesAddSiteSettingRequestBody;
        } & object) => Promise<BaseResponse<SitesAddSiteSettingResponse>>;
        deleteSiteSetting: (_: {
            path: SitesDeleteSiteSettingPathParams;
        } & object & {
            query?: SitesDeleteSiteSettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateSiteSetting: (_: {
            path: SitesUpdateSiteSettingPathParams;
        } & {
            body?: SitesUpdateSiteSettingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly users: {
        listPhoneUsers: (_: object & {
            query?: UsersListPhoneUsersQueryParams;
        }) => Promise<BaseResponse<UsersListPhoneUsersResponse>>;
        updateMultipleUsersPropertiesInBatch: (_: object & {
            body?: UsersUpdateMultipleUsersPropertiesInBatchRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        batchAddUsers: (_: object & {
            body?: UsersBatchAddUsersRequestBody;
        }) => Promise<BaseResponse<UsersBatchAddUsersResponse>>;
        getUsersProfile: (_: {
            path: UsersGetUsersProfilePathParams;
        } & object) => Promise<BaseResponse<UsersGetUsersProfileResponse>>;
        updateUsersProfile: (_: {
            path: UsersUpdateUsersProfilePathParams;
        } & {
            body?: UsersUpdateUsersProfileRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateUsersCallingPlan: (_: {
            path: UsersUpdateUsersCallingPlanPathParams;
        } & {
            body: UsersUpdateUsersCallingPlanRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        assignCallingPlanToUser: (_: {
            path: UsersAssignCallingPlanToUserPathParams;
        } & {
            body?: UsersAssignCallingPlanToUserRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        unassignUsersCallingPlan: (_: {
            path: UsersUnassignUsersCallingPlanPathParams;
        } & object & {
            query?: UsersUnassignUsersCallingPlanQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listUsersPhoneNumbersForCustomizedOutboundCallerID: (_: {
            path: UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDPathParams;
        } & object & {
            query?: UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDQueryParams;
        }) => Promise<BaseResponse<UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDResponse>>;
        addPhoneNumbersForUsersCustomizedOutboundCallerID: (_: {
            path: UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDPathParams;
        } & {
            body?: UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        removeUsersCustomizedOutboundCallerIDPhoneNumbers: (_: {
            path: UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersPathParams;
        } & object & {
            query?: UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getUserPolicyDetails: (_: {
            path: UsersGetUserPolicyDetailsPathParams;
        } & object) => Promise<BaseResponse<UsersGetUserPolicyDetailsResponse>>;
        updateUserPolicy: (_: {
            path: UsersUpdateUserPolicyPathParams;
        } & {
            body?: UsersUpdateUserPolicyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUsersProfileSettings: (_: {
            path: UsersGetUsersProfileSettingsPathParams;
        } & object) => Promise<BaseResponse<UsersGetUsersProfileSettingsResponse>>;
        updateUsersProfileSettings: (_: {
            path: UsersUpdateUsersProfileSettingsPathParams;
        } & {
            body?: UsersUpdateUsersProfileSettingsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        addUsersSharedAccessSetting: (_: {
            path: UsersAddUsersSharedAccessSettingPathParams;
        } & {
            body?: UsersAddUsersSharedAccessSettingRequestBody;
        } & object) => Promise<BaseResponse<UsersAddUsersSharedAccessSettingResponse>>;
        deleteUsersSharedAccessSetting: (_: {
            path: UsersDeleteUsersSharedAccessSettingPathParams;
        } & object & {
            query?: UsersDeleteUsersSharedAccessSettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateUsersSharedAccessSetting: (_: {
            path: UsersUpdateUsersSharedAccessSettingPathParams;
        } & {
            body?: UsersUpdateUsersSharedAccessSettingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly voicemails: {
        getUserVoicemailDetailsFromCallLog: (_: {
            path: VoicemailsGetUserVoicemailDetailsFromCallLogPathParams;
        } & object) => Promise<BaseResponse<VoicemailsGetUserVoicemailDetailsFromCallLogResponse>>;
        getUsersVoicemails: (_: {
            path: VoicemailsGetUsersVoicemailsPathParams;
        } & object & {
            query?: VoicemailsGetUsersVoicemailsQueryParams;
        }) => Promise<BaseResponse<VoicemailsGetUsersVoicemailsResponse>>;
        getAccountVoicemails: (_: object & {
            query?: VoicemailsGetAccountVoicemailsQueryParams;
        }) => Promise<BaseResponse<VoicemailsGetAccountVoicemailsResponse>>;
        downloadPhoneVoicemail: (_: {
            path: VoicemailsDownloadPhoneVoicemailPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getVoicemailDetails: (_: {
            path: VoicemailsGetVoicemailDetailsPathParams;
        } & object) => Promise<BaseResponse<VoicemailsGetVoicemailDetailsResponse>>;
        deleteVoicemail: (_: {
            path: VoicemailsDeleteVoicemailPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateVoicemailReadStatus: (_: {
            path: VoicemailsUpdateVoicemailReadStatusPathParams;
        } & object & {
            query: VoicemailsUpdateVoicemailReadStatusQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly zoomRooms: {
        listZoomRoomsUnderZoomPhoneLicense: (_: object & {
            query?: ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseQueryParams;
        }) => Promise<BaseResponse<ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseResponse>>;
        addZoomRoomToZoomPhone: (_: object & {
            body?: ZoomRoomsAddZoomRoomToZoomPhoneRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        listZoomRoomsWithoutZoomPhoneAssignment: (_: object & {
            query?: ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentQueryParams;
        }) => Promise<BaseResponse<ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentResponse>>;
        getZoomRoomUnderZoomPhoneLicense: (_: {
            path: ZoomRoomsGetZoomRoomUnderZoomPhoneLicensePathParams;
        } & object) => Promise<BaseResponse<ZoomRoomsGetZoomRoomUnderZoomPhoneLicenseResponse>>;
        removeZoomRoomFromZPAccount: (_: {
            path: ZoomRoomsRemoveZoomRoomFromZPAccountPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateZoomRoomUnderZoomPhoneLicense: (_: {
            path: ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicensePathParams;
        } & {
            body?: ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicenseRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        assignCallingPlansToZoomRoom: (_: {
            path: ZoomRoomsAssignCallingPlansToZoomRoomPathParams;
        } & {
            body?: ZoomRoomsAssignCallingPlansToZoomRoomRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        removeCallingPlanFromZoomRoom: (_: {
            path: ZoomRoomsRemoveCallingPlanFromZoomRoomPathParams;
        } & object & {
            query?: ZoomRoomsRemoveCallingPlanFromZoomRoomQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        assignPhoneNumbersToZoomRoom: (_: {
            path: ZoomRoomsAssignPhoneNumbersToZoomRoomPathParams;
        } & {
            body?: ZoomRoomsAssignPhoneNumbersToZoomRoomRequestBody;
        } & object) => Promise<BaseResponse<object>>;
        removePhoneNumberFromZoomRoom: (_: {
            path: ZoomRoomsRemovePhoneNumberFromZoomRoomPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
}

type PhoneRecordingDeletedEvent = Event<"phone.recording_deleted"> & {
    event: "phone.recording_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                call_id: string;
            }[];
        };
    };
};
type PhoneCallerCallLogCompletedEvent = Event<"phone.caller_call_log_completed"> & {
    event: "phone.caller_call_log_completed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                caller_number: string;
                caller_number_type: 1 | 2;
                caller_number_source?: "internal" | "external" | "byop";
                caller_name?: string;
                caller_location?: string;
                caller_did_number?: string;
                caller_country_code?: string;
                caller_country_iso_code?: string;
                callee_number: string;
                callee_number_type: 1 | 2 | 3;
                callee_number_source?: "internal" | "external" | "byop";
                callee_name?: string;
                callee_location?: string;
                callee_did_number?: string;
                callee_country_code?: string;
                callee_country_iso_code?: string;
                duration?: number;
                result: string;
                date_time: string;
                path: string;
                site?: {
                    id?: string;
                };
                has_recording?: boolean;
                recording_id?: string;
                recording_type?: string;
                has_voicemail: boolean;
                call_id: string;
                client_code?: string;
                call_type: "voip" | "pstn" | "tollfree" | "international" | "contactCenter";
                call_end_time?: string;
                direction?: "inbound" | "outbound";
                forwarded_to?: {
                    extension_number?: string;
                    extension_type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup" | "pstn";
                    location?: string;
                    name?: string;
                    number_type?: number;
                    phone_number?: string;
                };
                forwarded_by?: {
                    extension_number?: string;
                    extension_type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
                    location?: string;
                    name?: string;
                    number_type?: number;
                    phone_number?: string;
                };
                hold_time?: number;
                department?: string;
                cost_center?: string;
            }[];
        };
    };
};
type PhoneRecordingCompletedForAccessMemberEvent = Event<"phone.recording_completed_for_access_member"> & {
    event: "phone.recording_completed_for_access_member";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                caller_number: string;
                caller_number_type: 1 | 2;
                caller_name?: string;
                caller_did_number?: string;
                callee_number: string;
                callee_number_type: 1 | 2;
                callee_name: string;
                callee_did_number?: string;
                duration: number;
                download_url: string;
                date_time: string;
                user_id?: string;
                call_id?: string;
                call_log_id?: string;
                call_history_id?: string;
                end_time?: string;
                recording_type?: string;
                site?: {
                    id?: string;
                };
                owner?: {
                    type: string;
                    id: string;
                    name: string;
                    extension_number?: number;
                    has_access_permission?: boolean;
                };
                direction: "inbound" | "outbound";
                outgoing_by?: {
                    name?: string;
                    extension_number?: string;
                };
                accepted_by?: {
                    name?: string;
                    extension_number?: string;
                };
            }[];
        };
    };
};
type PhoneRecordingResumedEvent = Event<"phone.recording_resumed"> & {
    event: string;
    payload: {
        account_id: string;
        object: {
            id: string;
            user_id: string;
            caller_number: string;
            callee_number: string;
            direction: "inbound" | "outbound";
            date_time: string;
            recording_type: "OnDemand" | "Automatic";
            call_id: string;
            owner: {
                type: "user" | "callQueue" | "commonArea";
                id: string;
                name: string;
                extension_number: number;
            };
        };
    };
    event_ts: number;
};
type PhoneRecordingTranscriptCompletedEvent = Event<"phone.recording_transcript_completed"> & {
    event: "phone.recording_transcript_completed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                caller_number: string;
                caller_number_type: 1 | 2;
                caller_name?: string;
                callee_number: string;
                callee_number_type: 1 | 2;
                callee_name: string;
                duration?: number;
                transcript_download_url: string;
                date_time: string;
                user_id?: string;
                call_id?: string;
                call_log_id?: string;
                end_time?: string;
                recording_type?: string;
                site?: {
                    id: string;
                };
                owner?: {
                    type: string;
                    id: string;
                    name: string;
                    extension_number?: number;
                };
                direction: "inbound" | "outbound";
                outgoing_by?: {
                    name?: string;
                    extension_number?: string;
                };
                accepted_by?: {
                    name?: string;
                    extension_number?: string;
                };
            }[];
        };
    };
};
type PhoneCallLogPermanentlyDeletedEvent = Event<"phone.call_log_permanently_deleted"> & {
    event: "phone.call_log_permanently_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                call_id: string;
            }[];
        };
    };
};
type PhoneTransferCallToVoicemailInitiatedEvent = Event<"phone.transfer_call_to_voicemail_initiated"> & {
    event: "phone.transfer_call_to_voicemail_initiated";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            failure_reason?: string;
            call_id: string;
            transfer_phone_number: string;
            owner?: {
                extension_number?: number;
                id?: string;
                name?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "commonAreaPhone" | "sharedLineGroup";
            };
            date_time: string;
        };
    };
};
type PhoneCalleeMissedEvent = Event<"phone.callee_missed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
            call_end_time: string;
            forwarded_by?: {
                name?: string;
                extension_number?: string;
                extension_type?: string;
            };
            redirect_forwarded_by?: object;
            handup_result?: string;
        };
    };
};
type PhoneCallerRingingEvent = Event<"phone.caller_ringing"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
        };
    };
};
type PhoneVoicemailReceivedEvent = Event<"phone.voicemail_received"> & {
    event: "phone.voicemail_received";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            date_time: string;
            download_url: string;
            duration: number;
            caller_user_id?: string;
            caller_number: string;
            caller_number_type: 1 | 2;
            caller_name: string;
            caller_did_number?: string;
            callee_user_id?: string;
            callee_number: string;
            callee_number_type: 1 | 2;
            callee_name: string;
            callee_did_number?: string;
            callee_extension_type: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            callee_id: string;
            call_log_id?: string;
            call_history_id?: string;
            call_id?: string;
        };
    };
};
type PhoneSmsSentEvent = Event<"phone.sms_sent"> & {
    event: "phone.sms_sent";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            failure_reason?: string;
            sender: {
                phone_number: string;
                id?: string;
                type?: "user";
                display_name?: string;
            };
            to_members: {
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist";
                display_name?: string;
                phone_number: string;
            }[];
            owner: {
                type?: "user" | "callQueue" | "autoReceptionist";
                id?: string;
                sms_sender_user_id?: string;
            };
            message: string;
            attachments: {
                id: string;
                size: number;
                name: string;
                type: string;
                download_url: string;
            }[];
            session_id: string;
            message_id: string;
            message_type: number;
            date_time: string;
            phone_number_campaign_opt_statuses?: {
                consumer_phone_number: string;
                zoom_phone_user_number: string;
                opt_status: "pending" | "opt_out" | "opt_in";
            }[];
        };
    };
};
type PhoneVoicemailDeletedEvent = Event<"phone.voicemail_deleted"> & {
    event: "phone.voicemail_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            voice_mails: {
                id: string;
            }[];
        };
    };
};
type PhoneVoicemailTranscriptCompletedEvent = Event<"phone.voicemail_transcript_completed"> & {
    event: "phone.voicemail_transcript_completed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            date_time: string;
            caller_number: string;
            caller_number_type: 1 | 2;
            caller_name: string;
            callee_user_id?: string;
            callee_number: string;
            callee_number_type: 1 | 2;
            callee_name: string;
            callee_extension_type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            callee_id?: string;
            call_log_id?: string;
            call_history_id?: string;
            call_id?: string;
            transcription: {
                status: 0 | 1 | 2 | 4 | 5 | 9 | 11 | 12 | 13 | 14 | 409 | 415 | 422 | 500 | 601 | 602 | 603 | 999;
                content: string;
            };
        };
    };
};
type PhoneRecordingPermanentlyDeletedEvent = Event<"phone.recording_permanently_deleted"> & {
    event: "phone.recording_permanently_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                call_id: string;
            }[];
        };
    };
};
type PhonePeeringNumberEmergencyAddressUpdatedEvent = Event<"phone.peering_number_emergency_address_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            emergency_address?: {
                country?: string;
                address_line1: string;
                address_line2?: string;
                city?: string;
                zip?: string;
                state_code?: string;
            };
            carrier_code: number;
            phone_numbers: string[];
        };
    };
};
type PhoneSmsCampaignNumberOptOutEvent = Event<"phone.sms_campaign_number_opt_out"> & {
    event: "phone.sms_campaign_number_opt_out";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            phone_number_campaign_opt_statuses: {
                consumer_phone_number: string;
                zoom_phone_user_number: string;
            }[];
            date_time: string;
        };
    };
};
type PhoneCallerEndedEvent = Event<"phone.caller_ended"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
            answer_start_time?: string;
            call_end_time: string;
            handup_result?: string;
        };
    };
};
type PhoneCalleeEndedEvent = Event<"phone.callee_ended"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
            answer_start_time?: string;
            call_end_time: string;
            forwarded_by?: {
                name?: string;
                extension_number?: string;
                extension_type?: string;
            };
            redirect_forwarded_by?: {
                name?: string;
                extension_number?: string;
                phone_number?: string;
                extension_type?: string;
            };
        };
    };
};
type PhoneCalleeCallHistoryCompletedEvent = Event<"phone.callee_call_history_completed"> & {
    event: "phone.callee_call_history_completed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                call_path_id: string;
                call_id: string;
                group_id?: string;
                connect_type?: "internal" | "external";
                call_type?: "general" | "emergency";
                direction?: "inbound" | "outbound";
                hide_caller_id?: boolean;
                end_to_end?: boolean;
                caller_ext_id?: string;
                caller_name?: string;
                caller_email?: string;
                caller_employee_id?: string;
                caller_did_number?: string;
                caller_ext_number?: string;
                caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
                caller_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number";
                caller_device_private_ip?: string;
                caller_device_public_ip?: string;
                caller_device_type?: string;
                caller_country_iso_code?: string;
                caller_country_code?: string;
                caller_site_id?: string;
                caller_department?: string;
                caller_cost_center?: string;
                callee_ext_id?: string;
                callee_name?: string;
                callee_did_number?: string;
                callee_ext_number?: string;
                callee_email?: string;
                callee_employee_id?: string;
                callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
                callee_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number";
                callee_device_private_ip?: string;
                callee_device_public_ip?: string;
                callee_device_type?: string;
                callee_country_iso_code?: string;
                callee_country_code?: string;
                callee_site_id?: string;
                callee_department?: string;
                callee_cost_center?: string;
                start_time: string;
                answer_time?: string;
                end_time?: string;
                event?: "incoming" | "transfer_from_zoom_contact_center" | "shared_line_incoming" | "outgoing" | "call_me_on" | "outgoing_to_zoom_contact_center" | "warm_transfer" | "forward" | "ring_to_member" | "overflow" | "direct_transfer" | "barge" | "monitor" | "whisper" | "listen" | "takeover" | "conference_barge" | "park" | "timeout" | "park_pick_up" | "merge" | "shared";
                result: "answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable";
                result_reason?: "answered_by_other" | "pickup_by_other" | "call_out_by_other";
                operator_ext_number?: string;
                operator_ext_id?: string;
                operator_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
                operator_name?: string;
                recording_id?: string;
                recording_type?: "ad-hoc" | "automatic";
                voicemail_id?: string;
                talk_time?: number;
                hold_time?: number;
                wait_time?: number;
            }[];
        };
    };
};
type PhoneVoicemailPermanentlyDeletedEvent = Event<"phone.voicemail_permanently_deleted"> & {
    event: "phone.voicemail_permanently_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            voice_mails: {
                id: string;
            }[];
        };
    };
};
type PhoneSmsCampaignNumberOptInEvent = Event<"phone.sms_campaign_number_opt_in"> & {
    event: "phone.sms_campaign_number_opt_in";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            phone_number_campaign_opt_statuses: {
                consumer_phone_number: string;
                zoom_phone_user_number: string;
            }[];
            date_time: string;
        };
    };
};
type PhoneCalleeMuteEvent = Event<"phone.callee_mute"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneSmsEtiquetteWarnEvent = Event<"phone.sms_etiquette_warn"> & {
    event: "phone.sms_etiquette_warn";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            email: string;
            message: string;
            policy_name: string;
            date_time: string;
        };
    };
};
type PhoneCallHistoryDeletedEvent = Event<"phone.call_history_deleted"> & {
    event: "phone.call_history_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            move_to_trash?: boolean;
            execute_time?: string;
            delete_all?: boolean;
            call_log_ids?: string[];
        };
    };
};
type PhoneSmsEtiquetteBlockEvent = Event<"phone.sms_etiquette_block"> & {
    event: "phone.sms_etiquette_block";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            email: string;
            message: string;
            policy_name: string;
            date_time: string;
        };
    };
};
type PhoneCallLogDeletedEvent = Event<"phone.call_log_deleted"> & {
    event: "phone.call_log_deleted";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                call_id: string;
            }[];
        };
    };
};
type PhoneCallerHoldEvent = Event<"phone.caller_hold"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneCallerConnectedEvent = Event<"phone.caller_connected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
            connected_start_time: string;
        };
    };
};
type PhoneRecordingCompletedEvent = Event<"phone.recording_completed"> & {
    event: "phone.recording_completed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                caller_number: string;
                caller_number_type: 1 | 2;
                caller_name?: string;
                caller_did_number?: string;
                callee_number: string;
                callee_number_type: 1 | 2;
                callee_name: string;
                callee_did_number?: string;
                duration: number;
                download_url: string;
                date_time: string;
                user_id?: string;
                call_id?: string;
                call_log_id?: string;
                call_history_id?: string;
                end_time?: string;
                recording_type?: string;
                site?: {
                    id?: string;
                };
                owner?: {
                    type: string;
                    id: string;
                    name: string;
                    extension_number?: number;
                    has_access_permission?: boolean;
                };
                direction: "inbound" | "outbound";
                outgoing_by?: {
                    name?: string;
                    extension_number?: string;
                };
                accepted_by?: {
                    name?: string;
                    extension_number?: string;
                };
            }[];
        };
    };
};
type PhoneRecordingStartedEvent = Event<"phone.recording_started"> & {
    event: string;
    payload: {
        account_id: string;
        object: {
            id: string;
            user_id: string;
            caller_number: string;
            callee_number: string;
            direction: "inbound" | "outbound";
            date_time: string;
            recording_type: "OnDemand" | "Automatic";
            call_id: string;
            channel_id: string;
            sip_id: string;
            owner: {
                type: "user" | "callQueue" | "commonArea";
                id: string;
                name: string;
                extension_number?: number;
            };
        };
    };
    event_ts: number;
};
type PhoneSmsSentFailedEvent = Event<"phone.sms_sent_failed"> & {
    event: "phone.sms_sent_failed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            failure_reason?: string;
            sender: {
                phone_number: string;
                id?: string;
                type?: "user";
                display_name?: string;
            };
            to_members: {
                id?: string;
                display_name?: string;
                phone_number: string;
                is_message_owner?: boolean;
            }[];
            owner: {
                type?: "user" | "callQueue" | "autoReceptionist";
                id?: string;
                sms_sender_user_id?: string;
            };
            message: string;
            attachments: {
                id: string;
                size: number;
                name: string;
                type: string;
                download_url: string;
            }[];
            session_id: string;
            message_id: string;
            message_type: number;
            date_time: string;
            phone_number_campaign_opt_statuses?: {
                consumer_phone_number: string;
                zoom_phone_user_number: string;
                opt_status: "pending" | "opt_out" | "opt_in";
            }[];
        };
    };
};
type PhoneCalleeCallLogCompletedEvent = Event<"phone.callee_call_log_completed"> & {
    event: "phone.callee_call_log_completed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                caller_user_id?: string;
                caller_number: string;
                caller_number_type: 1 | 2;
                caller_number_source?: "internal" | "external" | "byop";
                caller_name?: string;
                caller_location?: string;
                caller_did_number?: string;
                caller_country_code?: string;
                caller_country_iso_code?: string;
                callee_user_id?: string;
                callee_number: string;
                callee_number_type: 1 | 2;
                callee_number_source?: "internal" | "external" | "byop";
                callee_name?: string;
                callee_location?: string;
                callee_did_number?: string;
                callee_country_code?: string;
                callee_country_iso_code?: string;
                duration?: number;
                result: string;
                date_time: string;
                path: string;
                site?: {
                    id?: string;
                };
                has_recording?: boolean;
                recording_id?: string;
                recording_type?: string;
                has_voicemail: boolean;
                call_id: string;
                client_code?: string;
                call_type?: "voip" | "pstn" | "tollfree" | "international" | "contactCenter";
                call_end_time?: string;
                direction?: "inbound" | "outbound";
                answer_start_time?: string;
                waiting_time?: number;
                forwarded_to?: {
                    extension_number?: string;
                    extension_type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
                    location?: string;
                    name?: string;
                    number_type?: number;
                    phone_number?: string;
                };
                forwarded_by?: {
                    extension_number?: string;
                    extension_type?: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
                    location?: string;
                    name?: string;
                    number_type?: number;
                    phone_number?: string;
                };
                hold_time?: number;
                department?: string;
                cost_center?: string;
            }[];
        };
    };
};
type PhoneCalleeRingingEvent = Event<"phone.callee_ringing"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
            forwarded_by?: {
                name?: string;
                extension_number?: string;
                extension_type?: string;
            };
            redirect_forwarded_by?: {
                name?: string;
                extension_number?: string;
                phone_number?: string;
                extension_type?: string;
            };
        };
    };
};
type PhoneCallerUnholdEvent = Event<"phone.caller_unhold"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneCalleeHoldEvent = Event<"phone.callee_hold"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneCalleeAnsweredEvent = Event<"phone.callee_answered"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
            answer_start_time: string;
            forwarded_by?: {
                name?: string;
                extension_number?: string;
                extension_type?: string;
            };
            redirect_forwarded_by?: {
                name?: string;
                extension_number?: string;
                phone_number?: string;
                extension_type?: string;
            };
        };
    };
};
type PhoneCallerUnmuteEvent = Event<"phone.caller_unmute"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneDeviceRegistrationEvent = Event<"phone.device_registration"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            device_id: string;
            device_name: string;
            mac_address: string;
        };
    };
};
type PhoneBlindTransferInitiatedEvent = Event<"phone.blind_transfer_initiated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            failure_reason?: string;
            call_id: string;
            transfer_phone_number: string;
            owner?: {
                extension_number?: number;
                id?: string;
                name?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "commonAreaPhone" | "sharedLineGroup";
            };
            date_time: string;
        };
    };
};
type PhoneAccountSettingsUpdatedEvent = Event<"phone.account_settings_updated"> & {
    event: "phone.account_settings_updated";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            settings: {
                call_live_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    transcription_start_prompt?: {
                        enable?: boolean;
                        audio_id?: string;
                        audio_name?: string;
                    };
                };
                local_survivability_mode?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                external_calling_on_zoom_room_common_area?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_videomail?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    allow_share?: boolean;
                    allow_virtual_background?: boolean;
                };
                voicemail_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    time_zone?: {
                        id?: string;
                        name?: string;
                    };
                    restricted_hours_applied?: boolean;
                    restricted_holiday_hours_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                allowed_call_locations?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    recording_calls?: "inbound" | "outbound" | "both";
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: "allMembers" | "recordingUser";
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: "allMembers" | "recordingUser";
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                    };
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    international_sms?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: 1 | 2;
                        content?: string;
                        action?: 1 | 2;
                        active?: boolean;
                    }[];
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_forwarding_type?: 1 | 2 | 3 | 4;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_overflow_type?: 1 | 2 | 3 | 4;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_transferring_type?: 1 | 2 | 3 | 4;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                call_park?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: "user" | "zoomRoom" | "commonArea" | "ciscoRoom/polycomRoom" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                        id?: string;
                    };
                    sequence?: 0 | 1;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: 0 | 9;
                };
                call_queue_opt_out_reason?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_queue_opt_out_reasons_list?: {
                        code?: string;
                        system?: boolean;
                        enable?: boolean;
                    }[];
                };
                auto_delete_data_after_retention_duration?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    items?: {
                        type?: "callLog" | "onDemandRecording" | "automaticRecording" | "voicemail" | "videomail" | "sms";
                        duration?: number;
                        time_unit?: "year" | "month" | "day";
                    }[];
                    delete_type?: 1 | 2;
                };
                auto_call_from_third_party_apps?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                override_default_port?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    min_port?: number;
                    max_port?: number;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    feedback_type?: 1 | 2;
                    feedback_mos?: {
                        enable?: boolean;
                        min?: string;
                        max?: string;
                    };
                    feedback_duration?: {
                        enable?: boolean;
                        min?: number;
                        max?: number;
                    };
                };
            };
        };
        old_object: {
            id: string;
            settings: {
                call_live_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    transcription_start_prompt?: {
                        enable?: boolean;
                        audio_id?: string;
                        audio_name?: string;
                    };
                };
                local_survivability_mode?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                external_calling_on_zoom_room_common_area?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_videomail?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    allow_share?: boolean;
                    allow_virtual_background?: boolean;
                };
                voicemail_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    time_zone?: {
                        id?: string;
                        name?: string;
                    };
                    restricted_hours_applied?: boolean;
                    restricted_holiday_hours_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                allowed_call_locations?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    recording_calls?: "inbound" | "outbound" | "both";
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: "allMembers" | "recordingUser";
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: "allMembers" | "recordingUser";
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                    };
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    international_sms?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: 1 | 2;
                        content?: string;
                        action?: 1 | 2;
                        active?: boolean;
                    }[];
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_forwarding_type?: 1 | 2 | 3 | 4;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_overflow_type?: 1 | 2 | 3 | 4;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_transferring_type?: 1 | 2 | 3 | 4;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                call_park?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: "user" | "zoomRoom" | "commonArea" | "ciscoRoom/polycomRoom" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                        id?: string;
                    };
                    sequence?: 0 | 1;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: 0 | 9;
                };
                call_queue_opt_out_reason?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    call_queue_opt_out_reasons_list?: {
                        code?: string;
                        system?: boolean;
                        enable?: boolean;
                    }[];
                };
                auto_delete_data_after_retention_duration?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    items?: {
                        type?: "callLog" | "onDemandRecording" | "automaticRecording" | "voicemail" | "videomail" | "sms";
                        duration?: number;
                        time_unit?: "year" | "month" | "day";
                    }[];
                    delete_type?: 1 | 2;
                };
                auto_call_from_third_party_apps?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                override_default_port?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    min_port?: number;
                    max_port?: number;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account";
                    feedback_type?: 1 | 2;
                    feedback_mos?: {
                        enable?: boolean;
                        min?: string;
                        max?: string;
                    };
                    feedback_duration?: {
                        enable?: boolean;
                        min?: number;
                        max?: number;
                    };
                };
            };
        };
    };
};
type PhoneCalleeMeetingInvitingEvent = Event<"phone.callee_meeting_inviting"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            meeting_id?: string;
            date_time: string;
        };
    };
};
type PhoneCalleeParkedEvent = Event<"phone.callee_parked"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            park_code?: string;
            park_failure_reason?: string;
            date_time: string;
        };
    };
};
type PhoneEmergencyAlertEvent = Event<"phone.emergency_alert"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            caller: {
                id: string;
                phone_number?: string;
                extension_number?: string;
                timezone?: string;
                display_name?: string;
                extension_type: "user" | "interop" | "commonAreaPhone";
                site_id?: string;
                site_name?: string;
            };
            callee: {
                phone_number?: string;
            };
            location: {
                gps?: string[];
                ip?: string[];
                bssid?: string[];
            };
            router: "ZOOM" | "BYOC Carrier" | "Mobile Carrier";
            deliver_to: "PSAP" | "SAFETY_TEAM" | "NONE" | "BOTH" | "MOBILE_911_CALL" | "SIP_GROUP" | "BOTH_SAFETY_TEAM_AND_SIP" | "OVERFLOW_TO_SIP_GROUP" | "TO_PSAP_FOR_MISSED_BY_SAFETY_TEAM";
            ringing_start_time: string;
            emergency_address?: {
                country?: string;
                address_line1?: string;
                address_line2?: string;
                city?: string;
                zip?: string;
                state_code?: string;
            };
        };
    };
};
type PhoneAiCallSummaryChangedEvent = Event<"phone.ai_call_summary_changed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            edited?: boolean;
            deleted?: boolean;
            ai_call_summary_id: string;
            user_id: string;
            call_id: string;
            call_log_ids?: string[];
            created_time?: string;
            modified_time?: string;
        };
    };
};
type PhoneCalleeRejectedEvent = Event<"phone.callee_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            ringing_start_time: string;
            call_end_time: string;
            handup_result?: string;
        };
    };
};
type PhoneGroupSettingsUpdatedEvent = Event<"phone.group_settings_updated"> & {
    event: "phone.group_settings_updated";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            group_id: string;
            settings: {
                call_live_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    transcription_start_prompt?: {
                        enable?: boolean;
                        audio_id?: string;
                        audio_name?: string;
                    };
                };
                local_survivability_mode?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_delete?: boolean;
                    allow_download?: boolean;
                    allow_videomail?: boolean;
                    allow_share?: boolean;
                    allow_virtual_background?: boolean;
                };
                voicemail_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                voicemail_notification_by_email?: {
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    time_zone?: {
                        id?: string;
                        name?: string;
                    };
                    restricted_hours_applied?: boolean;
                    restricted_holiday_hours_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                allowed_call_locations?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    recording_calls?: "inbound" | "outbound" | "both";
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                        play_beep_member?: "allMember" | "recordingSide";
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "site";
                    modified?: boolean;
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                        play_beep_member?: "allMember" | "recordingSide";
                    };
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    modified?: boolean;
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: 1 | 2;
                        content?: string;
                        action?: 1 | 2;
                        active?: boolean;
                    }[];
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                sms?: {
                    enable?: boolean;
                    international_sms?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    call_forwarding_type?: 1 | 2 | 3 | 4;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    call_overflow_type?: 1 | 2 | 3 | 4;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    call_transferring_type?: 1 | 2 | 3 | 4;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                call_park?: {
                    enable?: boolean;
                    expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: "user" | "zoomRoom" | "commonArea" | "ciscoRoom/polycomRoom" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                        id?: string;
                    };
                    sequence?: 0 | 1;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: 0 | 9;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    feedback_type?: 1 | 2;
                    feedback_mos?: {
                        enable?: boolean;
                        min?: string;
                        max?: string;
                    };
                    feedback_duration?: {
                        enable?: boolean;
                        min?: number;
                        max?: number;
                    };
                };
            };
        };
        old_object: {
            group_id: string;
            settings: {
                call_live_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    transcription_start_prompt?: {
                        enable?: boolean;
                        audio_id?: string;
                        audio_name?: string;
                    };
                };
                local_survivability_mode?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_delete?: boolean;
                    allow_download?: boolean;
                    allow_videomail?: boolean;
                    allow_share?: boolean;
                    allow_virtual_background?: boolean;
                };
                voicemail_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                voicemail_notification_by_email?: {
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    time_zone?: {
                        id?: string;
                        name?: string;
                    };
                    restricted_hours_applied?: boolean;
                    restricted_holiday_hours_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                allowed_call_locations?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    recording_calls?: "inbound" | "outbound" | "both";
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                        play_beep_member?: "allMember" | "recordingSide";
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "site";
                    modified?: boolean;
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: 0 | 20 | 40 | 60 | 80 | 100;
                        play_beep_time_interval?: 5 | 10 | 15 | 20 | 25 | 30 | 60 | 120;
                        play_beep_member?: "allMember" | "recordingSide";
                    };
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    modified?: boolean;
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: 1 | 2;
                        content?: string;
                        action?: 1 | 2;
                        active?: boolean;
                    }[];
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                sms?: {
                    enable?: boolean;
                    international_sms?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    call_forwarding_type?: 1 | 2 | 3 | 4;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    call_overflow_type?: 1 | 2 | 3 | 4;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    call_transferring_type?: 1 | 2 | 3 | 4;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                call_park?: {
                    enable?: boolean;
                    expiration_period?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | 60;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: "user" | "zoomRoom" | "commonArea" | "ciscoRoom/polycomRoom" | "autoReceptionist" | "callQueue" | "sharedLineGroup";
                        id?: string;
                    };
                    sequence?: 0 | 1;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: 0 | 9;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: "invalid" | "account" | "user_group";
                    modified?: boolean;
                    feedback_type?: 1 | 2;
                    feedback_mos?: {
                        enable?: boolean;
                        min?: string;
                        max?: string;
                    };
                    feedback_duration?: {
                        enable?: boolean;
                        min?: number;
                        max?: number;
                    };
                };
            };
        };
    };
};
type PhoneCalleeUnmuteEvent = Event<"phone.callee_unmute"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneRecordingStoppedEvent = Event<"phone.recording_stopped"> & {
    event: string;
    payload: {
        account_id: string;
        object: {
            id: string;
            user_id: string;
            caller_number: string;
            callee_number: string;
            direction: "inbound" | "outbound";
            date_time: string;
            recording_type: "OnDemand" | "Automatic";
            call_id: string;
            channel_id: string;
            sip_id: string;
            owner: {
                type: "user" | "callQueue" | "commonArea";
                id: string;
                name: string;
                extension_number?: number;
            };
        };
    };
    event_ts: number;
};
type PhoneCallerMeetingInvitingEvent = Event<"phone.caller_meeting_inviting"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            meeting_id?: string;
            date_time: string;
        };
    };
};
type PhoneVoicemailReceivedForAccessMemberEvent = Event<"phone.voicemail_received_for_access_member"> & {
    event: "phone.voicemail_received_for_access_member";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            date_time: string;
            download_url: string;
            duration: number;
            caller_number: string;
            caller_number_type: 1 | 2;
            caller_name: string;
            caller_did_number?: string;
            callee_user_id?: string;
            callee_number: string;
            callee_number_type: 1 | 2;
            callee_name: string;
            callee_did_number?: string;
            callee_extension_type: "user" | "callQueue" | "autoReceptionist" | "sharedLineGroup";
            callee_id: string;
            call_log_id?: string;
            call_history_id?: string;
            call_id?: string;
            access_member_id?: string;
            access_member_extension_type?: "user" | "commonAreaPhone";
        };
    };
};
type PhoneCalleeUnholdEvent = Event<"phone.callee_unhold"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneConferenceStartedEvent = Event<"phone.conference_started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            failure_reason?: string;
            enable_multiple_party_conference?: boolean;
            conference_id?: string;
            call_id: string;
            owner?: {
                extension_number?: number;
                id?: string;
                name?: string;
                type?: "user" | "callQueue" | "autoReceptionist" | "commonAreaPhone" | "sharedLineGroup";
            };
            date_time: string;
        };
    };
};
type PhoneGenericDeviceProvisionEvent = Event<"phone.generic_device_provision"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            display_name: string;
            device_type: string;
            mac_address: string;
            site?: {
                id: string;
                name: string;
            };
            provision?: {
                type: "manual";
                sip_accounts?: {
                    sip_domain?: string;
                    outbound_proxy: string;
                    secondary_outbound_proxy?: string;
                    user_name: string;
                    authorization_id: string;
                    password: string;
                    shared_line?: {
                        line_subscription: {
                            phone_number?: string;
                            extension_number?: number;
                            display_name?: string;
                        };
                        alias?: string;
                        outbound_caller_id?: string;
                    };
                }[];
            };
        };
    };
};
type PhoneRecordingPausedEvent = Event<"phone.recording_paused"> & {
    event: string;
    payload: {
        account_id: string;
        object: {
            id: string;
            user_id: string;
            caller_number: string;
            callee_number: string;
            direction: "inbound" | "outbound";
            date_time: string;
            recording_type: "OnDemand" | "Automatic";
            call_id: string;
            owner: {
                type: "user" | "callQueue" | "commonArea";
                id: string;
                name: string;
                extension_number?: number;
            };
        };
    };
    event_ts: number;
};
type PhoneSmsReceivedEvent = Event<"phone.sms_received"> & {
    event: "phone.sms_received";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            sender: {
                phone_number: string;
                id?: string;
                type?: "user" | "callQueue" | "autoReceptionist";
                display_name?: string;
            };
            to_members: {
                id?: string;
                type?: "user";
                display_name?: string;
                phone_number: string;
                is_message_owner?: boolean;
            }[];
            owner: {
                type?: "user" | "callQueue" | "autoReceptionist";
                id?: string;
                team_id?: string;
            };
            message: string;
            attachments: {
                id: string;
                size: number;
                name: string;
                type: string;
                download_url: string;
            }[];
            session_id: string;
            message_id: string;
            message_type: number;
            date_time: string;
            phone_number_campaign_opt_statuses?: {
                consumer_phone_number: string;
                zoom_phone_user_number: string;
                opt_status: "pending" | "opt_out" | "opt_in";
            }[];
        };
    };
};
type PhoneRecordingFailedEvent = Event<"phone.recording_failed"> & {
    event: string;
    payload: {
        account_id: string;
        object: {
            id: string;
            user_id: string;
            caller_number: string;
            callee_number: string;
            direction: "inbound" | "outbound";
            date_time: string;
            recording_type: "OnDemand" | "Automatic";
            call_id: string;
            channel_id: string;
            sip_id: string;
            owner: {
                type: "user" | "callQueue" | "commonArea";
                id: string;
                name: string;
                extension_number?: number;
            };
        };
    };
    event_ts: number;
};
type PhoneCallerCallHistoryCompletedEvent = Event<"phone.caller_call_history_completed"> & {
    event: "phone.caller_call_history_completed";
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                call_path_id: string;
                call_id: string;
                group_id?: string;
                connect_type?: "internal" | "external";
                call_type?: "general" | "emergency";
                direction?: "inbound" | "outbound";
                hide_caller_id?: boolean;
                end_to_end?: boolean;
                caller_ext_id?: string;
                caller_name?: string;
                caller_email?: string;
                caller_employee_id?: string;
                caller_did_number?: string;
                caller_ext_number?: string;
                caller_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
                caller_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number";
                caller_device_private_ip?: string;
                caller_device_public_ip?: string;
                caller_device_type?: string;
                caller_country_iso_code?: string;
                caller_country_code?: string;
                caller_site_id?: string;
                caller_department?: string;
                caller_cost_center?: string;
                callee_ext_id?: string;
                callee_name?: string;
                callee_did_number?: string;
                callee_ext_number?: string;
                callee_email?: string;
                callee_employee_id?: string;
                callee_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
                callee_number_type?: "zoom_pstn" | "zoom_toll_free_number" | "external_pstn" | "external_contact" | "byoc" | "byop" | "3rd_party_contact_center" | "zoom_service_number" | "external_service_number" | "zoom_contact_center" | "meeting_phone_number" | "meeting_id" | "anonymous_number";
                callee_device_private_ip?: string;
                callee_device_public_ip?: string;
                callee_device_type?: string;
                callee_country_iso_code?: string;
                callee_country_code?: string;
                callee_site_id?: string;
                callee_department?: string;
                callee_cost_center?: string;
                start_time: string;
                answer_time?: string;
                end_time?: string;
                event?: "incoming" | "transfer_from_zoom_contact_center" | "shared_line_incoming" | "outgoing" | "call_me_on" | "outgoing_to_zoom_contact_center" | "warm_transfer" | "forward" | "ring_to_member" | "overflow" | "direct_transfer" | "barge" | "monitor" | "whisper" | "listen" | "takeover" | "conference_barge" | "park" | "timeout" | "park_pick_up" | "merge" | "shared";
                result: "answered" | "accepted" | "picked_up" | "connected" | "succeeded" | "voicemail" | "hang_up" | "canceled" | "call_failed" | "unconnected" | "rejected" | "busy" | "ring_timeout" | "overflowed" | "no_answer" | "invalid_key" | "invalid_operation" | "abandoned" | "system_blocked" | "service_unavailable";
                result_reason?: "answered_by_other" | "pickup_by_other" | "call_out_by_other";
                operator_ext_number?: string;
                operator_ext_id?: string;
                operator_ext_type?: "user" | "call_queue" | "auto_receptionist" | "common_area" | "zoom_room" | "cisco_room" | "shared_line_group" | "group_call_pickup" | "external_contact";
                operator_name?: string;
                recording_id?: string;
                recording_type?: "ad-hoc" | "automatic";
                voicemail_id?: string;
                talk_time?: number;
                hold_time?: number;
                wait_time?: number;
            }[];
        };
    };
};
type PhonePeeringNumberCnamUpdatedEvent = Event<"phone.peering_number_cnam_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            cnam?: string;
            carrier_code: number;
            phone_numbers: string[];
        };
    };
};
type PhoneCallerMuteEvent = Event<"phone.caller_mute"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            caller: {
                extension_id?: string;
                extension_type?: "user" | "callQueue" | "autoReceptionist" | "commonArea" | "commonAreaPhone" | "sharedLineGroup" | "zoomRoom" | "ciscoRoom/PolycomRoom" | "contactCenter" | "pstn" | "five9" | "twilio";
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: "pstn_off_net" | "voip" | "pstn_on_net" | "contact_center" | "byop";
            };
            date_time: string;
        };
    };
};
type PhoneEvents = PhoneRecordingDeletedEvent | PhoneCallerCallLogCompletedEvent | PhoneRecordingCompletedForAccessMemberEvent | PhoneRecordingResumedEvent | PhoneRecordingTranscriptCompletedEvent | PhoneCallLogPermanentlyDeletedEvent | PhoneTransferCallToVoicemailInitiatedEvent | PhoneCalleeMissedEvent | PhoneCallerRingingEvent | PhoneVoicemailReceivedEvent | PhoneSmsSentEvent | PhoneVoicemailDeletedEvent | PhoneVoicemailTranscriptCompletedEvent | PhoneRecordingPermanentlyDeletedEvent | PhonePeeringNumberEmergencyAddressUpdatedEvent | PhoneSmsCampaignNumberOptOutEvent | PhoneCallerEndedEvent | PhoneCalleeEndedEvent | PhoneCalleeCallHistoryCompletedEvent | PhoneVoicemailPermanentlyDeletedEvent | PhoneSmsCampaignNumberOptInEvent | PhoneCalleeMuteEvent | PhoneSmsEtiquetteWarnEvent | PhoneCallHistoryDeletedEvent | PhoneSmsEtiquetteBlockEvent | PhoneCallLogDeletedEvent | PhoneCallerHoldEvent | PhoneCallerConnectedEvent | PhoneRecordingCompletedEvent | PhoneRecordingStartedEvent | PhoneSmsSentFailedEvent | PhoneCalleeCallLogCompletedEvent | PhoneCalleeRingingEvent | PhoneCallerUnholdEvent | PhoneCalleeHoldEvent | PhoneCalleeAnsweredEvent | PhoneCallerUnmuteEvent | PhoneDeviceRegistrationEvent | PhoneBlindTransferInitiatedEvent | PhoneAccountSettingsUpdatedEvent | PhoneCalleeMeetingInvitingEvent | PhoneCalleeParkedEvent | PhoneEmergencyAlertEvent | PhoneAiCallSummaryChangedEvent | PhoneCalleeRejectedEvent | PhoneGroupSettingsUpdatedEvent | PhoneCalleeUnmuteEvent | PhoneRecordingStoppedEvent | PhoneCallerMeetingInvitingEvent | PhoneVoicemailReceivedForAccessMemberEvent | PhoneCalleeUnholdEvent | PhoneConferenceStartedEvent | PhoneGenericDeviceProvisionEvent | PhoneRecordingPausedEvent | PhoneSmsReceivedEvent | PhoneRecordingFailedEvent | PhoneCallerCallHistoryCompletedEvent | PhonePeeringNumberCnamUpdatedEvent | PhoneCallerMuteEvent;
declare class PhoneEventProcessor extends EventManager<PhoneEndpoints, PhoneEvents> {
}

type PhoneOptions<R extends Receiver> = CommonClientOptions<OAuth, R>;
declare class PhoneOAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<OAuth, ReceiverType> = PhoneOptions<ReceiverType>> extends ProductClient<OAuth, PhoneEndpoints, PhoneEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, ...restOptions }: OptionsType): OAuth;
    protected initEndpoints(auth: OAuth, options: OptionsType): PhoneEndpoints;
    protected initEventProcessor(endpoints: PhoneEndpoints): PhoneEventProcessor;
}

type PhoneS2SAuthOptions<R extends Receiver> = CommonClientOptions<S2SAuth, R>;
declare class PhoneS2SAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<S2SAuth, ReceiverType> = PhoneS2SAuthOptions<ReceiverType>> extends ProductClient<S2SAuth, PhoneEndpoints, PhoneEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, accountId }: OptionsType): S2SAuth;
    protected initEndpoints(auth: S2SAuth, options: OptionsType): PhoneEndpoints;
    protected initEventProcessor(endpoints: PhoneEndpoints): PhoneEventProcessor;
}

export { ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, CommonHttpRequestError, ConsoleLogger, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, LogLevel, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, PhoneEndpoints, PhoneEventProcessor, PhoneOAuthClient, PhoneS2SAuthClient, ProductClientConstructionError, ReceiverInconsistentStateError, ReceiverOAuthFlowError, S2SRawResponseError, StatusCode, isCoreError, isStateStore };
export type { AccountsAddPhoneNumbersForAccountsCustomizedOutboundCallerIDRequestBody, AccountsAddPhoneNumbersForAccountsCustomizedOutboundCallerIDResponse, AccountsDeletePhoneNumbersForAccountsCustomizedOutboundCallerIDQueryParams, AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersQueryParams, AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersResponse, AccountsListAccountsZoomPhoneSettingsQueryParams, AccountsListAccountsZoomPhoneSettingsResponse, AlertsAddAlertSettingRequestBody, AlertsAddAlertSettingResponse, AlertsDeleteAlertSettingPathParams, AlertsGetAlertSettingDetailsPathParams, AlertsGetAlertSettingDetailsResponse, AlertsListAlertSettingsWithPagingQueryQueryParams, AlertsListAlertSettingsWithPagingQueryResponse, AlertsUpdateAlertSettingPathParams, AlertsUpdateAlertSettingRequestBody, AudioLibraryAddAudioItemForTextToSpeechConversionPathParams, AudioLibraryAddAudioItemForTextToSpeechConversionRequestBody, AudioLibraryAddAudioItemForTextToSpeechConversionResponse, AudioLibraryAddAudioItemsPathParams, AudioLibraryAddAudioItemsRequestBody, AudioLibraryAddAudioItemsResponse, AudioLibraryDeleteAudioItemPathParams, AudioLibraryGetAudioItemPathParams, AudioLibraryGetAudioItemResponse, AudioLibraryListAudioItemsPathParams, AudioLibraryListAudioItemsResponse, AudioLibraryUpdateAudioItemPathParams, AudioLibraryUpdateAudioItemRequestBody, AutoReceptionistsAddAutoReceptionistRequestBody, AutoReceptionistsAddAutoReceptionistResponse, AutoReceptionistsAddPolicySubsettingPathParams, AutoReceptionistsAddPolicySubsettingRequestBody, AutoReceptionistsAddPolicySubsettingResponse, AutoReceptionistsAssignPhoneNumbersPathParams, AutoReceptionistsAssignPhoneNumbersRequestBody, AutoReceptionistsDeleteNonPrimaryAutoReceptionistPathParams, AutoReceptionistsDeletePolicySubsettingPathParams, AutoReceptionistsDeletePolicySubsettingQueryParams, AutoReceptionistsGetAutoReceptionistPathParams, AutoReceptionistsGetAutoReceptionistPolicyPathParams, AutoReceptionistsGetAutoReceptionistPolicyResponse, AutoReceptionistsGetAutoReceptionistResponse, AutoReceptionistsListAutoReceptionistsQueryParams, AutoReceptionistsListAutoReceptionistsResponse, AutoReceptionistsUnassignAllPhoneNumbersPathParams, AutoReceptionistsUnassignPhoneNumberPathParams, AutoReceptionistsUpdateAutoReceptionistPathParams, AutoReceptionistsUpdateAutoReceptionistPolicyPathParams, AutoReceptionistsUpdateAutoReceptionistPolicyRequestBody, AutoReceptionistsUpdateAutoReceptionistRequestBody, AutoReceptionistsUpdatePolicySubsettingPathParams, AutoReceptionistsUpdatePolicySubsettingRequestBody, BillingAccountGetBillingAccountDetailsPathParams, BillingAccountGetBillingAccountDetailsResponse, BillingAccountListBillingAccountsQueryParams, BillingAccountListBillingAccountsResponse, BlockedListCreateBlockedListRequestBody, BlockedListCreateBlockedListResponse, BlockedListDeleteBlockedListPathParams, BlockedListGetBlockedListDetailsPathParams, BlockedListGetBlockedListDetailsResponse, BlockedListListBlockedListsQueryParams, BlockedListListBlockedListsResponse, BlockedListUpdateBlockedListPathParams, BlockedListUpdateBlockedListRequestBody, CallHandlingAddCallHandlingSettingPathParams, CallHandlingAddCallHandlingSettingRequestBody, CallHandlingAddCallHandlingSettingResponse, CallHandlingDeleteCallHandlingSettingPathParams, CallHandlingDeleteCallHandlingSettingQueryParams, CallHandlingGetCallHandlingSettingsPathParams, CallHandlingGetCallHandlingSettingsResponse, CallHandlingUpdateCallHandlingSettingPathParams, CallHandlingUpdateCallHandlingSettingRequestBody, CallLogsAddClientCodeToCallHistoryPathParams, CallLogsAddClientCodeToCallHistoryRequestBody, CallLogsAddClientCodeToCallLogPathParams, CallLogsAddClientCodeToCallLogRequestBody, CallLogsDeleteUsersCallHistoryPathParams, CallLogsDeleteUsersCallLogPathParams, CallLogsGetAccountsCallHistoryQueryParams, CallLogsGetAccountsCallHistoryResponse, CallLogsGetAccountsCallLogsQueryParams, CallLogsGetAccountsCallLogsResponse, CallLogsGetCallHistoryDetailPathParams, CallLogsGetCallHistoryDetailResponse, CallLogsGetCallLogDetailsPathParams, CallLogsGetCallLogDetailsResponse, CallLogsGetCallPathPathParams, CallLogsGetCallPathResponse, CallLogsGetUserAICallSummaryDetailPathParams, CallLogsGetUserAICallSummaryDetailResponse, CallLogsGetUsersCallHistoryPathParams, CallLogsGetUsersCallHistoryQueryParams, CallLogsGetUsersCallHistoryResponse, CallLogsGetUsersCallLogsPathParams, CallLogsGetUsersCallLogsQueryParams, CallLogsGetUsersCallLogsResponse, CallLogsSyncUsersCallHistoryPathParams, CallLogsSyncUsersCallHistoryQueryParams, CallLogsSyncUsersCallHistoryResponse, CallLogsSyncUsersCallLogsPathParams, CallLogsSyncUsersCallLogsQueryParams, CallLogsSyncUsersCallLogsResponse, CallQueuesAddMembersToCallQueuePathParams, CallQueuesAddMembersToCallQueueRequestBody, CallQueuesAddPolicySubsettingToCallQueuePathParams, CallQueuesAddPolicySubsettingToCallQueueRequestBody, CallQueuesAddPolicySubsettingToCallQueueResponse, CallQueuesAssignNumbersToCallQueuePathParams, CallQueuesAssignNumbersToCallQueueRequestBody, CallQueuesCreateCallQueueRequestBody, CallQueuesCreateCallQueueResponse, CallQueuesDeleteCQPolicySettingPathParams, CallQueuesDeleteCQPolicySettingQueryParams, CallQueuesDeleteCallQueuePathParams, CallQueuesGetCallQueueDetailsPathParams, CallQueuesGetCallQueueDetailsResponse, CallQueuesGetCallQueueRecordingsPathParams, CallQueuesGetCallQueueRecordingsQueryParams, CallQueuesGetCallQueueRecordingsResponse, CallQueuesListCallQueueAnalyticsQueryParams, CallQueuesListCallQueueAnalyticsResponse, CallQueuesListCallQueueMembersPathParams, CallQueuesListCallQueueMembersResponse, CallQueuesListCallQueuesQueryParams, CallQueuesListCallQueuesResponse, CallQueuesUnassignAllMembersPathParams, CallQueuesUnassignAllPhoneNumbersPathParams, CallQueuesUnassignMemberPathParams, CallQueuesUnassignPhoneNumberPathParams, CallQueuesUpdateCallQueueDetailsPathParams, CallQueuesUpdateCallQueueDetailsRequestBody, CallQueuesUpdateCallQueuesPolicySubsettingPathParams, CallQueuesUpdateCallQueuesPolicySubsettingRequestBody, CarrierResellerActivatePhoneNumbersRequestBody, CarrierResellerCreatePhoneNumbersRequestBody, CarrierResellerDeletePhoneNumberPathParams, CarrierResellerListPhoneNumbersQueryParams, CarrierResellerListPhoneNumbersResponse, ClientCredentialsToken, CommonAreasAddCommonAreaRequestBody, CommonAreasAddCommonAreaResponse, CommonAreasAddCommonAreaSettingPathParams, CommonAreasAddCommonAreaSettingRequestBody, CommonAreasAddCommonAreaSettingResponse, CommonAreasApplyTemplateToCommonAreasPathParams, CommonAreasApplyTemplateToCommonAreasRequestBody, CommonAreasAssignCallingPlansToCommonAreaPathParams, CommonAreasAssignCallingPlansToCommonAreaRequestBody, CommonAreasAssignCallingPlansToCommonAreaResponse, CommonAreasAssignPhoneNumbersToCommonAreaPathParams, CommonAreasAssignPhoneNumbersToCommonAreaRequestBody, CommonAreasAssignPhoneNumbersToCommonAreaResponse, CommonAreasDeleteCommonAreaPathParams, CommonAreasDeleteCommonAreaSettingPathParams, CommonAreasDeleteCommonAreaSettingQueryParams, CommonAreasGenerateActivationCodesForCommonAreasRequestBody, CommonAreasGenerateActivationCodesForCommonAreasResponse, CommonAreasGetCommonAreaDetailsPathParams, CommonAreasGetCommonAreaDetailsResponse, CommonAreasGetCommonAreaSettingsPathParams, CommonAreasGetCommonAreaSettingsResponse, CommonAreasListActivationCodesQueryParams, CommonAreasListActivationCodesResponse, CommonAreasListCommonAreasQueryParams, CommonAreasListCommonAreasResponse, CommonAreasUnassignCallingPlanFromCommonAreaPathParams, CommonAreasUnassignCallingPlanFromCommonAreaQueryParams, CommonAreasUnassignPhoneNumbersFromCommonAreaPathParams, CommonAreasUpdateCommonAreaPathParams, CommonAreasUpdateCommonAreaPinCodePathParams, CommonAreasUpdateCommonAreaPinCodeRequestBody, CommonAreasUpdateCommonAreaRequestBody, CommonAreasUpdateCommonAreaSettingPathParams, CommonAreasUpdateCommonAreaSettingRequestBody, DashboardGetCallDetailsFromCallLogPathParams, DashboardGetCallDetailsFromCallLogResponse, DashboardGetCallQoSPathParams, DashboardGetCallQoSResponse, DashboardListCallLogsQueryParams, DashboardListCallLogsResponse, DashboardListDefaultEmergencyAddressUsersQueryParams, DashboardListDefaultEmergencyAddressUsersResponse, DashboardListDetectablePersonalLocationUsersQueryParams, DashboardListDetectablePersonalLocationUsersResponse, DashboardListNomadicEmergencyServicesUsersQueryParams, DashboardListNomadicEmergencyServicesUsersResponse, DashboardListPastCallMetricsQueryParams, DashboardListPastCallMetricsResponse, DashboardListRealTimeLocationForIPPhonesQueryParams, DashboardListRealTimeLocationForIPPhonesResponse, DashboardListRealTimeLocationForUsersQueryParams, DashboardListRealTimeLocationForUsersResponse, DashboardListTrackedLocationsQueryParams, DashboardListTrackedLocationsResponse, DashboardListUsersPermissionForLocationSharingQueryParams, DashboardListUsersPermissionForLocationSharingResponse, DeviceLineKeysBatchUpdateDeviceLineKeyPositionPathParams, DeviceLineKeysBatchUpdateDeviceLineKeyPositionRequestBody, DeviceLineKeysGetDeviceLineKeysInformationPathParams, DeviceLineKeysGetDeviceLineKeysInformationResponse, DialByNameDirectoryAddUsersToDirectoryOfSitePathParams, DialByNameDirectoryAddUsersToDirectoryOfSiteRequestBody, DialByNameDirectoryAddUsersToDirectoryRequestBody, DialByNameDirectoryDeleteUsersFromDirectoryOfSitePathParams, DialByNameDirectoryDeleteUsersFromDirectoryOfSiteQueryParams, DialByNameDirectoryDeleteUsersFromDirectoryQueryParams, DialByNameDirectoryListUsersInDirectoryBySitePathParams, DialByNameDirectoryListUsersInDirectoryBySiteQueryParams, DialByNameDirectoryListUsersInDirectoryBySiteResponse, DialByNameDirectoryListUsersInDirectoryQueryParams, DialByNameDirectoryListUsersInDirectoryResponse, EmergencyAddressesAddEmergencyAddressRequestBody, EmergencyAddressesAddEmergencyAddressResponse, EmergencyAddressesDeleteEmergencyAddressPathParams, EmergencyAddressesGetEmergencyAddressDetailsPathParams, EmergencyAddressesGetEmergencyAddressDetailsResponse, EmergencyAddressesListEmergencyAddressesQueryParams, EmergencyAddressesListEmergencyAddressesResponse, EmergencyAddressesUpdateEmergencyAddressPathParams, EmergencyAddressesUpdateEmergencyAddressRequestBody, EmergencyAddressesUpdateEmergencyAddressResponse, EmergencyServiceLocationsAddEmergencyServiceLocationRequestBody, EmergencyServiceLocationsAddEmergencyServiceLocationResponse, EmergencyServiceLocationsBatchAddEmergencyServiceLocationsRequestBody, EmergencyServiceLocationsBatchAddEmergencyServiceLocationsResponse, EmergencyServiceLocationsDeleteEmergencyLocationPathParams, EmergencyServiceLocationsGetEmergencyServiceLocationDetailsPathParams, EmergencyServiceLocationsGetEmergencyServiceLocationDetailsResponse, EmergencyServiceLocationsListEmergencyServiceLocationsQueryParams, EmergencyServiceLocationsListEmergencyServiceLocationsResponse, EmergencyServiceLocationsUpdateEmergencyServiceLocationPathParams, EmergencyServiceLocationsUpdateEmergencyServiceLocationRequestBody, ExternalContactsAddExternalContactRequestBody, ExternalContactsAddExternalContactResponse, ExternalContactsDeleteExternalContactPathParams, ExternalContactsGetExternalContactDetailsPathParams, ExternalContactsGetExternalContactDetailsResponse, ExternalContactsListExternalContactsQueryParams, ExternalContactsListExternalContactsResponse, ExternalContactsUpdateExternalContactPathParams, ExternalContactsUpdateExternalContactRequestBody, FirmwareUpdateRulesAddFirmwareUpdateRuleRequestBody, FirmwareUpdateRulesAddFirmwareUpdateRuleResponse, FirmwareUpdateRulesDeleteFirmwareUpdateRulePathParams, FirmwareUpdateRulesDeleteFirmwareUpdateRuleQueryParams, FirmwareUpdateRulesGetFirmwareUpdateRuleInformationPathParams, FirmwareUpdateRulesGetFirmwareUpdateRuleInformationResponse, FirmwareUpdateRulesListFirmwareUpdateRulesQueryParams, FirmwareUpdateRulesListFirmwareUpdateRulesResponse, FirmwareUpdateRulesListUpdatableFirmwaresQueryParams, FirmwareUpdateRulesListUpdatableFirmwaresResponse, FirmwareUpdateRulesUpdateFirmwareUpdateRulePathParams, FirmwareUpdateRulesUpdateFirmwareUpdateRuleRequestBody, GroupCallPickupAddGroupCallPickupObjectRequestBody, GroupCallPickupAddGroupCallPickupObjectResponse, GroupCallPickupAddMembersToCallPickupGroupPathParams, GroupCallPickupAddMembersToCallPickupGroupRequestBody, GroupCallPickupDeleteGroupCallPickupObjectsPathParams, GroupCallPickupGetCallPickupGroupByIDPathParams, GroupCallPickupGetCallPickupGroupByIDResponse, GroupCallPickupListCallPickupGroupMembersPathParams, GroupCallPickupListCallPickupGroupMembersQueryParams, GroupCallPickupListCallPickupGroupMembersResponse, GroupCallPickupListGroupCallPickupObjectsQueryParams, GroupCallPickupListGroupCallPickupObjectsResponse, GroupCallPickupRemoveMembersFromCallPickupGroupPathParams, GroupCallPickupUpdateGroupCallPickupInformationPathParams, GroupCallPickupUpdateGroupCallPickupInformationRequestBody, GroupsGetGroupPhoneSettingsPathParams, GroupsGetGroupPhoneSettingsQueryParams, GroupsGetGroupPhoneSettingsResponse, GroupsGetGroupPolicyDetailsPathParams, GroupsGetGroupPolicyDetailsResponse, GroupsUpdateGroupPolicyPathParams, GroupsUpdateGroupPolicyRequestBody, HttpReceiverOptions, IVRGetAutoReceptionistIVRPathParams, IVRGetAutoReceptionistIVRQueryParams, IVRGetAutoReceptionistIVRResponse, IVRUpdateAutoReceptionistIVRPathParams, IVRUpdateAutoReceptionistIVRRequestBody, InboundBlockedListAddAccountsInboundBlockRuleRequestBody, InboundBlockedListAddAccountsInboundBlockRuleResponse, InboundBlockedListAddExtensionsInboundBlockRulePathParams, InboundBlockedListAddExtensionsInboundBlockRuleRequestBody, InboundBlockedListAddExtensionsInboundBlockRuleResponse, InboundBlockedListDeleteAccountsInboundBlockRuleQueryParams, InboundBlockedListDeleteAccountsInboundBlockedStatisticsQueryParams, InboundBlockedListDeleteExtensionsInboundBlockRulePathParams, InboundBlockedListDeleteExtensionsInboundBlockRuleQueryParams, InboundBlockedListListAccountsInboundBlockRulesQueryParams, InboundBlockedListListAccountsInboundBlockRulesResponse, InboundBlockedListListAccountsInboundBlockedStatisticsQueryParams, InboundBlockedListListAccountsInboundBlockedStatisticsResponse, InboundBlockedListListExtensionsInboundBlockRulesPathParams, InboundBlockedListListExtensionsInboundBlockRulesQueryParams, InboundBlockedListListExtensionsInboundBlockRulesResponse, InboundBlockedListMarkPhoneNumberAsBlockedForAllExtensionsRequestBody, InboundBlockedListUpdateAccountsInboundBlockRulePathParams, InboundBlockedListUpdateAccountsInboundBlockRuleRequestBody, JwtToken, LineKeysBatchUpdateLineKeyPositionAndSettingsInformationPathParams, LineKeysBatchUpdateLineKeyPositionAndSettingsInformationRequestBody, LineKeysDeleteLineKeySettingPathParams, LineKeysGetLineKeyPositionAndSettingsInformationPathParams, LineKeysGetLineKeyPositionAndSettingsInformationResponse, Logger, MonitoringGroupsAddMembersToMonitoringGroupPathParams, MonitoringGroupsAddMembersToMonitoringGroupQueryParams, MonitoringGroupsAddMembersToMonitoringGroupRequestBody, MonitoringGroupsAddMembersToMonitoringGroupResponse, MonitoringGroupsCreateMonitoringGroupRequestBody, MonitoringGroupsCreateMonitoringGroupResponse, MonitoringGroupsDeleteMonitoringGroupPathParams, MonitoringGroupsGetListOfMonitoringGroupsOnAccountQueryParams, MonitoringGroupsGetListOfMonitoringGroupsOnAccountResponse, MonitoringGroupsGetMembersOfMonitoringGroupPathParams, MonitoringGroupsGetMembersOfMonitoringGroupQueryParams, MonitoringGroupsGetMembersOfMonitoringGroupResponse, MonitoringGroupsGetMonitoringGroupByIDPathParams, MonitoringGroupsGetMonitoringGroupByIDResponse, MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupPathParams, MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupQueryParams, MonitoringGroupsRemoveMemberFromMonitoringGroupPathParams, MonitoringGroupsRemoveMemberFromMonitoringGroupQueryParams, MonitoringGroupsUpdateMonitoringGroupPathParams, MonitoringGroupsUpdateMonitoringGroupRequestBody, OAuthToken, OutboundCallingAddAccountLevelOutboundCallingExceptionRuleRequestBody, OutboundCallingAddAccountLevelOutboundCallingExceptionRuleResponse, OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRulePathParams, OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleRequestBody, OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleResponse, OutboundCallingAddSiteLevelOutboundCallingExceptionRulePathParams, OutboundCallingAddSiteLevelOutboundCallingExceptionRuleRequestBody, OutboundCallingAddSiteLevelOutboundCallingExceptionRuleResponse, OutboundCallingAddUserLevelOutboundCallingExceptionRulePathParams, OutboundCallingAddUserLevelOutboundCallingExceptionRuleRequestBody, OutboundCallingAddUserLevelOutboundCallingExceptionRuleResponse, OutboundCallingDeleteAccountLevelOutboundCallingExceptionRulePathParams, OutboundCallingDeleteCommonAreaLevelOutboundCallingExceptionRulePathParams, OutboundCallingDeleteSiteLevelOutboundCallingExceptionRulePathParams, OutboundCallingDeleteUserLevelOutboundCallingExceptionRulePathParams, OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsQueryParams, OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsResponse, OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsPathParams, OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsQueryParams, OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsResponse, OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsPathParams, OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsQueryParams, OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsResponse, OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsPathParams, OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsQueryParams, OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsResponse, OutboundCallingListAccountLevelOutboundCallingExceptionRulesQueryParams, OutboundCallingListAccountLevelOutboundCallingExceptionRulesResponse, OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesPathParams, OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesQueryParams, OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesResponse, OutboundCallingListSiteLevelOutboundCallingExceptionRulesPathParams, OutboundCallingListSiteLevelOutboundCallingExceptionRulesQueryParams, OutboundCallingListSiteLevelOutboundCallingExceptionRulesResponse, OutboundCallingListUserLevelOutboundCallingExceptionRulesPathParams, OutboundCallingListUserLevelOutboundCallingExceptionRulesQueryParams, OutboundCallingListUserLevelOutboundCallingExceptionRulesResponse, OutboundCallingUpdateAccountLevelOutboundCallingCountriesOrRegionsRequestBody, OutboundCallingUpdateAccountLevelOutboundCallingExceptionRulePathParams, OutboundCallingUpdateAccountLevelOutboundCallingExceptionRuleRequestBody, OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsPathParams, OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsRequestBody, OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRulePathParams, OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRuleRequestBody, OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsPathParams, OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsRequestBody, OutboundCallingUpdateSiteLevelOutboundCallingExceptionRulePathParams, OutboundCallingUpdateSiteLevelOutboundCallingExceptionRuleRequestBody, OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsPathParams, OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsRequestBody, OutboundCallingUpdateUserLevelOutboundCallingExceptionRulePathParams, OutboundCallingUpdateUserLevelOutboundCallingExceptionRuleRequestBody, PhoneAccountSettingsUpdatedEvent, PhoneAiCallSummaryChangedEvent, PhoneBlindTransferInitiatedEvent, PhoneCallHistoryDeletedEvent, PhoneCallLogDeletedEvent, PhoneCallLogPermanentlyDeletedEvent, PhoneCalleeAnsweredEvent, PhoneCalleeCallHistoryCompletedEvent, PhoneCalleeCallLogCompletedEvent, PhoneCalleeEndedEvent, PhoneCalleeHoldEvent, PhoneCalleeMeetingInvitingEvent, PhoneCalleeMissedEvent, PhoneCalleeMuteEvent, PhoneCalleeParkedEvent, PhoneCalleeRejectedEvent, PhoneCalleeRingingEvent, PhoneCalleeUnholdEvent, PhoneCalleeUnmuteEvent, PhoneCallerCallHistoryCompletedEvent, PhoneCallerCallLogCompletedEvent, PhoneCallerConnectedEvent, PhoneCallerEndedEvent, PhoneCallerHoldEvent, PhoneCallerMeetingInvitingEvent, PhoneCallerMuteEvent, PhoneCallerRingingEvent, PhoneCallerUnholdEvent, PhoneCallerUnmuteEvent, PhoneConferenceStartedEvent, PhoneDeviceRegistrationEvent, PhoneDevicesAddDeviceRequestBody, PhoneDevicesAddDeviceResponse, PhoneDevicesAssignEntityToDevicePathParams, PhoneDevicesAssignEntityToDeviceRequestBody, PhoneDevicesAssignEntityToDeviceResponse, PhoneDevicesDeleteDevicePathParams, PhoneDevicesGetDeviceDetailsPathParams, PhoneDevicesGetDeviceDetailsResponse, PhoneDevicesListDevicesQueryParams, PhoneDevicesListDevicesResponse, PhoneDevicesListSmartphonesQueryParams, PhoneDevicesListSmartphonesResponse, PhoneDevicesRebootDeskPhonePathParams, PhoneDevicesSyncDeskphonesRequestBody, PhoneDevicesUnassignEntityFromDevicePathParams, PhoneDevicesUpdateDevicePathParams, PhoneDevicesUpdateDeviceRequestBody, PhoneDevicesUpdateProvisionTemplateOfDevicePathParams, PhoneDevicesUpdateProvisionTemplateOfDeviceRequestBody, PhoneEmergencyAlertEvent, PhoneEvents, PhoneGenericDeviceProvisionEvent, PhoneGroupSettingsUpdatedEvent, PhoneNumbersAddBYOCPhoneNumbersRequestBody, PhoneNumbersAddBYOCPhoneNumbersResponse, PhoneNumbersAssignPhoneNumberToUserPathParams, PhoneNumbersAssignPhoneNumberToUserRequestBody, PhoneNumbersAssignPhoneNumberToUserResponse, PhoneNumbersDeleteUnassignedPhoneNumbersQueryParams, PhoneNumbersGetPhoneNumberPathParams, PhoneNumbersGetPhoneNumberResponse, PhoneNumbersListPhoneNumbersQueryParams, PhoneNumbersListPhoneNumbersResponse, PhoneNumbersUnassignPhoneNumberPathParams, PhoneNumbersUpdatePhoneNumberPathParams, PhoneNumbersUpdatePhoneNumberRequestBody, PhoneNumbersUpdateSitesUnassignedPhoneNumbersPathParams, PhoneNumbersUpdateSitesUnassignedPhoneNumbersRequestBody, PhoneOptions, PhonePeeringNumberCnamUpdatedEvent, PhonePeeringNumberEmergencyAddressUpdatedEvent, PhonePlansListCallingPlansResponse, PhonePlansListPlanInformationResponse, PhoneRecordingCompletedEvent, PhoneRecordingCompletedForAccessMemberEvent, PhoneRecordingDeletedEvent, PhoneRecordingFailedEvent, PhoneRecordingPausedEvent, PhoneRecordingPermanentlyDeletedEvent, PhoneRecordingResumedEvent, PhoneRecordingStartedEvent, PhoneRecordingStoppedEvent, PhoneRecordingTranscriptCompletedEvent, PhoneRolesAddMembersToRolesPathParams, PhoneRolesAddMembersToRolesRequestBody, PhoneRolesAddPhoneRoleTargetsPathParams, PhoneRolesAddPhoneRoleTargetsRequestBody, PhoneRolesAddPhoneRoleTargetsResponse, PhoneRolesDeleteMembersInRolePathParams, PhoneRolesDeleteMembersInRoleQueryParams, PhoneRolesDeletePhoneRolePathParams, PhoneRolesDeletePhoneRoleTargetsPathParams, PhoneRolesDeletePhoneRoleTargetsRequestBody, PhoneRolesDuplicatePhoneRoleRequestBody, PhoneRolesDuplicatePhoneRoleResponse, PhoneRolesGetRoleInformationPathParams, PhoneRolesGetRoleInformationResponse, PhoneRolesListMembersInRolePathParams, PhoneRolesListMembersInRoleQueryParams, PhoneRolesListMembersInRoleResponse, PhoneRolesListPhoneRoleTargetsPathParams, PhoneRolesListPhoneRoleTargetsQueryParams, PhoneRolesListPhoneRoleTargetsResponse, PhoneRolesListPhoneRolesResponse, PhoneRolesUpdatePhoneRolePathParams, PhoneRolesUpdatePhoneRoleRequestBody, PhoneS2SAuthOptions, PhoneSmsCampaignNumberOptInEvent, PhoneSmsCampaignNumberOptOutEvent, PhoneSmsEtiquetteBlockEvent, PhoneSmsEtiquetteWarnEvent, PhoneSmsReceivedEvent, PhoneSmsSentEvent, PhoneSmsSentFailedEvent, PhoneTransferCallToVoicemailInitiatedEvent, PhoneVoicemailDeletedEvent, PhoneVoicemailPermanentlyDeletedEvent, PhoneVoicemailReceivedEvent, PhoneVoicemailReceivedForAccessMemberEvent, PhoneVoicemailTranscriptCompletedEvent, PrivateDirectoryAddMembersToPrivateDirectoryRequestBody, PrivateDirectoryListPrivateDirectoryMembersQueryParams, PrivateDirectoryListPrivateDirectoryMembersResponse, PrivateDirectoryRemoveMemberFromPrivateDirectoryPathParams, PrivateDirectoryRemoveMemberFromPrivateDirectoryQueryParams, PrivateDirectoryUpdatePrivateDirectoryMemberPathParams, PrivateDirectoryUpdatePrivateDirectoryMemberRequestBody, ProviderExchangeAddPeeringPhoneNumbersRequestBody, ProviderExchangeAddPeeringPhoneNumbersResponse, ProviderExchangeListCarrierPeeringPhoneNumbersQueryParams, ProviderExchangeListCarrierPeeringPhoneNumbersResponse, ProviderExchangeListPeeringPhoneNumbersQueryParams, ProviderExchangeListPeeringPhoneNumbersResponse, ProviderExchangeRemovePeeringPhoneNumbersQueryParams, ProviderExchangeRemovePeeringPhoneNumbersResponse, ProviderExchangeUpdatePeeringPhoneNumbersRequestBody, ProviderExchangeUpdatePeeringPhoneNumbersResponse, ProvisionTemplatesAddProvisionTemplateRequestBody, ProvisionTemplatesAddProvisionTemplateResponse, ProvisionTemplatesDeleteProvisionTemplatePathParams, ProvisionTemplatesGetProvisionTemplatePathParams, ProvisionTemplatesGetProvisionTemplateResponse, ProvisionTemplatesListProvisionTemplatesQueryParams, ProvisionTemplatesListProvisionTemplatesResponse, ProvisionTemplatesUpdateProvisionTemplatePathParams, ProvisionTemplatesUpdateProvisionTemplateRequestBody, Receiver, ReceiverInitOptions, RecordingsDeleteCallRecordingPathParams, RecordingsDownloadPhoneRecordingPathParams, RecordingsDownloadPhoneRecordingTranscriptPathParams, RecordingsGetCallRecordingsQueryParams, RecordingsGetCallRecordingsResponse, RecordingsGetRecordingByCallIDPathParams, RecordingsGetRecordingByCallIDResponse, RecordingsGetUsersRecordingsPathParams, RecordingsGetUsersRecordingsQueryParams, RecordingsGetUsersRecordingsResponse, RecordingsUpdateAutoDeleteFieldPathParams, RecordingsUpdateAutoDeleteFieldRequestBody, RecordingsUpdateRecordingStatusPathParams, RecordingsUpdateRecordingStatusRequestBody, ReportsGetCallChargesUsageReportQueryParams, ReportsGetCallChargesUsageReportResponse, ReportsGetOperationLogsReportQueryParams, ReportsGetOperationLogsReportResponse, ReportsGetSMSMMSChargesUsageReportQueryParams, ReportsGetSMSMMSChargesUsageReportResponse, RoutingRulesAddDirectoryBackupRoutingRuleRequestBody, RoutingRulesAddDirectoryBackupRoutingRuleResponse, RoutingRulesDeleteDirectoryBackupRoutingRulePathParams, RoutingRulesGetDirectoryBackupRoutingRulePathParams, RoutingRulesGetDirectoryBackupRoutingRuleResponse, RoutingRulesListDirectoryBackupRoutingRulesQueryParams, RoutingRulesListDirectoryBackupRoutingRulesResponse, RoutingRulesUpdateDirectoryBackupRoutingRulePathParams, RoutingRulesUpdateDirectoryBackupRoutingRuleRequestBody, S2SAuthToken, SMSCampaignAssignPhoneNumberToSMSCampaignPathParams, SMSCampaignAssignPhoneNumberToSMSCampaignRequestBody, SMSCampaignAssignPhoneNumberToSMSCampaignResponse, SMSCampaignGetSMSCampaignPathParams, SMSCampaignGetSMSCampaignResponse, SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams, SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignQueryParams, SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignResponse, SMSCampaignListSMSCampaignsQueryParams, SMSCampaignListSMSCampaignsResponse, SMSCampaignListUsersOptStatusesOfPhoneNumbersPathParams, SMSCampaignListUsersOptStatusesOfPhoneNumbersQueryParams, SMSCampaignListUsersOptStatusesOfPhoneNumbersResponse, SMSCampaignUnassignPhoneNumberPathParams, SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams, SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignRequestBody, SMSGetAccountsSMSSessionsQueryParams, SMSGetAccountsSMSSessionsResponse, SMSGetSMSByMessageIDPathParams, SMSGetSMSByMessageIDResponse, SMSGetSMSSessionDetailsPathParams, SMSGetSMSSessionDetailsQueryParams, SMSGetSMSSessionDetailsResponse, SMSGetUsersSMSSessionsPathParams, SMSGetUsersSMSSessionsQueryParams, SMSGetUsersSMSSessionsResponse, SMSListUsersSMSSessionsInDescendingOrderPathParams, SMSListUsersSMSSessionsInDescendingOrderQueryParams, SMSListUsersSMSSessionsInDescendingOrderResponse, SMSPostSMSMessageRequestBody, SMSPostSMSMessageResponse, SMSSyncSMSBySessionIDPathParams, SMSSyncSMSBySessionIDQueryParams, SMSSyncSMSBySessionIDResponse, SettingTemplatesAddSettingTemplateRequestBody, SettingTemplatesAddSettingTemplateResponse, SettingTemplatesGetSettingTemplateDetailsPathParams, SettingTemplatesGetSettingTemplateDetailsQueryParams, SettingTemplatesGetSettingTemplateDetailsResponse, SettingTemplatesListSettingTemplatesQueryParams, SettingTemplatesListSettingTemplatesResponse, SettingTemplatesUpdateSettingTemplatePathParams, SettingTemplatesUpdateSettingTemplateRequestBody, SettingsGetAccountPolicyDetailsPathParams, SettingsGetAccountPolicyDetailsResponse, SettingsGetPhoneAccountSettingsResponse, SettingsGetPortedNumberDetailsPathParams, SettingsGetPortedNumberDetailsResponse, SettingsListBYOCSIPTrunksQueryParams, SettingsListBYOCSIPTrunksResponse, SettingsListPortedNumbersQueryParams, SettingsListPortedNumbersResponse, SettingsListSIPGroupsQueryParams, SettingsListSIPGroupsResponse, SettingsUpdateAccountPolicyPathParams, SettingsUpdateAccountPolicyRequestBody, SettingsUpdatePhoneAccountSettingsRequestBody, SharedLineAppearanceListSharedLineAppearancesQueryParams, SharedLineAppearanceListSharedLineAppearancesResponse, SharedLineGroupAddMembersToSharedLineGroupPathParams, SharedLineGroupAddMembersToSharedLineGroupRequestBody, SharedLineGroupAddPolicySettingToSharedLineGroupPathParams, SharedLineGroupAddPolicySettingToSharedLineGroupRequestBody, SharedLineGroupAddPolicySettingToSharedLineGroupResponse, SharedLineGroupAssignPhoneNumbersPathParams, SharedLineGroupAssignPhoneNumbersRequestBody, SharedLineGroupCreateSharedLineGroupRequestBody, SharedLineGroupCreateSharedLineGroupResponse, SharedLineGroupDeleteSLGPolicySettingPathParams, SharedLineGroupDeleteSLGPolicySettingQueryParams, SharedLineGroupDeleteSharedLineGroupPathParams, SharedLineGroupGetSharedLineGroupPathParams, SharedLineGroupGetSharedLineGroupPolicyPathParams, SharedLineGroupGetSharedLineGroupPolicyResponse, SharedLineGroupGetSharedLineGroupResponse, SharedLineGroupListSharedLineGroupsQueryParams, SharedLineGroupListSharedLineGroupsResponse, SharedLineGroupUnassignAllPhoneNumbersPathParams, SharedLineGroupUnassignMemberFromSharedLineGroupPathParams, SharedLineGroupUnassignMembersFromSharedLineGroupPathParams, SharedLineGroupUnassignPhoneNumberPathParams, SharedLineGroupUpdateSLGPolicySettingPathParams, SharedLineGroupUpdateSLGPolicySettingRequestBody, SharedLineGroupUpdateSharedLineGroupPathParams, SharedLineGroupUpdateSharedLineGroupPolicyPathParams, SharedLineGroupUpdateSharedLineGroupPolicyRequestBody, SharedLineGroupUpdateSharedLineGroupRequestBody, SitesAddCustomizedOutboundCallerIDPhoneNumbersPathParams, SitesAddCustomizedOutboundCallerIDPhoneNumbersRequestBody, SitesAddCustomizedOutboundCallerIDPhoneNumbersResponse, SitesAddSiteSettingPathParams, SitesAddSiteSettingRequestBody, SitesAddSiteSettingResponse, SitesCreatePhoneSiteRequestBody, SitesCreatePhoneSiteResponse, SitesDeletePhoneSitePathParams, SitesDeletePhoneSiteQueryParams, SitesDeleteSiteSettingPathParams, SitesDeleteSiteSettingQueryParams, SitesGetPhoneSiteDetailsPathParams, SitesGetPhoneSiteDetailsResponse, SitesGetPhoneSiteSettingPathParams, SitesGetPhoneSiteSettingResponse, SitesListCustomizedOutboundCallerIDPhoneNumbersPathParams, SitesListCustomizedOutboundCallerIDPhoneNumbersQueryParams, SitesListCustomizedOutboundCallerIDPhoneNumbersResponse, SitesListPhoneSitesQueryParams, SitesListPhoneSitesResponse, SitesRemoveCustomizedOutboundCallerIDPhoneNumbersPathParams, SitesRemoveCustomizedOutboundCallerIDPhoneNumbersQueryParams, SitesUpdatePhoneSiteDetailsPathParams, SitesUpdatePhoneSiteDetailsRequestBody, SitesUpdateSiteSettingPathParams, SitesUpdateSiteSettingRequestBody, StateStore, TokenStore, UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDPathParams, UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDRequestBody, UsersAddUsersSharedAccessSettingPathParams, UsersAddUsersSharedAccessSettingRequestBody, UsersAddUsersSharedAccessSettingResponse, UsersAssignCallingPlanToUserPathParams, UsersAssignCallingPlanToUserRequestBody, UsersBatchAddUsersRequestBody, UsersBatchAddUsersResponse, UsersDeleteUsersSharedAccessSettingPathParams, UsersDeleteUsersSharedAccessSettingQueryParams, UsersGetUserPolicyDetailsPathParams, UsersGetUserPolicyDetailsResponse, UsersGetUsersProfilePathParams, UsersGetUsersProfileResponse, UsersGetUsersProfileSettingsPathParams, UsersGetUsersProfileSettingsResponse, UsersListPhoneUsersQueryParams, UsersListPhoneUsersResponse, UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDPathParams, UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDQueryParams, UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDResponse, UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersPathParams, UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersQueryParams, UsersUnassignUsersCallingPlanPathParams, UsersUnassignUsersCallingPlanQueryParams, UsersUpdateMultipleUsersPropertiesInBatchRequestBody, UsersUpdateUserPolicyPathParams, UsersUpdateUserPolicyRequestBody, UsersUpdateUsersCallingPlanPathParams, UsersUpdateUsersCallingPlanRequestBody, UsersUpdateUsersProfilePathParams, UsersUpdateUsersProfileRequestBody, UsersUpdateUsersProfileSettingsPathParams, UsersUpdateUsersProfileSettingsRequestBody, UsersUpdateUsersSharedAccessSettingPathParams, UsersUpdateUsersSharedAccessSettingRequestBody, VoicemailsDeleteVoicemailPathParams, VoicemailsDownloadPhoneVoicemailPathParams, VoicemailsGetAccountVoicemailsQueryParams, VoicemailsGetAccountVoicemailsResponse, VoicemailsGetUserVoicemailDetailsFromCallLogPathParams, VoicemailsGetUserVoicemailDetailsFromCallLogResponse, VoicemailsGetUsersVoicemailsPathParams, VoicemailsGetUsersVoicemailsQueryParams, VoicemailsGetUsersVoicemailsResponse, VoicemailsGetVoicemailDetailsPathParams, VoicemailsGetVoicemailDetailsResponse, VoicemailsUpdateVoicemailReadStatusPathParams, VoicemailsUpdateVoicemailReadStatusQueryParams, ZoomRoomsAddZoomRoomToZoomPhoneRequestBody, ZoomRoomsAssignCallingPlansToZoomRoomPathParams, ZoomRoomsAssignCallingPlansToZoomRoomRequestBody, ZoomRoomsAssignPhoneNumbersToZoomRoomPathParams, ZoomRoomsAssignPhoneNumbersToZoomRoomRequestBody, ZoomRoomsAssignPhoneNumbersToZoomRoomResponse, ZoomRoomsGetZoomRoomUnderZoomPhoneLicensePathParams, ZoomRoomsGetZoomRoomUnderZoomPhoneLicenseResponse, ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseQueryParams, ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseResponse, ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentQueryParams, ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentResponse, ZoomRoomsRemoveCallingPlanFromZoomRoomPathParams, ZoomRoomsRemoveCallingPlanFromZoomRoomQueryParams, ZoomRoomsRemovePhoneNumberFromZoomRoomPathParams, ZoomRoomsRemoveZoomRoomFromZPAccountPathParams, ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicensePathParams, ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicenseRequestBody };
