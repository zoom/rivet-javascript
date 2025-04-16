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
    private getHeaders;
    private getRequestBody;
    private isOk;
    private isZoomResponseError;
    private makeRequest;
}

type CommonClientOptions<A extends Auth, R extends Receiver> = GetAuthOptions<A> & ExtractInstallerOptions<A, R> & {
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
        locked_by?: string;
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
        locked_by?: string;
    };
    external_calling_on_zoom_room_common_area?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    select_outbound_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        allow_hide_outbound_caller_id?: boolean;
    };
    personal_audio_library?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        allow_music_on_hold_customization?: boolean;
        allow_voicemail_and_message_greeting_customization?: boolean;
    };
    voicemail?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
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
        locked_by?: string;
    };
    voicemail_notification_by_email?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        include_voicemail_file?: boolean;
        include_voicemail_transcription?: boolean;
        forward_voicemail_to_email?: boolean;
    };
    shared_voicemail_notification_by_email?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    restricted_call_hours?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
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
        locked_by?: string;
    } & {
        locations_applied?: boolean;
        allow_internal_calls?: boolean;
    };
    check_voicemails_over_phone?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    auto_call_recording?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        recording_calls?: string;
        recording_transcription?: boolean;
        recording_start_prompt?: boolean;
        recording_start_prompt_audio_id?: string;
        recording_explicit_consent?: boolean;
        allow_stop_resume_recording?: boolean;
        disconnect_on_recording_failure?: boolean;
        play_recording_beep_tone?: {
            enable?: boolean;
            play_beep_member?: string;
            play_beep_volume?: number;
            play_beep_time_interval?: number;
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
        locked_by?: string;
    };
    international_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    outbound_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    outbound_sms?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    sms?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        international_sms?: boolean;
    };
    sms_etiquette_tool?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    zoom_phone_on_mobile?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        allow_calling_sms_mms?: boolean;
    };
    zoom_phone_on_pwa?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    e2e_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    call_handling_forwarding_to_other_users?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        call_forwarding_type?: number;
    };
    call_overflow?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        call_overflow_type?: number;
    };
    call_transferring?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    } & {
        call_transferring_type?: number;
    };
    elevate_to_meeting?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    call_park?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    hand_off_to_room?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    mobile_switch_to_carrier?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    delegation?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    audio_intercom?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    block_calls_without_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    block_external_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    call_queue_opt_out_reason?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    auto_delete_data_after_retention_duration?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    auto_call_from_third_party_apps?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    override_default_port?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    peer_to_peer_media?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    advanced_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    display_call_feedback_survey?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
    };
    block_list_for_inbound_calls_and_messaging?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
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
    extension_type?: string;
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
type AccountsDeletePhoneNumbersForAccountsCustomizedOutboundCallerIDQueryParams = {
    customize_ids?: string[];
};
type AlertsListAlertSettingsWithPagingQueryQueryParams = {
    page_size?: number;
    next_page_token?: string;
    module?: number;
    rule?: number;
    status?: number;
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
            rule_condition_type?: number;
            rule_condition_value?: string;
        }[];
        targets?: {
            target_name?: string;
        }[];
        time_frame_type?: string;
        time_frame_from?: string;
        time_frame_to?: string;
        frequency?: number;
        email_recipients?: string[];
        chat_channels?: {
            chat_channel_name?: string;
            token?: string;
            end_point?: string;
        }[];
        status?: number;
    }[];
};
type AlertsAddAlertSettingRequestBody = {
    alert_setting_name: string;
    module: number;
    rule: number;
    target_type: number;
    target_ids?: string[];
    rule_conditions: {
        rule_condition_type?: number;
        rule_condition_value?: string;
    }[];
    time_frame_type: string;
    time_frame_from: string;
    time_frame_to: string;
    frequency?: number;
    email_recipients?: string[];
    chat_channels?: {
        chat_channel_name?: string;
        token?: string;
        end_point?: string;
    }[];
    status?: number;
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
        rule_condition_type?: number;
        rule_condition_value?: string;
    }[];
    targets?: {
        target_id?: string;
        target_name?: string;
        target_type?: number;
        target_extension_number?: number;
        site?: {
            id?: string;
            name?: string;
        };
        assignees?: {
            extension_number?: number;
            name?: string;
            extension_type?: string;
            extension_id?: string;
        }[];
    }[];
    time_frame_type?: string;
    time_frame_from?: string;
    time_frame_to?: string;
    frequency?: number;
    email_recipients?: string[];
    chat_channels?: {
        chat_channel_name?: string;
        token?: string;
        end_point?: string;
    }[];
    status?: number;
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
        rule_condition_type?: number;
        rule_condition_value?: string;
    }[];
    target_ids?: string[];
    time_frame_type?: string;
    time_frame_from?: string;
    time_frame_to?: string;
    frequency?: number;
    email_recipients?: string[];
    chat_channels?: {
        chat_channel_name?: string;
        token?: string;
        end_point?: string;
    }[];
    status?: number;
};
type AudioLibraryGetAudioItemPathParams = {
    audioId: string;
};
type AudioLibraryGetAudioItemResponse = {
    audio_id?: string;
    name?: string;
    play_url?: string;
    text?: string;
    voice_language?: string;
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
    recording_storage_location?: string;
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
    audio_prompt_language?: string;
    timezone?: string;
    recording_storage_location?: string;
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
        locked_by?: string;
        modified?: boolean;
    };
    voicemail_notification_by_email?: {
        include_voicemail_file?: boolean;
        include_voicemail_transcription?: boolean;
        forward_voicemail_to_email?: boolean;
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    sms?: {
        enable?: boolean;
        international_sms?: boolean;
        international_sms_countries?: string[];
        locked?: boolean;
        locked_by?: string;
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
        block_type?: string;
        comment?: string;
        id?: string;
        match_type?: string;
        phone_number?: string;
        status?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type BlockedListCreateBlockedListRequestBody = {
    block_type?: string;
    comment?: string;
    country?: string;
    match_type?: string;
    phone_number?: string;
    status?: string;
};
type BlockedListCreateBlockedListResponse = {
    id?: string;
};
type BlockedListGetBlockedListDetailsPathParams = {
    blockedListId: string;
};
type BlockedListGetBlockedListDetailsResponse = {
    block_type?: string;
    comment?: string;
    id?: string;
    match_type?: string;
    phone_number?: string;
    status?: string;
};
type BlockedListDeleteBlockedListPathParams = {
    blockedListId: string;
};
type BlockedListUpdateBlockedListPathParams = {
    blockedListId: string;
};
type BlockedListUpdateBlockedListRequestBody = {
    block_type?: string;
    comment?: string;
    country?: string;
    match_type?: string;
    phone_number?: string;
    status?: string;
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
                ring_duration?: number;
                ring_mode?: string;
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
            call_not_answer_action?: number;
            connect_to_operator?: boolean;
            custom_hours_settings?: {
                from?: string;
                to?: string;
                type?: number;
                weekday?: number;
            }[];
            greeting_prompt?: {
                id?: string;
                name?: string;
            };
            max_call_in_queue?: number;
            max_wait_time?: number;
            music_on_hold?: {
                id?: string;
                name?: string;
            };
            receive_call?: boolean;
            require_press_1_before_connecting?: boolean;
            ring_mode?: string;
            routing?: {
                action?: number;
                forward_to?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: string;
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
                    extension_type?: string;
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
                    extension_type?: string;
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
                    extension_type?: string;
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
            type?: number;
            wrap_up_time?: number;
        };
        sub_setting_type?: string;
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
            call_not_answer_action?: number;
            connect_to_operator?: boolean;
            max_wait_time?: number;
            require_press_1_before_connecting?: boolean;
            ring_mode?: string;
            routing?: {
                action?: number;
                forward_to?: {
                    display_name?: string;
                    extension_id?: string;
                    extension_number?: number;
                    extension_type?: string;
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
                    extension_type?: string;
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
                    extension_type?: string;
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
                    extension_type?: string;
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
        sub_setting_type?: string;
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
                call_not_answer_action?: number;
                connect_to_operator?: boolean;
                from?: string;
                max_wait_time?: number;
                name?: string;
                require_press_1_before_connecting?: boolean;
                ring_mode?: string;
                routing?: {
                    action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: string;
                        id?: string;
                        phone_number?: string;
                        description?: string;
                        voicemail_greeting?: object;
                    };
                    operator?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: string;
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
            sub_setting_type?: string;
        }[];
        holiday_id?: string;
    }[];
};
type CallHandlingAddCallHandlingSettingPathParams = {
    extensionId: string;
    settingType: string;
};
type CallHandlingAddCallHandlingSettingRequestBody = {
    settings?: {
        holiday_id?: string;
        description?: string;
        phone_number?: string;
    };
    sub_setting_type?: string;
} | {
    settings?: {
        name?: string;
        from?: string;
        to?: string;
    };
    sub_setting_type?: string;
};
type CallHandlingAddCallHandlingSettingResponse = {
    call_forwarding_id?: string;
} | {
    holiday_id?: string;
};
type CallHandlingDeleteCallHandlingSettingPathParams = {
    extensionId: string;
    settingType: string;
};
type CallHandlingDeleteCallHandlingSettingQueryParams = {
    call_forwarding_id?: string;
    holiday_id?: string;
};
type CallHandlingUpdateCallHandlingSettingPathParams = {
    extensionId: string;
    settingType: string;
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
    sub_setting_type?: string;
} | {
    settings?: {
        from?: string;
        holiday_id?: string;
        name?: string;
        to?: string;
    };
    sub_setting_type?: string;
} | {
    settings?: {
        allow_members_to_reset?: boolean;
        custom_hours_settings?: {
            from?: string;
            to?: string;
            type?: number;
            weekday?: number;
        }[];
        type?: number;
    };
    sub_setting_type?: string;
} | {
    settings?: {
        allow_callers_check_voicemail?: boolean;
        allow_members_to_reset?: boolean;
        audio_while_connecting_id?: string;
        call_distribution?: {
            handle_multiple_calls?: boolean;
            ring_duration?: number;
            ring_mode?: string;
            skip_offline_device_phone_number?: boolean;
        };
        call_not_answer_action?: number;
        busy_on_another_call_action?: number;
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
        max_wait_time?: number;
        music_on_hold_id?: string;
        operator_extension_id?: string;
        receive_call?: boolean;
        ring_mode?: string;
        voicemail_greeting_id?: string;
        voicemail_leaving_instruction_id?: string;
        message_greeting_id?: string;
        forward_to_zcc_phone_number?: string;
        forward_to_partner_contact_center_id?: string;
        forward_to_teams_id?: string;
        wrap_up_time?: number;
    };
    sub_setting_type?: string;
};
type CallLogsGetAccountsCallHistoryQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    next_page_token?: string;
    keyword?: string;
    directions?: string[];
    connect_types?: string[];
    number_types?: string[];
    call_types?: string[];
    extension_types?: string[];
    call_results?: string[];
    group_ids?: string[];
    site_ids?: string[];
    department?: string;
    cost_center?: string;
    time_type?: string;
    recording_status?: string;
};
type CallLogsGetAccountsCallHistoryResponse = {
    call_logs?: {
        id?: string;
        call_id?: string;
        direction?: string;
        international?: boolean;
        start_time?: string;
        answer_time?: string;
        end_time?: string;
        duration?: number;
        connect_type?: string;
        sbc_id?: string;
        sbc_name?: string;
        sip_group_id?: string;
        sip_group_name?: string;
        call_type?: string;
        call_result?: string;
        caller_ext_id?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_name?: string;
        caller_email?: string;
        caller_ext_type?: string;
        caller_number_type?: string;
        caller_device_type?: string;
        caller_country_iso_code?: string;
        caller_country_code?: string;
        callee_ext_id?: string;
        callee_did_number?: string;
        callee_ext_number?: string;
        callee_name?: string;
        callee_email?: string;
        callee_ext_type?: string;
        callee_number_type?: string;
        callee_device_type?: string;
        callee_country_iso_code?: string;
        callee_country_code?: string;
        client_code?: string;
        department?: string;
        cost_center?: string;
        site_id?: string;
        group_id?: string;
        site_name?: string;
        spam?: string;
        recording_status?: string;
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
    connect_type?: string;
    call_type?: string;
    direction?: string;
    international?: boolean;
    caller_ext_id?: string;
    caller_name?: string;
    caller_did_number?: string;
    caller_ext_number?: string;
    caller_email?: string;
    caller_ext_type?: string;
    callee_ext_id?: string;
    callee_name?: string;
    callee_email?: string;
    callee_did_number?: string;
    callee_ext_number?: string;
    callee_ext_type?: string;
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
        connect_type?: string;
        call_type?: string;
        direction?: string;
        caller_ext_id?: string;
        caller_name?: string;
        caller_email?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_ext_type?: string;
        caller_number_type?: string;
        caller_device_type?: string;
        caller_country_iso_code?: string;
        caller_country_code?: string;
        callee_ext_id?: string;
        callee_name?: string;
        callee_did_number?: string;
        callee_ext_number?: string;
        callee_email?: string;
        callee_ext_type?: string;
        callee_number_type?: string;
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
        event?: string;
        result?: string;
        result_reason?: string;
        device_private_ip?: string;
        device_public_ip?: string;
        operator_ext_number?: string;
        operator_ext_id?: string;
        operator_ext_type?: string;
        operator_name?: string;
        press_key?: string;
        segment?: number;
        node?: number;
        is_node?: number;
        recording_id?: string;
        recording_type?: string;
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
type CallLogsGetAccountsCallLogsQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    type?: string;
    next_page_token?: string;
    path?: string;
    time_type?: string;
    site_id?: string;
    charged_call_logs?: boolean;
};
type CallLogsGetAccountsCallLogsResponse = {
    call_logs?: {
        answer_start_time?: string;
        call_end_time?: string;
        call_id?: string;
        call_type?: string;
        callee_country_code?: string;
        callee_country_iso_code?: string;
        callee_did_number?: string;
        callee_name?: string;
        callee_number?: string;
        callee_number_type?: number;
        callee_number_source?: string;
        caller_country_code?: string;
        caller_country_iso_code?: string;
        caller_did_number?: string;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
        caller_number_source?: string;
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
            type?: string;
        };
        path?: string;
        rate?: string;
        recording_id?: string;
        recording_type?: string;
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
    call_type?: string;
    callee_country_code?: string;
    callee_country_iso_code?: string;
    callee_did_number?: string;
    callee_name?: string;
    callee_number?: string;
    callee_number_type?: number;
    callee_number_source?: string;
    callee_status?: string;
    callee_deleted_time?: string;
    caller_country_code?: string;
    caller_country_iso_code?: string;
    caller_did_number?: string;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: number;
    caller_number_source?: string;
    caller_billing_reference_id?: string;
    caller_status?: string;
    caller_deleted_time?: string;
    date_time?: string;
    device_private_ip?: string;
    device_public_ip?: string;
    direction?: string;
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
            type?: string;
            extension_status?: string;
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
type CallLogsGetUsersCallHistoryPathParams = {
    userId: string;
};
type CallLogsGetUsersCallHistoryQueryParams = {
    page_size?: number;
    from?: string;
    to?: string;
    next_page_token?: string;
    keyword?: string;
    directions?: string[];
    connect_types?: string[];
    number_types?: string[];
    call_types?: string[];
    extension_types?: string[];
    call_results?: string[];
    group_ids?: string[];
    site_ids?: string[];
    department?: string;
    cost_center?: string;
    time_type?: string;
    recording_status?: string;
};
type CallLogsGetUsersCallHistoryResponse = {
    call_logs?: {
        id?: string;
        call_id?: string;
        group_id?: string;
        connect_type?: string;
        call_type?: string;
        direction?: string;
        caller_ext_id?: string;
        caller_name?: string;
        caller_email?: string;
        caller_employee_id?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_ext_type?: string;
        caller_number_type?: string;
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
        callee_ext_type?: string;
        callee_number_type?: string;
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
        event?: string;
        result?: string;
        result_reason?: string;
        operator_ext_number?: string;
        operator_ext_id?: string;
        operator_ext_type?: string;
        operator_name?: string;
        recording_id?: string;
        recording_type?: string;
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
        call_id?: string;
        group_id?: string;
        connect_type?: string;
        call_type?: string;
        direction?: string;
        caller_ext_id?: string;
        caller_name?: string;
        caller_email?: string;
        caller_employee_id?: string;
        caller_did_number?: string;
        caller_ext_number?: string;
        caller_ext_type?: string;
        caller_number_type?: string;
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
        callee_ext_type?: string;
        callee_number_type?: string;
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
        event?: string;
        result?: string;
        result_reason?: string;
        operator_ext_number?: string;
        operator_ext_id?: string;
        operator_ext_type?: string;
        operator_name?: string;
        recording_id?: string;
        recording_type?: string;
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
    type?: string;
    next_page_token?: string;
    phone_number?: string;
    time_type?: string;
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
        callee_number_type?: number;
        callee_number_source?: string;
        caller_country_code?: string;
        caller_country_iso_code?: string;
        caller_did_number?: string;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
        caller_number_source?: string;
        caller_billing_reference_id?: string;
        charge?: string;
        client_code?: string;
        date_time?: string;
        direction?: string;
        duration?: number;
        forwarded_by?: {
            extension_number?: string;
            extension_type?: string;
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
        recording_type?: string;
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
    sync_type?: string;
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
        callee_number_type?: number;
        callee_number_source?: string;
        caller_user_id?: string;
        caller_country_code?: string;
        caller_country_iso_code?: string;
        caller_did_number?: string;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
        caller_number_source?: string;
        caller_billing_reference_id?: string;
        charge?: string;
        client_code?: string;
        date_time?: string;
        direction?: string;
        duration?: number;
        forwarded_by?: {
            extension_number?: string;
            extension_type?: string;
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
        recording_type?: string;
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
            source?: string;
        }[];
        site?: {
            id?: string;
            name?: string;
        };
        status?: string;
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
            level?: string;
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
        source?: string;
    }[];
    site?: {
        id?: string;
        name?: string;
    };
    status?: string;
    policy?: {
        voicemail_access_members?: ({
            access_user_id?: string;
            allow_download?: boolean;
            allow_delete?: boolean;
            allow_sharing?: boolean;
        } & {
            shared_id?: string;
        })[];
    };
    timezone?: string;
    audio_prompt_language?: string;
    recording_storage_location?: string;
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
    status?: string;
    timezone?: string;
    audio_prompt_language?: string;
    recording_storage_location?: string;
};
type CallQueuesListCallQueueMembersPathParams = {
    callQueueId: string;
};
type CallQueuesListCallQueueMembersResponse = {
    call_queue_members?: {
        id?: string;
        level?: string;
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
type CallQueuesAddPolicySettingToCallQueuePathParams = {
    callQueueId: string;
    policyType: string;
};
type CallQueuesAddPolicySettingToCallQueueRequestBody = {
    voicemail_access_members?: {
        access_user_id?: string;
        allow_download?: boolean;
        allow_delete?: boolean;
        allow_sharing?: boolean;
    }[];
};
type CallQueuesAddPolicySettingToCallQueueResponse = {
    voicemail_access_members?: ({
        access_user_id?: string;
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
        callee_number_type?: string;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
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
    assigned_status?: string;
    sub_account_id?: string;
    keyword?: string;
};
type CarrierResellerListPhoneNumbersResponse = {
    carrier_reseller_numbers?: {
        assigned_status?: string;
        carrier_code?: number;
        country_iso_code?: string;
        phone_number?: string;
        status?: string;
        sub_account_id?: string;
        sub_account_name?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type CarrierResellerCreatePhoneNumbersRequestBody = {
    phone_number?: string;
    status?: string;
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
        }[];
        display_name?: string;
        extension_number?: number;
        id?: string;
        phone_numbers?: {
            display_name?: string;
            id?: string;
            number?: string;
            source?: string;
        }[];
        site?: {
            id?: string;
            name?: string;
        };
        status?: string;
        desk_phones?: {
            id?: string;
            display_name?: string;
            device_type?: string;
            status?: string;
        }[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type CommonAreasAddCommonAreaRequestBody = {
    calling_plans?: {
        type?: number;
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
        status?: string;
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
        status?: number;
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
        source?: string;
    }[];
    policy?: {
        international_calling?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
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
    status?: string;
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
        status?: string;
        mac_address?: string;
        hot_desking?: {
            status?: string;
        };
        private_ip?: string;
        public_ip?: string;
    }[];
};
type CommonAreasAddCommonAreaSettingsPathParams = {
    commonAreaId: string;
    settingType: string;
};
type CommonAreasAddCommonAreaSettingsRequestBody = {
    device_id?: string;
};
type CommonAreasAddCommonAreaSettingsResponse = {
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
type CommonAreasUpdateCommonAreaSettingsPathParams = {
    commonAreaId: string;
    settingType: string;
};
type CommonAreasUpdateCommonAreaSettingsRequestBody = {
    desk_phones?: {
        id?: string;
        hot_desking?: {
            status?: string;
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
        extension_type?: string;
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
        extension_type?: string;
        display_name?: string;
    };
    date_time?: string;
    direction?: string;
    duration?: number;
    mos?: string;
};
type DashboardListTrackedLocationsQueryParams = {
    type?: number;
    site_id?: string;
    location_type?: string;
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
        type?: string;
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
    quality_type?: string;
    department?: string;
    cost_center?: string;
    directions?: string[];
    durations?: number[];
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
        direction?: string;
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
        extension_type?: string;
        extension_id?: string;
        display_name?: string;
        phone_number?: string;
        outbound_caller_ids?: {
            extension_id?: string;
            phone_number?: string;
            usage_type?: string;
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
    level?: number;
    status?: number;
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
        level?: number;
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
        status?: number;
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
    level?: number;
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
    status?: number;
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
    level?: number;
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
    status?: number;
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
    level?: number;
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
    status?: number;
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
    restart_type?: number;
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
    restart_type?: number;
};
type FirmwareUpdateRulesUpdateFirmwareUpdateRulePathParams = {
    ruleId: string;
};
type FirmwareUpdateRulesUpdateFirmwareUpdateRuleRequestBody = {
    version: string;
    device_type: string;
    device_model: string;
    restart_type?: number;
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
            status?: number;
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
        delay?: number;
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
    delay?: number;
    play_incoming_calls_sound?: {
        enable?: boolean;
        ring_tone?: string;
        duration?: number;
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
    delay?: number;
    member_count?: number;
    cost_center?: string;
    department?: string;
    site?: {
        id?: string;
        name?: string;
    };
    play_incoming_calls_sound?: {
        enable?: boolean;
        ring_tone?: string;
        duration?: number;
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
    delay?: number;
    cost_center?: string;
    department?: string;
    play_incoming_calls_sound?: {
        enable?: boolean;
        ring_tone?: string;
        duration?: number;
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
    extension_type?: string;
};
type GroupCallPickupListCallPickupGroupMembersResponse = {
    group_call_pickup_member?: {
        id?: string;
        display_name?: string;
        extension_id?: string;
        extension_type?: string;
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
        locked_by?: string;
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
        locked_by?: string;
        modified?: boolean;
    };
    select_outbound_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        allow_hide_outbound_caller_id?: boolean;
    };
    personal_audio_library?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        allow_music_on_hold_customization?: boolean;
        allow_voicemail_and_message_greeting_customization?: boolean;
    };
    voicemail?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
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
        locked_by?: string;
        modified?: boolean;
    };
    voicemail_notification_by_email?: {
        include_voicemail_file?: boolean;
        include_voicemail_transcription?: boolean;
        forward_voicemail_to_email?: boolean;
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    shared_voicemail_notification_by_email?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    restricted_call_hours?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
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
        locked_by?: string;
        modified?: boolean;
        locations_applied?: boolean;
        allow_internal_calls?: boolean;
    };
    check_voicemails_over_phone?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    auto_call_recording?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        recording_calls?: string;
        recording_transcription?: boolean;
        recording_start_prompt?: boolean;
        recording_start_prompt_audio_id?: string;
        recording_explicit_consent?: boolean;
        allow_stop_resume_recording?: boolean;
        disconnect_on_recording_failure?: boolean;
        play_recording_beep_tone?: {
            enable?: boolean;
            play_beep_volume?: number;
            play_beep_time_interval?: number;
            play_beep_member?: string;
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
        locked_by?: string;
        modified?: boolean;
        recording_transcription?: boolean;
        allow_download?: boolean;
        allow_delete?: boolean;
        recording_start_prompt?: boolean;
        recording_explicit_consent?: boolean;
        play_recording_beep_tone?: {
            enable?: boolean;
            play_beep_volume?: number;
            play_beep_time_interval?: number;
            play_beep_member?: string;
        };
    };
    zoom_phone_on_mobile?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        allow_calling_sms_mms?: boolean;
    };
    zoom_phone_on_pwa?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    sms_etiquette_tool?: {
        enable?: boolean;
        modified?: boolean;
        sms_etiquette_policy?: {
            id?: string;
            name?: string;
            description?: string;
            rule?: number;
            content?: string;
            action?: number;
            active?: boolean;
        }[];
    };
    outbound_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    outbound_sms?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    international_calling?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    sms?: {
        enable?: boolean;
        international_sms?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    e2e_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    call_handling_forwarding?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        call_forwarding_type?: number;
    };
    call_overflow?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        call_overflow_type?: number;
    };
    call_transferring?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        call_transferring_type?: number;
    };
    elevate_to_meeting?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    call_park?: {
        enable?: boolean;
        expiration_period?: number;
        call_not_picked_up_action?: number;
        forward_to?: {
            display_name?: string;
            extension_id?: string;
            extension_number?: number;
            extension_type?: string;
            id?: string;
        };
        sequence?: number;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    hand_off_to_room?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    mobile_switch_to_carrier?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    delegation?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    audio_intercom?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    block_list_for_inbound_calls_and_messaging?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    block_calls_without_caller_id?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    block_external_calls?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        block_business_hours?: boolean;
        block_closed_hours?: boolean;
        block_holiday_hours?: boolean;
        block_call_action?: number;
    };
    peer_to_peer_media?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
    };
    advanced_encryption?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        disable_incoming_unencrypted_voicemail?: boolean;
    };
    display_call_feedback_survey?: {
        enable?: boolean;
        locked?: boolean;
        locked_by?: string;
        modified?: boolean;
        feedback_type?: number;
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
        audio_prompt_repeat?: number;
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
        audio_prompt_repeat?: number;
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
    match_type?: string;
    type?: string;
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListListExtensionsInboundBlockRulesResponse = {
    extension_blocked_rules?: {
        id?: string;
        match_type?: string;
        phone_number?: string;
        type?: string;
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
    match_type: string;
    blocked_number: string;
    type: string;
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
    match_type?: string;
    type?: string;
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListListAccountsInboundBlockedStatisticsResponse = {
    blocked_statistic?: {
        id?: string;
        match_type?: string;
        phone_number?: string;
        type?: string;
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
    match_type?: string;
    type?: string;
    status?: string;
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListListAccountsInboundBlockRulesResponse = {
    account_blocked_rules?: {
        id?: string;
        match_type?: string;
        phone_number?: string;
        type?: string;
        status?: string;
        comment?: string;
        blocked_number?: string;
        country?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type InboundBlockedListAddAccountsInboundBlockRuleRequestBody = {
    match_type: string;
    blocked_number: string;
    type: string;
    comment?: string;
    status: string;
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
    match_type: string;
    blocked_number: string;
    type: string;
    comment?: string;
    status?: string;
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
        type?: string;
    }[];
};
type LineKeysBatchUpdateLineKeyPositionAndSettingsInformationPathParams = {
    extensionId: string;
};
type LineKeysBatchUpdateLineKeyPositionAndSettingsInformationRequestBody = {
    line_keys?: {
        line_key_id?: string;
        index?: number;
        type?: string;
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
    type?: number;
    site_id?: string;
    page_size?: number;
    next_page_token?: string;
};
type MonitoringGroupsGetListOfMonitoringGroupsOnAccountResponse = {
    monitoring_groups?: {
        id?: string;
        monitor_members_count?: number;
        monitored_members_count?: number;
        monitoring_privileges?: string[];
        name?: string;
        prompt?: boolean;
        site?: {
            id?: string;
            name?: string;
        };
        type?: number;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type MonitoringGroupsCreateMonitoringGroupRequestBody = {
    monitoring_privileges?: string[];
    name?: string;
    prompt?: boolean;
    site_id?: string;
    type?: number;
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
    monitoring_privileges?: string[];
    name?: string;
    prompt?: boolean;
    site?: {
        id?: string;
        name?: string;
    };
    type?: number;
};
type MonitoringGroupsDeleteMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsUpdateMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsUpdateMonitoringGroupRequestBody = {
    monitoring_privileges?: string[];
    name?: string;
    prompt?: boolean;
    site_id?: string;
};
type MonitoringGroupsGetMembersOfMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsGetMembersOfMonitoringGroupQueryParams = {
    member_type: string;
    page_size?: number;
    next_page_token?: string;
};
type MonitoringGroupsGetMembersOfMonitoringGroupResponse = {
    members?: {
        display_name?: string;
        extension_id?: string;
        extension_number?: number;
        extension_type?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type MonitoringGroupsAddMembersToMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsAddMembersToMonitoringGroupQueryParams = {
    member_type: string;
};
type MonitoringGroupsAddMembersToMonitoringGroupRequestBody = string[];
type MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupPathParams = {
    monitoringGroupId: string;
};
type MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupQueryParams = {
    member_type: string;
};
type MonitoringGroupsRemoveMemberFromMonitoringGroupPathParams = {
    monitoringGroupId: string;
    memberExtensionId: string;
};
type MonitoringGroupsRemoveMemberFromMonitoringGroupQueryParams = {
    member_type?: string;
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
        rule?: number;
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
        rule?: number;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesPathParams = {
    commonAreaId: string;
};
type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: string;
    status?: string;
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: string;
        prefix_number?: string;
        rule?: number;
        comment?: string;
        status?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRulePathParams = {
    commonAreaId: string;
};
type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
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
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
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
        rule?: number;
        enabled_carrier?: string[];
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingUpdateAccountLevelOutboundCallingCountriesOrRegionsRequestBody = {
    country_regions?: {
        iso_code?: string;
        rule?: number;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListAccountLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: string;
    status?: string;
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListAccountLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: string;
        prefix_number?: string;
        rule?: number;
        comment?: string;
        status?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddAccountLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
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
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
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
        rule?: number;
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
        rule?: number;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListSiteLevelOutboundCallingExceptionRulesPathParams = {
    siteId: string;
};
type OutboundCallingListSiteLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: string;
    status?: string;
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListSiteLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: string;
        prefix_number?: string;
        rule?: number;
        comment?: string;
        status?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddSiteLevelOutboundCallingExceptionRulePathParams = {
    siteId: string;
};
type OutboundCallingAddSiteLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
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
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
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
        rule?: number;
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
        rule?: number;
        delete_existing_exception_rules?: boolean;
    }[];
};
type OutboundCallingListUserLevelOutboundCallingExceptionRulesPathParams = {
    userId: string;
};
type OutboundCallingListUserLevelOutboundCallingExceptionRulesQueryParams = {
    country?: string;
    keyword?: string;
    match_type?: string;
    status?: string;
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingListUserLevelOutboundCallingExceptionRulesResponse = {
    exception_rules?: {
        id?: string;
        match_type?: string;
        prefix_number?: string;
        rule?: number;
        comment?: string;
        status?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type OutboundCallingAddUserLevelOutboundCallingExceptionRulePathParams = {
    userId: string;
};
type OutboundCallingAddUserLevelOutboundCallingExceptionRuleRequestBody = {
    exception_rule?: {
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
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
        match_type: string;
        prefix_number: string;
        comment?: string;
        status: string;
        country: string;
    };
};
type PhoneDevicesListDevicesQueryParams = {
    type: string;
    assignee_type?: string;
    device_source?: string;
    location_status?: string;
    site_id?: string;
    device_type?: string;
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
            extension_type?: string;
        };
        assignees?: {
            extension_number?: number;
            id?: string;
            name?: string;
            extension_type?: string;
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
        status?: string;
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
        extension_type?: string;
    };
    assignees?: {
        extension_number?: number;
        id?: string;
        name?: string;
        extension_type?: string;
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
        type?: string;
        url?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    status?: string;
    provision_template_id?: string;
    private_ip?: string;
    public_ip?: string;
    policy?: {
        call_control?: {
            status?: string;
        };
        hot_desking?: {
            status?: string;
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
    mac_address?: string;
    provision_template_id?: string;
};
type PhoneDevicesAssignEntityToDevicePathParams = {
    deviceId: string;
};
type PhoneDevicesAssignEntityToDeviceRequestBody = {
    assignee_extension_ids: string[];
};
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
    type?: string;
    extension_type?: string;
    page_size?: number;
    number_type?: string;
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
            type?: string;
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
        emergency_address_status?: number;
        emergency_address_update_time?: string;
        id?: string;
        location?: string;
        number?: string;
        number_type?: string;
        sip_group?: {
            display_name?: string;
            id?: string;
        };
        site?: {
            id?: string;
            name?: string;
        };
        source?: string;
        status?: string;
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
        type?: string;
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
    emergency_address_status?: number;
    emergency_address_update_time?: string;
    id?: string;
    location?: string;
    number?: string;
    number_type?: string;
    sip_group?: {
        display_name?: string;
        id?: string;
    };
    site?: {
        id?: string;
        name?: string;
    };
    source?: string;
    status?: string;
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
    }[];
};
type PhonePlansListPlanInformationResponse = {
    calling_plans?: {
        assigned?: number;
        available?: number;
        name?: string;
        subscribed?: number;
        type?: number;
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
        extension_type: string;
        extension_number: number;
        extension_display_name: string;
        extension_email?: string;
        searchable_on_web_portal: string;
        site_id?: string;
        site_name?: string;
    }[];
};
type PrivateDirectoryAddMembersToPrivateDirectoryRequestBody = {
    site_id?: string;
    members: {
        extension_id: string;
        searchable_on_web_portal: string;
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
    searchable_on_web_portal: string;
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
    callee_name?: string;
    callee_number?: string;
    callee_number_type?: number;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: number;
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
        type?: string;
        extension_status?: string;
        extension_deleted_time?: string;
    };
    deleted_time?: string;
    days_left_auto_permantely_delete?: number;
    soft_deleted_type?: string;
    recording_type?: string;
    file_url?: string;
    disclaimer_status?: number;
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
        callee_number_type?: number;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
        outgoing_by?: {
            name?: string;
            extension_number?: string;
        };
        accepted_by?: {
            name?: string;
            extension_number?: string;
        };
        date_time?: string;
        disclaimer_status?: number;
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
            type?: string;
            extension_status?: string;
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
    action?: string;
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
        callee_number_type?: number;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
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
        call_type?: string;
        service_type?: string;
        calling_party_name?: string;
        cost_center?: string;
        employee_id?: string;
        department?: string;
        end_time?: string;
        duration?: number;
        charge_mode?: string;
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
        type?: string;
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
    type?: string;
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
        type?: string;
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
    type?: string;
};
type SMSGetAccountsSMSSessionsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    session_type?: string;
    phone_number?: string;
    filter_type?: string;
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
                type?: string;
            };
            phone_number?: string;
            is_session_owner?: boolean;
            extension_status?: string;
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
            type?: string;
        }[];
        date_time?: string;
        direction?: string;
        message?: string;
        message_id?: string;
        message_type?: number;
        sender?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: string;
            };
            phone_number: string;
        };
        to_members?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: string;
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
        type?: string;
    }[];
    date_time?: string;
    direction?: string;
    message?: string;
    message_id?: string;
    message_type?: number;
    sender?: {
        display_name?: string;
        owner?: {
            id?: string;
            type?: string;
        };
        phone_number: string;
    };
    to_members?: {
        display_name?: string;
        owner?: {
            id?: string;
            type?: string;
        };
        phone_number: string;
    }[];
};
type SMSSyncSMSBySessionIDPathParams = {
    sessionId: string;
};
type SMSSyncSMSBySessionIDQueryParams = {
    sync_type?: string;
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
            type?: string;
        }[];
        date_time?: string;
        direction?: string;
        message?: string;
        message_id?: string;
        message_type?: number;
        sender?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: string;
            };
            phone_number: string;
        };
        to_members?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: string;
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
    filter_type?: string;
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
                type?: string;
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
    sync_type: string;
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
                type?: string;
            }[];
            date_time?: string;
            direction?: string;
            message?: string;
            message_id?: string;
            message_type?: number;
            sender?: {
                display_name?: string;
                owner?: {
                    id?: string;
                    type?: string;
                };
                phone_number: string;
            };
            to_members?: {
                display_name?: string;
                owner?: {
                    id?: string;
                    type?: string;
                };
                phone_number: string;
            }[];
        };
        participants?: {
            display_name?: string;
            owner?: {
                id?: string;
                type?: string;
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
        status?: string;
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
    status?: string;
    service_type?: string;
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
    use_case?: string;
    categories_fit?: boolean;
    content_type?: string[];
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
    phone_numbers?: {
        id?: string;
        number?: string;
    }[];
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
        opt_status: string;
    }[];
};
type SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams = {
    smsCampaignId: string;
};
type SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignRequestBody = {
    consumer_phone_number: string;
    zoom_phone_user_numbers: string[];
    opt_status: string;
};
type SMSCampaignUnassignPhoneNumberPathParams = {
    smsCampaignId: string;
    phoneNumberId: string;
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
        type?: string;
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
            call_forwarding_type?: number;
        };
        call_overflow?: {
            enable?: boolean;
            call_overflow_type?: number;
        };
    };
    profile?: {
        area_code?: string;
        country?: string;
    };
    type?: string;
    user_settings?: {
        audio_prompt_language?: string;
        block_calls_without_caller_id?: boolean;
        call_handling?: {
            business_hours?: {
                business_hour_action?: number;
                connect_to_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: string;
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                busy_action?: number;
                busy_connect_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: string;
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
                    type?: number;
                    weekday?: number;
                }[];
                ring_type?: string;
                ringing_duration?: string;
                type?: number;
            };
            close_hours?: {
                close_hour_action?: number;
                connect_to_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: string;
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                busy_action?: number;
                busy_connect_operator?: {
                    enable?: boolean;
                    id?: string;
                    type?: string;
                    external_number?: {
                        number?: string;
                        description?: string;
                    };
                    play_callee_voicemail_greeting?: boolean;
                    require_press_1_before_connecting?: boolean;
                    allow_caller_check_voicemail?: boolean;
                };
                max_wait_time?: string;
            };
        };
        desk_phone?: {
            pin_code?: string;
        };
        hold_music?: string;
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
            call_forwarding_type?: number;
        };
        call_overflow?: {
            enable?: boolean;
            call_overflow_type?: number;
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
                business_hour_action?: number;
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
                busy_action?: number;
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
                    type?: number;
                    weekday?: number;
                }[];
                ring_type?: string;
                ringing_duration?: string;
                type?: number;
            };
            close_hours?: {
                close_hour_action?: number;
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
                busy_action?: number;
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
                max_wait_time?: string;
            };
        };
        desk_phone?: {
            pin_code?: string;
        };
        hold_music?: string;
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
        status?: string;
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
    status?: string;
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
            extension_type?: string;
        };
        assistants?: {
            id?: string;
            name?: string;
            extension_number?: number;
            extension_type?: string;
        }[];
        privileges?: string[];
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
            status?: string;
        }[];
        site?: {
            id?: string;
            name?: string;
        };
        status?: string;
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
    status?: string;
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
            access_user_type?: string;
        })[];
    };
    cost_center?: string;
    department?: string;
    audio_prompt_language?: string;
    recording_storage_location?: string;
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
        locked_by?: string;
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
    status?: string;
    timezone?: string;
    cost_center?: string;
    department?: string;
    audio_prompt_language?: string;
    recording_storage_location?: string;
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
        access_user_type?: string;
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
            locked_by?: string;
            modified?: boolean;
            allow_hide_outbound_caller_id?: boolean;
        };
        personal_audio_library?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
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
            locked_by?: string;
            modified?: boolean;
        };
        voicemail_transcription?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        voicemail_notification_by_email?: {
            include_voicemail_file?: boolean;
            include_voicemail_transcription?: boolean;
            forward_voicemail_to_email?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        shared_voicemail_notification_by_email?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        international_calling?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        zoom_phone_on_mobile?: {
            allow_calling_sms_mms?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        sms?: {
            enable?: boolean;
            international_sms?: boolean;
            international_sms_countries?: string[];
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        elevate_to_meeting?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        hand_off_to_room?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        mobile_switch_to_carrier?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        delegation?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        ad_hoc_call_recording?: {
            enable?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
            };
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        auto_call_recording?: {
            allow_stop_resume_recording?: boolean;
            disconnect_on_recording_failure?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
            recording_calls?: string;
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
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
            call_forwarding_type?: number;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        check_voicemails_over_phone?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        call_queue_pickup_code?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        call_queue_opt_out_reason?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
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
            locked_by?: string;
            items?: {
                type?: string;
                duration?: number;
                time_unit?: string;
            }[];
            delete_type?: number;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            expiration_period?: number;
            forward_to?: {
                display_name?: string;
                extension_id?: string;
                extension_number?: number;
                extension_type?: string;
                id?: string;
            };
            sequence?: number;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        call_overflow?: {
            call_overflow_type?: number;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        call_transferring?: {
            call_transferring_type?: number;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        audio_intercom?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        block_calls_without_caller_id?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        block_external_calls?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
            block_business_hours?: boolean;
            block_closed_hours?: boolean;
            block_holiday_hours?: boolean;
            block_call_action?: number;
            block_call_change_type?: number;
            e2e_encryption?: {
                enable?: boolean;
                locked?: boolean;
                locked_by?: string;
                modified?: boolean;
            };
        };
        force_off_net?: {
            enable?: boolean;
            allow_extension_only_users_call_users_outside_site?: boolean;
        };
    };
    sip_zone?: {
        id?: string;
        name?: string;
    };
    caller_id_name?: string;
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
        };
        sms?: {
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            international_sms?: boolean;
            international_sms_countries?: string[];
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
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
            };
        };
        auto_call_recording?: {
            allow_stop_resume_recording?: boolean;
            disconnect_on_recording_failure?: boolean;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            recording_calls?: string;
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
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
            call_forwarding_type?: number;
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
                type?: string;
                duration?: number;
                time_unit?: string;
            }[];
            delete_type?: number;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
            expiration_period?: number;
            forward_to_extension_id?: string;
            sequence?: number;
        };
        call_overflow?: {
            call_overflow_type?: number;
            enable?: boolean;
            reset?: boolean;
            locked?: boolean;
        };
        call_transferring?: {
            call_transferring_type?: number;
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
            block_call_action?: number;
            block_call_change_type?: number;
            e2e_encryption?: {
                enable?: boolean;
                locked?: boolean;
                locked_by?: string;
                modified?: boolean;
            };
        };
        force_off_net?: {
            enable?: boolean;
            allow_extension_only_users_call_users_outside_site?: boolean;
        };
    };
};
type SitesListCustomizedOutboundCallerIDPhoneNumbersPathParams = {
    siteId: string;
};
type SitesListCustomizedOutboundCallerIDPhoneNumbersQueryParams = {
    selected?: boolean;
    site_id?: string;
    extension_type?: string;
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
type SitesRemoveCustomizedOutboundCallerIDPhoneNumbersPathParams = {
    siteId: string;
};
type SitesRemoveCustomizedOutboundCallerIDPhoneNumbersQueryParams = {
    customize_ids?: string[];
};
type SitesGetPhoneSiteSettingPathParams = {
    siteId: string;
    settingType: string;
};
type SitesGetPhoneSiteSettingResponse = {
    location_based_routing?: {
        enable?: boolean;
        place_receive_pstn_calls?: boolean;
        enable_media_off_load_pstn_calls?: boolean;
    };
    business_hours?: {
        custom_hour_type?: number;
        custom_hours?: {
            from?: string;
            to?: string;
            type?: number;
            weekday?: number;
        }[];
        overflow?: {
            allow_caller_to_reach_operator?: boolean;
            operator?: {
                extension_id?: string;
                extension_number?: number;
                display_name?: string;
                extension_type?: string;
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
                extension_type?: string;
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
                extension_type?: string;
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
            number: number;
            unit?: string;
        };
    };
    dial_by_name?: {
        status?: boolean;
        inherit?: boolean;
        rule?: string;
    };
    billing_account?: {
        id?: string;
        name?: string;
    };
};
type SitesAddSiteSettingPathParams = {
    siteId: string;
    settingType: string;
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
    settingType: string;
};
type SitesDeleteSiteSettingQueryParams = {
    device_type?: string;
    holiday_id?: string;
};
type SitesUpdateSiteSettingPathParams = {
    siteId: string;
    settingType: string;
};
type SitesUpdateSiteSettingRequestBody = {
    location_based_routing?: {
        enable?: boolean;
        place_receive_pstn_calls?: boolean;
        enable_media_off_load_pstn_calls?: boolean;
    };
    business_hours?: {
        custom_hour_type?: number;
        custom_hours?: {
            from?: string;
            to?: string;
            type?: number;
            weekday?: number;
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
            number: number;
            unit?: string;
        };
    };
    dial_by_name?: {
        status?: boolean;
        inherit?: boolean;
        rule?: string;
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
    status?: string;
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
    batch_type?: string;
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
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
            };
            locked?: boolean;
            locked_by?: string;
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
            locked_by?: string;
            recording_calls?: string;
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
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
            call_overflow_type?: number;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            expiration_period?: number;
            forward_to?: {
                display_name?: string;
                extension_id?: string;
                extension_number?: number;
                extension_type?: string;
                id?: string;
            };
            locked?: boolean;
            locked_by?: string;
        };
        call_transferring?: {
            call_transferring_type?: number;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
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
            call_forwarding_type?: number;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        hand_off_to_room?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
        };
        international_calling?: boolean;
        mobile_switch_to_carrier?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
        };
        select_outbound_caller_id?: {
            enable?: boolean;
            allow_hide_outbound_caller_id?: boolean;
            locked?: boolean;
            locked_by?: string;
        };
        sms?: {
            enable?: boolean;
            international_sms?: boolean;
            international_sms_countries?: string[];
            locked?: boolean;
            locked_by?: string;
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
            allow_calling_sms_mms?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
        };
        personal_audio_library?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
            allow_music_on_hold_customization?: boolean;
            allow_voicemail_and_message_greeting_customization?: boolean;
        };
        voicemail_transcription?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        voicemail_notification_by_email?: {
            include_voicemail_file?: boolean;
            include_voicemail_transcription?: boolean;
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        shared_voicemail_notification_by_email?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        check_voicemails_over_phone?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        audio_intercom?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        peer_to_peer_media?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
            modified?: boolean;
        };
        e2e_encryption?: {
            enable?: boolean;
            locked?: boolean;
            locked_by?: string;
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
            locked_by?: string;
            modified?: boolean;
        };
        voicemail_tasks?: {
            enable?: boolean;
            locked?: boolean;
            modified?: boolean;
            locked_by?: string;
        };
    };
    site_admin?: boolean;
    site_id?: string;
    status?: string;
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
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
            };
        };
        auto_call_recording?: {
            allow_stop_resume_recording?: boolean;
            disconnect_on_recording_failure?: boolean;
            enable?: boolean;
            recording_calls?: string;
            recording_explicit_consent?: boolean;
            recording_start_prompt?: boolean;
            recording_transcription?: boolean;
            play_recording_beep_tone?: {
                enable?: boolean;
                play_beep_volume?: number;
                play_beep_time_interval?: number;
                play_beep_member?: string;
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
            call_overflow_type?: number;
            enable?: boolean;
            reset?: boolean;
        };
        call_park?: {
            call_not_picked_up_action?: number;
            enable?: boolean;
            expiration_period?: number;
            forward_to_extension_id?: string;
        };
        call_transferring?: {
            call_transferring_type?: number;
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
            call_forwarding_type?: number;
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
};
type UsersAssignCallingPlanToUserPathParams = {
    userId: string;
};
type UsersAssignCallingPlanToUserRequestBody = {
    calling_plans?: {
        type?: number;
        billing_account_id?: string;
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
    extension_type?: string;
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
                    status?: string;
                };
                hot_desking?: {
                    status?: string;
                };
            };
            status?: string;
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
    status?: string;
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
            status?: string;
            device_id?: string;
            device_status?: string;
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
                    status?: string;
                };
                hot_desking?: {
                    status?: string;
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
    callee_number_type?: number;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: number;
    date_time?: string;
    download_url?: string;
    duration?: number;
    id?: string;
    status?: string;
    transcription?: {
        content?: string;
        status?: number;
        engine?: string;
    };
};
type VoicemailsGetUsersVoicemailsPathParams = {
    userId: string;
};
type VoicemailsGetUsersVoicemailsQueryParams = {
    page_size?: number;
    status?: string;
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
        callee_number_type?: number;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
        date_time?: string;
        download_url?: string;
        duration?: number;
        id?: string;
        status?: string;
    }[];
};
type VoicemailsGetAccountVoicemailsQueryParams = {
    page_size?: number;
    status?: string;
    site_id?: string;
    owner_type?: string;
    voicemail_type?: string;
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
        callee_number_type?: number;
        caller_name?: string;
        caller_number?: string;
        caller_number_type?: number;
        date_time?: string;
        download_url?: string;
        duration?: number;
        id?: string;
        status?: string;
        owner?: {
            extension_number?: number;
            id?: string;
            name?: string;
            type?: string;
            extension_status?: string;
            extension_deleted_time?: string;
        };
        deleted_time?: string;
        days_left_auto_permantely_delete?: number;
        soft_deleted_type?: string;
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
    callee_name?: string;
    callee_number?: string;
    callee_number_type?: number;
    caller_name?: string;
    caller_number?: string;
    caller_number_type?: number;
    date_time?: string;
    download_url?: string;
    duration?: number;
    id?: string;
    status?: string;
    transcription?: {
        content?: string;
        status?: number;
        engine?: string;
    };
    deleted_time?: string;
    days_left_auto_permantely_delete?: number;
    soft_deleted_type?: string;
    intent_detect_status?: string;
    intent_results?: {
        intent_id?: string;
        confidence_score?: number;
    }[];
    voice_mail_task?: {
        status?: string;
        content?: string;
        feedback?: string;
    };
};
type VoicemailsUpdateVoicemailReadStatusPathParams = {
    voicemailId: string;
};
type VoicemailsUpdateVoicemailReadStatusQueryParams = {
    read_status: string;
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
            locked_by?: string;
        };
        select_outbound_caller_id?: {
            enable?: boolean;
            locked_by?: string;
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
        }) => Promise<BaseResponse<unknown>>;
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
                sub_setting_type?: string;
            };
        } | {
            body?: {
                settings?: {
                    name?: string;
                    from?: string;
                    to?: string;
                };
                sub_setting_type?: string;
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
                sub_setting_type?: string;
            };
        } | {
            body?: {
                settings?: {
                    from?: string;
                    holiday_id?: string;
                    name?: string;
                    to?: string;
                };
                sub_setting_type?: string;
            };
        } | {
            body?: {
                settings?: {
                    allow_members_to_reset?: boolean;
                    custom_hours_settings?: {
                        from?: string;
                        to?: string;
                        type?: number;
                        weekday?: number;
                    }[];
                    type?: number;
                };
                sub_setting_type?: string;
            };
        } | {
            body?: {
                settings?: {
                    allow_callers_check_voicemail?: boolean;
                    allow_members_to_reset?: boolean;
                    audio_while_connecting_id?: string;
                    call_distribution?: {
                        handle_multiple_calls?: boolean;
                        ring_duration?: number;
                        ring_mode?: string;
                        skip_offline_device_phone_number?: boolean;
                    };
                    call_not_answer_action?: number;
                    busy_on_another_call_action?: number;
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
                    max_wait_time?: number;
                    music_on_hold_id?: string;
                    operator_extension_id?: string;
                    receive_call?: boolean;
                    ring_mode?: string;
                    voicemail_greeting_id?: string;
                    voicemail_leaving_instruction_id?: string;
                    message_greeting_id?: string;
                    forward_to_zcc_phone_number?: string;
                    forward_to_partner_contact_center_id?: string;
                    forward_to_teams_id?: string;
                    wrap_up_time?: number;
                };
                sub_setting_type?: string;
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
        addPolicySettingToCallQueue: (_: {
            path: CallQueuesAddPolicySettingToCallQueuePathParams;
        } & {
            body?: CallQueuesAddPolicySettingToCallQueueRequestBody;
        } & object) => Promise<BaseResponse<CallQueuesAddPolicySettingToCallQueueResponse>>;
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
        addCommonAreaSettings: (_: {
            path: CommonAreasAddCommonAreaSettingsPathParams;
        } & {
            body?: CommonAreasAddCommonAreaSettingsRequestBody;
        } & object) => Promise<BaseResponse<CommonAreasAddCommonAreaSettingsResponse>>;
        deleteCommonAreaSetting: (_: {
            path: CommonAreasDeleteCommonAreaSettingPathParams;
        } & object & {
            query: CommonAreasDeleteCommonAreaSettingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateCommonAreaSettings: (_: {
            path: CommonAreasUpdateCommonAreaSettingsPathParams;
        } & {
            body?: CommonAreasUpdateCommonAreaSettingsRequestBody;
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
        }) => Promise<BaseResponse<unknown>>;
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
        } & object) => Promise<BaseResponse<unknown>>;
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
            body?: SMSCampaignAssignPhoneNumberToSMSCampaignRequestBody;
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
        } & object) => Promise<BaseResponse<unknown>>;
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
        } & object) => Promise<BaseResponse<unknown>>;
        removePhoneNumberFromZoomRoom: (_: {
            path: ZoomRoomsRemovePhoneNumberFromZoomRoomPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
}

type PhoneRecordingDeletedEvent = Event<"phone.recording_deleted"> & {
    event: string;
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
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                caller_number: string;
                caller_number_type: number;
                caller_number_source?: string;
                caller_name?: string;
                caller_location?: string;
                caller_did_number?: string;
                caller_country_code?: string;
                caller_country_iso_code?: string;
                callee_number: string;
                callee_number_type: number;
                callee_number_source?: string;
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
                call_type: string;
                call_end_time?: string;
                direction?: string;
                forwarded_to?: {
                    extension_number?: string;
                    extension_type?: string;
                    location?: string;
                    name?: string;
                    number_type?: number;
                    phone_number?: string;
                };
                forwarded_by?: {
                    extension_number?: string;
                    extension_type?: string;
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
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                caller_number: string;
                caller_number_type: number;
                caller_name?: string;
                caller_did_number?: string;
                callee_number: string;
                callee_number_type: number;
                callee_name: string;
                callee_did_number?: string;
                duration: number;
                download_url: string;
                date_time: string;
                user_id?: string;
                call_id?: string;
                call_log_id?: string;
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
                direction: string;
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
            direction: string;
            date_time: string;
            recording_type: string;
            call_id: string;
            owner: {
                type: string;
                id: string;
                name: string;
                extension_number: number;
            };
        };
    };
    event_ts: number;
};
type PhoneRecordingTranscriptCompletedEvent = Event<"phone.recording_transcript_completed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                caller_number: string;
                caller_number_type: number;
                caller_name?: string;
                callee_number: string;
                callee_number_type: number;
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
                direction: string;
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
    event: string;
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
                type?: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: string;
            };
            callee: {
                extension_id?: string;
                extension_type?: string;
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: string;
            };
            ringing_start_time: string;
        };
    };
};
type PhoneVoicemailReceivedEvent = Event<"phone.voicemail_received"> & {
    event: string;
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
            caller_number_type: number;
            caller_name: string;
            caller_did_number?: string;
            callee_user_id?: string;
            callee_number: string;
            callee_number_type: number;
            callee_name: string;
            callee_did_number?: string;
            callee_extension_type: string;
            callee_id: string;
            call_log_id?: string;
            call_id?: string;
        };
    };
};
type PhoneSmsSentEvent = Event<"phone.sms_sent"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            failure_reason?: string;
            sender: {
                phone_number: string;
                id?: string;
                type?: string;
                display_name?: string;
            };
            to_members: {
                id?: string;
                type?: string;
                display_name?: string;
                phone_number: string;
            }[];
            owner: {
                type?: string;
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
        };
    };
};
type PhoneVoicemailDeletedEvent = Event<"phone.voicemail_deleted"> & {
    event: string;
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
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            date_time: string;
            caller_number: string;
            caller_number_type: number;
            caller_name: string;
            callee_user_id?: string;
            callee_number: string;
            callee_number_type: number;
            callee_name: string;
            callee_extension_type?: string;
            callee_id?: string;
            call_log_id?: string;
            call_id?: string;
            transcription: {
                status: number;
                content: string;
            };
        };
    };
};
type PhoneRecordingPermanentlyDeletedEvent = Event<"phone.recording_permanently_deleted"> & {
    event: string;
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
    event: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
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
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                call_id: string;
                group_id?: string;
                connect_type?: string;
                call_type?: string;
                direction?: string;
                caller_ext_id?: string;
                caller_name?: string;
                caller_email?: string;
                caller_employee_id?: string;
                caller_did_number?: string;
                caller_ext_number?: string;
                caller_ext_type?: string;
                caller_number_type?: string;
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
                callee_ext_type?: string;
                callee_number_type?: string;
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
                event?: string;
                result: string;
                result_reason?: string;
                operator_ext_number?: string;
                operator_ext_id?: string;
                operator_ext_type?: string;
                operator_name?: string;
                recording_id?: string;
                recording_type?: string;
                voicemail_id?: string;
                talk_time?: number;
                hold_time?: number;
                wait_time?: number;
            }[];
        };
    };
};
type PhoneVoicemailPermanentlyDeletedEvent = Event<"phone.voicemail_permanently_deleted"> & {
    event: string;
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
    event: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            date_time: string;
        };
    };
};
type PhoneCallHistoryDeletedEvent = Event<"phone.call_history_deleted"> & {
    event: string;
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
type PhoneCallLogDeletedEvent = Event<"phone.call_log_deleted"> & {
    event: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_id?: string;
                connection_type?: string;
            };
            callee: {
                extension_id?: string;
                extension_type?: string;
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: string;
            };
            ringing_start_time: string;
            connected_start_time: string;
        };
    };
};
type PhoneRecordingCompletedEvent = Event<"phone.recording_completed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            recordings: {
                id: string;
                caller_number: string;
                caller_number_type: number;
                caller_name?: string;
                caller_did_number?: string;
                callee_number: string;
                callee_number_type: number;
                callee_name: string;
                callee_did_number?: string;
                duration: number;
                download_url: string;
                date_time: string;
                user_id?: string;
                call_id?: string;
                call_log_id?: string;
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
                direction: string;
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
            direction: string;
            date_time: string;
            recording_type: string;
            call_id: string;
            channel_id: string;
            sip_id: string;
            owner: {
                type: string;
                id: string;
                name: string;
                extension_number?: number;
            };
        };
    };
    event_ts: number;
};
type PhoneSmsSentFailedEvent = Event<"phone.sms_sent_failed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            failure_reason?: string;
            sender: {
                phone_number: string;
                id?: string;
                type?: string;
                display_name?: string;
            };
            to_members: {
                id?: string;
                display_name?: string;
                phone_number: string;
                is_message_owner?: boolean;
            }[];
            owner: {
                type?: string;
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
        };
    };
};
type PhoneCalleeCallLogCompletedEvent = Event<"phone.callee_call_log_completed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                caller_user_id?: string;
                caller_number: string;
                caller_number_type: number;
                caller_number_source?: string;
                caller_name?: string;
                caller_location?: string;
                caller_did_number?: string;
                caller_country_code?: string;
                caller_country_iso_code?: string;
                callee_user_id?: string;
                callee_number: string;
                callee_number_type: number;
                callee_number_source?: string;
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
                call_type?: string;
                call_end_time?: string;
                direction?: string;
                answer_start_time?: string;
                waiting_time?: number;
                forwarded_to?: {
                    extension_number?: string;
                    extension_type?: string;
                    location?: string;
                    name?: string;
                    number_type?: number;
                    phone_number?: string;
                };
                forwarded_by?: {
                    extension_number?: string;
                    extension_type?: string;
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
                extension_type?: string;
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                name?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_type?: string;
                device_name?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                name?: string;
                phone_number?: string;
                extension_number?: number;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
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
                type?: string;
            };
            date_time: string;
        };
    };
};
type PhoneAccountSettingsUpdatedEvent = Event<"phone.account_settings_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            settings: {
                call_live_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    transcription_start_prompt?: {
                        enable?: boolean;
                        audio_id?: string;
                        audio_name?: string;
                    };
                };
                local_survivability_mode?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                external_calling_on_zoom_room_common_area?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_videomail?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    allow_share?: boolean;
                    allow_virtual_background?: boolean;
                };
                voicemail_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
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
                    locked_by?: string;
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    recording_calls?: string;
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: string;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: string;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                    };
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    international_sms?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: number;
                        content?: string;
                        action?: number;
                        active?: boolean;
                    }[];
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_forwarding_type?: number;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_overflow_type?: number;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_transferring_type?: number;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                call_park?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    expiration_period?: number;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: string;
                        id?: string;
                    };
                    sequence?: number;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: number;
                };
                call_queue_opt_out_reason?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_queue_opt_out_reasons_list?: {
                        code?: string;
                        system?: boolean;
                        enable?: boolean;
                    }[];
                };
                auto_delete_data_after_retention_duration?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    items?: {
                        type?: string;
                        duration?: number;
                        time_unit?: string;
                    }[];
                    delete_type?: number;
                };
                auto_call_from_third_party_apps?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                override_default_port?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    min_port?: number;
                    max_port?: number;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    feedback_type?: number;
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
                    locked_by?: string;
                    transcription_start_prompt?: {
                        enable?: boolean;
                        audio_id?: string;
                        audio_name?: string;
                    };
                };
                local_survivability_mode?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                external_calling_on_zoom_room_common_area?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_videomail?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    allow_share?: boolean;
                    allow_virtual_background?: boolean;
                };
                voicemail_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
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
                    locked_by?: string;
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    recording_calls?: string;
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: string;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_member?: string;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                    };
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    international_sms?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: number;
                        content?: string;
                        action?: number;
                        active?: boolean;
                    }[];
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_forwarding_type?: number;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_overflow_type?: number;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_transferring_type?: number;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                call_park?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    expiration_period?: number;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: string;
                        id?: string;
                    };
                    sequence?: number;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: number;
                };
                call_queue_opt_out_reason?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    call_queue_opt_out_reasons_list?: {
                        code?: string;
                        system?: boolean;
                        enable?: boolean;
                    }[];
                };
                auto_delete_data_after_retention_duration?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    items?: {
                        type?: string;
                        duration?: number;
                        time_unit?: string;
                    }[];
                    delete_type?: number;
                };
                auto_call_from_third_party_apps?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                override_default_port?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    min_port?: number;
                    max_port?: number;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    feedback_type?: number;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
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
                extension_type: string;
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
            router: string;
            deliver_to: string;
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
type PhoneCalleeRejectedEvent = Event<"phone.callee_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            call_id: string;
            callee: {
                extension_id?: string;
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            ringing_start_time: string;
            call_end_time: string;
            handup_result?: string;
        };
    };
};
type PhoneGroupSettingsUpdatedEvent = Event<"phone.group_settings_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            group_id: string;
            settings: {
                call_live_transcription?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
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
                    locked_by?: string;
                    modified?: boolean;
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
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
                    locked_by?: string;
                    modified?: boolean;
                };
                voicemail_notification_by_email?: {
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
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
                    locked_by?: string;
                    modified?: boolean;
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    recording_calls?: string;
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                        play_beep_member?: string;
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                        play_beep_member?: string;
                    };
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    modified?: boolean;
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: number;
                        content?: string;
                        action?: number;
                        active?: boolean;
                    }[];
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                sms?: {
                    enable?: boolean;
                    international_sms?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    call_forwarding_type?: number;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    call_overflow_type?: number;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    call_transferring_type?: number;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                call_park?: {
                    enable?: boolean;
                    expiration_period?: number;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: string;
                        id?: string;
                    };
                    sequence?: number;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: number;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    feedback_type?: number;
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
                    locked_by?: string;
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
                    locked_by?: string;
                    modified?: boolean;
                };
                select_outbound_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    allow_hide_outbound_caller_id?: boolean;
                };
                personal_audio_library?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    allow_music_on_hold_customization?: boolean;
                    allow_voicemail_and_message_greeting_customization?: boolean;
                };
                voicemail?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
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
                    locked_by?: string;
                    modified?: boolean;
                };
                voicemail_notification_by_email?: {
                    include_voicemail_file?: boolean;
                    include_voicemail_transcription?: boolean;
                    forward_voicemail_to_email?: boolean;
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                shared_voicemail_notification_by_email?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                restricted_call_hours?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
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
                    locked_by?: string;
                    modified?: boolean;
                    locations_applied?: boolean;
                    allow_internal_calls?: boolean;
                };
                check_voicemails_over_phone?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                auto_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    recording_calls?: string;
                    recording_transcription?: boolean;
                    recording_start_prompt?: boolean;
                    recording_start_prompt_audio_id?: string;
                    recording_explicit_consent?: boolean;
                    allow_stop_resume_recording?: boolean;
                    disconnect_on_recording_failure?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                        play_beep_member?: string;
                    };
                };
                ad_hoc_call_recording?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    recording_transcription?: boolean;
                    allow_download?: boolean;
                    allow_delete?: boolean;
                    recording_start_prompt?: boolean;
                    recording_explicit_consent?: boolean;
                    play_recording_beep_tone?: {
                        enable?: boolean;
                        play_beep_volume?: number;
                        play_beep_time_interval?: number;
                        play_beep_member?: string;
                    };
                };
                zoom_phone_on_mobile?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    allow_calling_sms_mms?: boolean;
                };
                zoom_phone_on_pwa?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                sms_etiquette_tool?: {
                    enable?: boolean;
                    modified?: boolean;
                    sms_etiquette_policy?: {
                        id?: string;
                        name?: string;
                        description?: string;
                        rule?: number;
                        content?: string;
                        action?: number;
                        active?: boolean;
                    }[];
                };
                outbound_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                outbound_sms?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                international_calling?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                sms?: {
                    enable?: boolean;
                    international_sms?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                e2e_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                call_handling_forwarding_to_other_users?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    call_forwarding_type?: number;
                };
                call_overflow?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    call_overflow_type?: number;
                };
                call_transferring?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    call_transferring_type?: number;
                };
                elevate_to_meeting?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                call_park?: {
                    enable?: boolean;
                    expiration_period?: number;
                    call_not_picked_up_action?: number;
                    forward_to?: {
                        display_name?: string;
                        extension_id?: string;
                        extension_number?: number;
                        extension_type?: string;
                        id?: string;
                    };
                    sequence?: number;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                hand_off_to_room?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                mobile_switch_to_carrier?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                delegation?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                audio_intercom?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                block_calls_without_caller_id?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                block_external_calls?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    block_business_hours?: boolean;
                    block_closed_hours?: boolean;
                    block_holiday_hours?: boolean;
                    block_call_action?: number;
                };
                peer_to_peer_media?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                };
                advanced_encryption?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    disable_incoming_unencrypted_voicemail?: boolean;
                };
                display_call_feedback_survey?: {
                    enable?: boolean;
                    locked?: boolean;
                    locked_by?: string;
                    modified?: boolean;
                    feedback_type?: number;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
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
            direction: string;
            date_time: string;
            recording_type: string;
            call_id: string;
            channel_id: string;
            sip_id: string;
            owner: {
                type: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            meeting_id?: string;
            date_time: string;
        };
    };
};
type PhoneVoicemailReceivedForAccessMemberEvent = Event<"phone.voicemail_received_for_access_member"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            date_time: string;
            download_url: string;
            duration: number;
            caller_number: string;
            caller_number_type: number;
            caller_name: string;
            caller_did_number?: string;
            callee_user_id?: string;
            callee_number: string;
            callee_number_type: number;
            callee_name: string;
            callee_did_number?: string;
            callee_extension_type: string;
            callee_id: string;
            call_log_id?: string;
            call_id?: string;
            access_member_id?: string;
            access_member_extension_type?: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number?: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
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
                type?: string;
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
                type: string;
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
            direction: string;
            date_time: string;
            recording_type: string;
            call_id: string;
            owner: {
                type: string;
                id: string;
                name: string;
                extension_number?: number;
            };
        };
    };
    event_ts: number;
};
type PhoneSmsReceivedEvent = Event<"phone.sms_received"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            sender: {
                phone_number: string;
                id?: string;
                type?: string;
                display_name?: string;
            };
            to_members: {
                id?: string;
                type?: string;
                display_name?: string;
                phone_number: string;
                is_message_owner?: boolean;
            }[];
            owner: {
                type?: string;
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
            direction: string;
            date_time: string;
            recording_type: string;
            call_id: string;
            channel_id: string;
            sip_id: string;
            owner: {
                type: string;
                id: string;
                name: string;
                extension_number?: number;
            };
        };
    };
    event_ts: number;
};
type PhoneCallerCallHistoryCompletedEvent = Event<"phone.caller_call_history_completed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            user_id: string;
            call_logs: {
                id: string;
                call_id: string;
                group_id?: string;
                connect_type?: string;
                call_type?: string;
                direction?: string;
                caller_ext_id?: string;
                caller_name?: string;
                caller_email?: string;
                caller_employee_id?: string;
                caller_did_number?: string;
                caller_ext_number?: string;
                caller_ext_type?: string;
                caller_number_type?: string;
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
                callee_ext_type?: string;
                callee_number_type?: string;
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
                event?: string;
                result: string;
                result_reason?: string;
                operator_ext_number?: string;
                operator_ext_id?: string;
                operator_ext_type?: string;
                operator_name?: string;
                recording_id?: string;
                recording_type?: string;
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
                extension_type?: string;
                user_id?: string;
                phone_number: string;
                extension_number?: number;
                timezone?: string;
                connection_type?: string;
            };
            caller: {
                extension_id?: string;
                extension_type?: string;
                phone_number: string;
                user_id?: string;
                extension_number?: number;
                timezone?: string;
                device_id?: string;
                connection_type?: string;
            };
            date_time: string;
        };
    };
};
type PhoneEvents = PhoneRecordingDeletedEvent | PhoneCallerCallLogCompletedEvent | PhoneRecordingCompletedForAccessMemberEvent | PhoneRecordingResumedEvent | PhoneRecordingTranscriptCompletedEvent | PhoneCallLogPermanentlyDeletedEvent | PhoneTransferCallToVoicemailInitiatedEvent | PhoneCalleeMissedEvent | PhoneCallerRingingEvent | PhoneVoicemailReceivedEvent | PhoneSmsSentEvent | PhoneVoicemailDeletedEvent | PhoneVoicemailTranscriptCompletedEvent | PhoneRecordingPermanentlyDeletedEvent | PhonePeeringNumberEmergencyAddressUpdatedEvent | PhoneSmsCampaignNumberOptOutEvent | PhoneCallerEndedEvent | PhoneCalleeEndedEvent | PhoneCalleeCallHistoryCompletedEvent | PhoneVoicemailPermanentlyDeletedEvent | PhoneSmsCampaignNumberOptInEvent | PhoneCalleeMuteEvent | PhoneCallHistoryDeletedEvent | PhoneCallLogDeletedEvent | PhoneCallerHoldEvent | PhoneCallerConnectedEvent | PhoneRecordingCompletedEvent | PhoneRecordingStartedEvent | PhoneSmsSentFailedEvent | PhoneCalleeCallLogCompletedEvent | PhoneCalleeRingingEvent | PhoneCallerUnholdEvent | PhoneCalleeHoldEvent | PhoneCalleeAnsweredEvent | PhoneCallerUnmuteEvent | PhoneDeviceRegistrationEvent | PhoneBlindTransferInitiatedEvent | PhoneAccountSettingsUpdatedEvent | PhoneCalleeMeetingInvitingEvent | PhoneCalleeParkedEvent | PhoneEmergencyAlertEvent | PhoneCalleeRejectedEvent | PhoneGroupSettingsUpdatedEvent | PhoneCalleeUnmuteEvent | PhoneRecordingStoppedEvent | PhoneCallerMeetingInvitingEvent | PhoneVoicemailReceivedForAccessMemberEvent | PhoneCalleeUnholdEvent | PhoneConferenceStartedEvent | PhoneGenericDeviceProvisionEvent | PhoneRecordingPausedEvent | PhoneSmsReceivedEvent | PhoneRecordingFailedEvent | PhoneCallerCallHistoryCompletedEvent | PhonePeeringNumberCnamUpdatedEvent | PhoneCallerMuteEvent;
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

export { type AccountsAddPhoneNumbersForAccountsCustomizedOutboundCallerIDRequestBody, type AccountsDeletePhoneNumbersForAccountsCustomizedOutboundCallerIDQueryParams, type AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersQueryParams, type AccountsListAccountsCustomizedOutboundCallerIDPhoneNumbersResponse, type AccountsListAccountsZoomPhoneSettingsQueryParams, type AccountsListAccountsZoomPhoneSettingsResponse, type AlertsAddAlertSettingRequestBody, type AlertsAddAlertSettingResponse, type AlertsDeleteAlertSettingPathParams, type AlertsGetAlertSettingDetailsPathParams, type AlertsGetAlertSettingDetailsResponse, type AlertsListAlertSettingsWithPagingQueryQueryParams, type AlertsListAlertSettingsWithPagingQueryResponse, type AlertsUpdateAlertSettingPathParams, type AlertsUpdateAlertSettingRequestBody, ApiResponseError, type AudioLibraryAddAudioItemForTextToSpeechConversionPathParams, type AudioLibraryAddAudioItemForTextToSpeechConversionRequestBody, type AudioLibraryAddAudioItemForTextToSpeechConversionResponse, type AudioLibraryAddAudioItemsPathParams, type AudioLibraryAddAudioItemsRequestBody, type AudioLibraryAddAudioItemsResponse, type AudioLibraryDeleteAudioItemPathParams, type AudioLibraryGetAudioItemPathParams, type AudioLibraryGetAudioItemResponse, type AudioLibraryListAudioItemsPathParams, type AudioLibraryListAudioItemsResponse, type AudioLibraryUpdateAudioItemPathParams, type AudioLibraryUpdateAudioItemRequestBody, type AutoReceptionistsAddAutoReceptionistRequestBody, type AutoReceptionistsAddAutoReceptionistResponse, type AutoReceptionistsAddPolicySubsettingPathParams, type AutoReceptionistsAddPolicySubsettingRequestBody, type AutoReceptionistsAddPolicySubsettingResponse, type AutoReceptionistsAssignPhoneNumbersPathParams, type AutoReceptionistsAssignPhoneNumbersRequestBody, type AutoReceptionistsDeleteNonPrimaryAutoReceptionistPathParams, type AutoReceptionistsDeletePolicySubsettingPathParams, type AutoReceptionistsDeletePolicySubsettingQueryParams, type AutoReceptionistsGetAutoReceptionistPathParams, type AutoReceptionistsGetAutoReceptionistPolicyPathParams, type AutoReceptionistsGetAutoReceptionistPolicyResponse, type AutoReceptionistsGetAutoReceptionistResponse, type AutoReceptionistsListAutoReceptionistsQueryParams, type AutoReceptionistsListAutoReceptionistsResponse, type AutoReceptionistsUnassignAllPhoneNumbersPathParams, type AutoReceptionistsUnassignPhoneNumberPathParams, type AutoReceptionistsUpdateAutoReceptionistPathParams, type AutoReceptionistsUpdateAutoReceptionistPolicyPathParams, type AutoReceptionistsUpdateAutoReceptionistPolicyRequestBody, type AutoReceptionistsUpdateAutoReceptionistRequestBody, type AutoReceptionistsUpdatePolicySubsettingPathParams, type AutoReceptionistsUpdatePolicySubsettingRequestBody, AwsLambdaReceiver, AwsReceiverRequestError, type BillingAccountGetBillingAccountDetailsPathParams, type BillingAccountGetBillingAccountDetailsResponse, type BillingAccountListBillingAccountsQueryParams, type BillingAccountListBillingAccountsResponse, type BlockedListCreateBlockedListRequestBody, type BlockedListCreateBlockedListResponse, type BlockedListDeleteBlockedListPathParams, type BlockedListGetBlockedListDetailsPathParams, type BlockedListGetBlockedListDetailsResponse, type BlockedListListBlockedListsQueryParams, type BlockedListListBlockedListsResponse, type BlockedListUpdateBlockedListPathParams, type BlockedListUpdateBlockedListRequestBody, type CallHandlingAddCallHandlingSettingPathParams, type CallHandlingAddCallHandlingSettingRequestBody, type CallHandlingAddCallHandlingSettingResponse, type CallHandlingDeleteCallHandlingSettingPathParams, type CallHandlingDeleteCallHandlingSettingQueryParams, type CallHandlingGetCallHandlingSettingsPathParams, type CallHandlingGetCallHandlingSettingsResponse, type CallHandlingUpdateCallHandlingSettingPathParams, type CallHandlingUpdateCallHandlingSettingRequestBody, type CallLogsAddClientCodeToCallHistoryPathParams, type CallLogsAddClientCodeToCallHistoryRequestBody, type CallLogsAddClientCodeToCallLogPathParams, type CallLogsAddClientCodeToCallLogRequestBody, type CallLogsDeleteUsersCallHistoryPathParams, type CallLogsDeleteUsersCallLogPathParams, type CallLogsGetAccountsCallHistoryQueryParams, type CallLogsGetAccountsCallHistoryResponse, type CallLogsGetAccountsCallLogsQueryParams, type CallLogsGetAccountsCallLogsResponse, type CallLogsGetCallLogDetailsPathParams, type CallLogsGetCallLogDetailsResponse, type CallLogsGetCallPathPathParams, type CallLogsGetCallPathResponse, type CallLogsGetUsersCallHistoryPathParams, type CallLogsGetUsersCallHistoryQueryParams, type CallLogsGetUsersCallHistoryResponse, type CallLogsGetUsersCallLogsPathParams, type CallLogsGetUsersCallLogsQueryParams, type CallLogsGetUsersCallLogsResponse, type CallLogsSyncUsersCallHistoryPathParams, type CallLogsSyncUsersCallHistoryQueryParams, type CallLogsSyncUsersCallHistoryResponse, type CallLogsSyncUsersCallLogsPathParams, type CallLogsSyncUsersCallLogsQueryParams, type CallLogsSyncUsersCallLogsResponse, type CallQueuesAddMembersToCallQueuePathParams, type CallQueuesAddMembersToCallQueueRequestBody, type CallQueuesAddPolicySettingToCallQueuePathParams, type CallQueuesAddPolicySettingToCallQueueRequestBody, type CallQueuesAddPolicySettingToCallQueueResponse, type CallQueuesAssignNumbersToCallQueuePathParams, type CallQueuesAssignNumbersToCallQueueRequestBody, type CallQueuesCreateCallQueueRequestBody, type CallQueuesCreateCallQueueResponse, type CallQueuesDeleteCQPolicySettingPathParams, type CallQueuesDeleteCQPolicySettingQueryParams, type CallQueuesDeleteCallQueuePathParams, type CallQueuesGetCallQueueDetailsPathParams, type CallQueuesGetCallQueueDetailsResponse, type CallQueuesGetCallQueueRecordingsPathParams, type CallQueuesGetCallQueueRecordingsQueryParams, type CallQueuesGetCallQueueRecordingsResponse, type CallQueuesListCallQueueMembersPathParams, type CallQueuesListCallQueueMembersResponse, type CallQueuesListCallQueuesQueryParams, type CallQueuesListCallQueuesResponse, type CallQueuesUnassignAllMembersPathParams, type CallQueuesUnassignAllPhoneNumbersPathParams, type CallQueuesUnassignMemberPathParams, type CallQueuesUnassignPhoneNumberPathParams, type CallQueuesUpdateCallQueueDetailsPathParams, type CallQueuesUpdateCallQueueDetailsRequestBody, type CallQueuesUpdateCallQueuesPolicySubsettingPathParams, type CallQueuesUpdateCallQueuesPolicySubsettingRequestBody, type CarrierResellerActivatePhoneNumbersRequestBody, type CarrierResellerCreatePhoneNumbersRequestBody, type CarrierResellerDeletePhoneNumberPathParams, type CarrierResellerListPhoneNumbersQueryParams, type CarrierResellerListPhoneNumbersResponse, ClientCredentialsRawResponseError, type ClientCredentialsToken, type CommonAreasAddCommonAreaRequestBody, type CommonAreasAddCommonAreaResponse, type CommonAreasAddCommonAreaSettingsPathParams, type CommonAreasAddCommonAreaSettingsRequestBody, type CommonAreasAddCommonAreaSettingsResponse, type CommonAreasApplyTemplateToCommonAreasPathParams, type CommonAreasApplyTemplateToCommonAreasRequestBody, type CommonAreasAssignCallingPlansToCommonAreaPathParams, type CommonAreasAssignCallingPlansToCommonAreaRequestBody, type CommonAreasAssignCallingPlansToCommonAreaResponse, type CommonAreasAssignPhoneNumbersToCommonAreaPathParams, type CommonAreasAssignPhoneNumbersToCommonAreaRequestBody, type CommonAreasAssignPhoneNumbersToCommonAreaResponse, type CommonAreasDeleteCommonAreaPathParams, type CommonAreasDeleteCommonAreaSettingPathParams, type CommonAreasDeleteCommonAreaSettingQueryParams, type CommonAreasGetCommonAreaDetailsPathParams, type CommonAreasGetCommonAreaDetailsResponse, type CommonAreasGetCommonAreaSettingsPathParams, type CommonAreasGetCommonAreaSettingsResponse, type CommonAreasListActivationCodesQueryParams, type CommonAreasListActivationCodesResponse, type CommonAreasListCommonAreasQueryParams, type CommonAreasListCommonAreasResponse, type CommonAreasUnassignCallingPlanFromCommonAreaPathParams, type CommonAreasUnassignCallingPlanFromCommonAreaQueryParams, type CommonAreasUnassignPhoneNumbersFromCommonAreaPathParams, type CommonAreasUpdateCommonAreaPathParams, type CommonAreasUpdateCommonAreaPinCodePathParams, type CommonAreasUpdateCommonAreaPinCodeRequestBody, type CommonAreasUpdateCommonAreaRequestBody, type CommonAreasUpdateCommonAreaSettingsPathParams, type CommonAreasUpdateCommonAreaSettingsRequestBody, CommonHttpRequestError, ConsoleLogger, type DashboardGetCallDetailsFromCallLogPathParams, type DashboardGetCallDetailsFromCallLogResponse, type DashboardGetCallQoSPathParams, type DashboardGetCallQoSResponse, type DashboardListCallLogsQueryParams, type DashboardListCallLogsResponse, type DashboardListPastCallMetricsQueryParams, type DashboardListPastCallMetricsResponse, type DashboardListTrackedLocationsQueryParams, type DashboardListTrackedLocationsResponse, type DeviceLineKeysBatchUpdateDeviceLineKeyPositionPathParams, type DeviceLineKeysBatchUpdateDeviceLineKeyPositionRequestBody, type DeviceLineKeysGetDeviceLineKeysInformationPathParams, type DeviceLineKeysGetDeviceLineKeysInformationResponse, type DialByNameDirectoryAddUsersToDirectoryOfSitePathParams, type DialByNameDirectoryAddUsersToDirectoryOfSiteRequestBody, type DialByNameDirectoryAddUsersToDirectoryRequestBody, type DialByNameDirectoryDeleteUsersFromDirectoryOfSitePathParams, type DialByNameDirectoryDeleteUsersFromDirectoryOfSiteQueryParams, type DialByNameDirectoryDeleteUsersFromDirectoryQueryParams, type DialByNameDirectoryListUsersInDirectoryBySitePathParams, type DialByNameDirectoryListUsersInDirectoryBySiteQueryParams, type DialByNameDirectoryListUsersInDirectoryBySiteResponse, type DialByNameDirectoryListUsersInDirectoryQueryParams, type DialByNameDirectoryListUsersInDirectoryResponse, type EmergencyAddressesAddEmergencyAddressRequestBody, type EmergencyAddressesAddEmergencyAddressResponse, type EmergencyAddressesDeleteEmergencyAddressPathParams, type EmergencyAddressesGetEmergencyAddressDetailsPathParams, type EmergencyAddressesGetEmergencyAddressDetailsResponse, type EmergencyAddressesListEmergencyAddressesQueryParams, type EmergencyAddressesListEmergencyAddressesResponse, type EmergencyAddressesUpdateEmergencyAddressPathParams, type EmergencyAddressesUpdateEmergencyAddressRequestBody, type EmergencyAddressesUpdateEmergencyAddressResponse, type EmergencyServiceLocationsAddEmergencyServiceLocationRequestBody, type EmergencyServiceLocationsAddEmergencyServiceLocationResponse, type EmergencyServiceLocationsBatchAddEmergencyServiceLocationsRequestBody, type EmergencyServiceLocationsBatchAddEmergencyServiceLocationsResponse, type EmergencyServiceLocationsDeleteEmergencyLocationPathParams, type EmergencyServiceLocationsGetEmergencyServiceLocationDetailsPathParams, type EmergencyServiceLocationsGetEmergencyServiceLocationDetailsResponse, type EmergencyServiceLocationsListEmergencyServiceLocationsQueryParams, type EmergencyServiceLocationsListEmergencyServiceLocationsResponse, type EmergencyServiceLocationsUpdateEmergencyServiceLocationPathParams, type EmergencyServiceLocationsUpdateEmergencyServiceLocationRequestBody, type ExternalContactsAddExternalContactRequestBody, type ExternalContactsAddExternalContactResponse, type ExternalContactsDeleteExternalContactPathParams, type ExternalContactsGetExternalContactDetailsPathParams, type ExternalContactsGetExternalContactDetailsResponse, type ExternalContactsListExternalContactsQueryParams, type ExternalContactsListExternalContactsResponse, type ExternalContactsUpdateExternalContactPathParams, type ExternalContactsUpdateExternalContactRequestBody, type FirmwareUpdateRulesAddFirmwareUpdateRuleRequestBody, type FirmwareUpdateRulesAddFirmwareUpdateRuleResponse, type FirmwareUpdateRulesDeleteFirmwareUpdateRulePathParams, type FirmwareUpdateRulesDeleteFirmwareUpdateRuleQueryParams, type FirmwareUpdateRulesGetFirmwareUpdateRuleInformationPathParams, type FirmwareUpdateRulesGetFirmwareUpdateRuleInformationResponse, type FirmwareUpdateRulesListFirmwareUpdateRulesQueryParams, type FirmwareUpdateRulesListFirmwareUpdateRulesResponse, type FirmwareUpdateRulesListUpdatableFirmwaresQueryParams, type FirmwareUpdateRulesListUpdatableFirmwaresResponse, type FirmwareUpdateRulesUpdateFirmwareUpdateRulePathParams, type FirmwareUpdateRulesUpdateFirmwareUpdateRuleRequestBody, type GroupCallPickupAddGroupCallPickupObjectRequestBody, type GroupCallPickupAddGroupCallPickupObjectResponse, type GroupCallPickupAddMembersToCallPickupGroupPathParams, type GroupCallPickupAddMembersToCallPickupGroupRequestBody, type GroupCallPickupDeleteGroupCallPickupObjectsPathParams, type GroupCallPickupGetCallPickupGroupByIDPathParams, type GroupCallPickupGetCallPickupGroupByIDResponse, type GroupCallPickupListCallPickupGroupMembersPathParams, type GroupCallPickupListCallPickupGroupMembersQueryParams, type GroupCallPickupListCallPickupGroupMembersResponse, type GroupCallPickupListGroupCallPickupObjectsQueryParams, type GroupCallPickupListGroupCallPickupObjectsResponse, type GroupCallPickupRemoveMembersFromCallPickupGroupPathParams, type GroupCallPickupUpdateGroupCallPickupInformationPathParams, type GroupCallPickupUpdateGroupCallPickupInformationRequestBody, type GroupsGetGroupPhoneSettingsPathParams, type GroupsGetGroupPhoneSettingsQueryParams, type GroupsGetGroupPhoneSettingsResponse, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, type HttpReceiverOptions, type IVRGetAutoReceptionistIVRPathParams, type IVRGetAutoReceptionistIVRQueryParams, type IVRGetAutoReceptionistIVRResponse, type IVRUpdateAutoReceptionistIVRPathParams, type IVRUpdateAutoReceptionistIVRRequestBody, type InboundBlockedListAddAccountsInboundBlockRuleRequestBody, type InboundBlockedListAddAccountsInboundBlockRuleResponse, type InboundBlockedListAddExtensionsInboundBlockRulePathParams, type InboundBlockedListAddExtensionsInboundBlockRuleRequestBody, type InboundBlockedListAddExtensionsInboundBlockRuleResponse, type InboundBlockedListDeleteAccountsInboundBlockRuleQueryParams, type InboundBlockedListDeleteAccountsInboundBlockedStatisticsQueryParams, type InboundBlockedListDeleteExtensionsInboundBlockRulePathParams, type InboundBlockedListDeleteExtensionsInboundBlockRuleQueryParams, type InboundBlockedListListAccountsInboundBlockRulesQueryParams, type InboundBlockedListListAccountsInboundBlockRulesResponse, type InboundBlockedListListAccountsInboundBlockedStatisticsQueryParams, type InboundBlockedListListAccountsInboundBlockedStatisticsResponse, type InboundBlockedListListExtensionsInboundBlockRulesPathParams, type InboundBlockedListListExtensionsInboundBlockRulesQueryParams, type InboundBlockedListListExtensionsInboundBlockRulesResponse, type InboundBlockedListMarkPhoneNumberAsBlockedForAllExtensionsRequestBody, type InboundBlockedListUpdateAccountsInboundBlockRulePathParams, type InboundBlockedListUpdateAccountsInboundBlockRuleRequestBody, type JwtToken, type LineKeysBatchUpdateLineKeyPositionAndSettingsInformationPathParams, type LineKeysBatchUpdateLineKeyPositionAndSettingsInformationRequestBody, type LineKeysDeleteLineKeySettingPathParams, type LineKeysGetLineKeyPositionAndSettingsInformationPathParams, type LineKeysGetLineKeyPositionAndSettingsInformationResponse, LogLevel, type Logger, type MonitoringGroupsAddMembersToMonitoringGroupPathParams, type MonitoringGroupsAddMembersToMonitoringGroupQueryParams, type MonitoringGroupsAddMembersToMonitoringGroupRequestBody, type MonitoringGroupsCreateMonitoringGroupRequestBody, type MonitoringGroupsCreateMonitoringGroupResponse, type MonitoringGroupsDeleteMonitoringGroupPathParams, type MonitoringGroupsGetListOfMonitoringGroupsOnAccountQueryParams, type MonitoringGroupsGetListOfMonitoringGroupsOnAccountResponse, type MonitoringGroupsGetMembersOfMonitoringGroupPathParams, type MonitoringGroupsGetMembersOfMonitoringGroupQueryParams, type MonitoringGroupsGetMembersOfMonitoringGroupResponse, type MonitoringGroupsGetMonitoringGroupByIDPathParams, type MonitoringGroupsGetMonitoringGroupByIDResponse, type MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupPathParams, type MonitoringGroupsRemoveAllMonitorsOrMonitoredMembersFromMonitoringGroupQueryParams, type MonitoringGroupsRemoveMemberFromMonitoringGroupPathParams, type MonitoringGroupsRemoveMemberFromMonitoringGroupQueryParams, type MonitoringGroupsUpdateMonitoringGroupPathParams, type MonitoringGroupsUpdateMonitoringGroupRequestBody, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, type OAuthToken, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, type OutboundCallingAddAccountLevelOutboundCallingExceptionRuleRequestBody, type OutboundCallingAddAccountLevelOutboundCallingExceptionRuleResponse, type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRulePathParams, type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleRequestBody, type OutboundCallingAddCommonAreaLevelOutboundCallingExceptionRuleResponse, type OutboundCallingAddSiteLevelOutboundCallingExceptionRulePathParams, type OutboundCallingAddSiteLevelOutboundCallingExceptionRuleRequestBody, type OutboundCallingAddSiteLevelOutboundCallingExceptionRuleResponse, type OutboundCallingAddUserLevelOutboundCallingExceptionRulePathParams, type OutboundCallingAddUserLevelOutboundCallingExceptionRuleRequestBody, type OutboundCallingAddUserLevelOutboundCallingExceptionRuleResponse, type OutboundCallingDeleteAccountLevelOutboundCallingExceptionRulePathParams, type OutboundCallingDeleteCommonAreaLevelOutboundCallingExceptionRulePathParams, type OutboundCallingDeleteSiteLevelOutboundCallingExceptionRulePathParams, type OutboundCallingDeleteUserLevelOutboundCallingExceptionRulePathParams, type OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsQueryParams, type OutboundCallingGetAccountLevelOutboundCallingCountriesAndRegionsResponse, type OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsPathParams, type OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsQueryParams, type OutboundCallingGetCommonAreaLevelOutboundCallingCountriesAndRegionsResponse, type OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsPathParams, type OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsQueryParams, type OutboundCallingGetSiteLevelOutboundCallingCountriesAndRegionsResponse, type OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsPathParams, type OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsQueryParams, type OutboundCallingGetUserLevelOutboundCallingCountriesAndRegionsResponse, type OutboundCallingListAccountLevelOutboundCallingExceptionRulesQueryParams, type OutboundCallingListAccountLevelOutboundCallingExceptionRulesResponse, type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesPathParams, type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesQueryParams, type OutboundCallingListCommonAreaLevelOutboundCallingExceptionRulesResponse, type OutboundCallingListSiteLevelOutboundCallingExceptionRulesPathParams, type OutboundCallingListSiteLevelOutboundCallingExceptionRulesQueryParams, type OutboundCallingListSiteLevelOutboundCallingExceptionRulesResponse, type OutboundCallingListUserLevelOutboundCallingExceptionRulesPathParams, type OutboundCallingListUserLevelOutboundCallingExceptionRulesQueryParams, type OutboundCallingListUserLevelOutboundCallingExceptionRulesResponse, type OutboundCallingUpdateAccountLevelOutboundCallingCountriesOrRegionsRequestBody, type OutboundCallingUpdateAccountLevelOutboundCallingExceptionRulePathParams, type OutboundCallingUpdateAccountLevelOutboundCallingExceptionRuleRequestBody, type OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsPathParams, type OutboundCallingUpdateCommonAreaLevelOutboundCallingCountriesOrRegionsRequestBody, type OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRulePathParams, type OutboundCallingUpdateCommonAreaLevelOutboundCallingExceptionRuleRequestBody, type OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsPathParams, type OutboundCallingUpdateSiteLevelOutboundCallingCountriesOrRegionsRequestBody, type OutboundCallingUpdateSiteLevelOutboundCallingExceptionRulePathParams, type OutboundCallingUpdateSiteLevelOutboundCallingExceptionRuleRequestBody, type OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsPathParams, type OutboundCallingUpdateUserLevelOutboundCallingCountriesOrRegionsRequestBody, type OutboundCallingUpdateUserLevelOutboundCallingExceptionRulePathParams, type OutboundCallingUpdateUserLevelOutboundCallingExceptionRuleRequestBody, type PhoneAccountSettingsUpdatedEvent, type PhoneBlindTransferInitiatedEvent, type PhoneCallHistoryDeletedEvent, type PhoneCallLogDeletedEvent, type PhoneCallLogPermanentlyDeletedEvent, type PhoneCalleeAnsweredEvent, type PhoneCalleeCallHistoryCompletedEvent, type PhoneCalleeCallLogCompletedEvent, type PhoneCalleeEndedEvent, type PhoneCalleeHoldEvent, type PhoneCalleeMeetingInvitingEvent, type PhoneCalleeMissedEvent, type PhoneCalleeMuteEvent, type PhoneCalleeParkedEvent, type PhoneCalleeRejectedEvent, type PhoneCalleeRingingEvent, type PhoneCalleeUnholdEvent, type PhoneCalleeUnmuteEvent, type PhoneCallerCallHistoryCompletedEvent, type PhoneCallerCallLogCompletedEvent, type PhoneCallerConnectedEvent, type PhoneCallerEndedEvent, type PhoneCallerHoldEvent, type PhoneCallerMeetingInvitingEvent, type PhoneCallerMuteEvent, type PhoneCallerRingingEvent, type PhoneCallerUnholdEvent, type PhoneCallerUnmuteEvent, type PhoneConferenceStartedEvent, type PhoneDeviceRegistrationEvent, type PhoneDevicesAddDeviceRequestBody, type PhoneDevicesAddDeviceResponse, type PhoneDevicesAssignEntityToDevicePathParams, type PhoneDevicesAssignEntityToDeviceRequestBody, type PhoneDevicesDeleteDevicePathParams, type PhoneDevicesGetDeviceDetailsPathParams, type PhoneDevicesGetDeviceDetailsResponse, type PhoneDevicesListDevicesQueryParams, type PhoneDevicesListDevicesResponse, type PhoneDevicesRebootDeskPhonePathParams, type PhoneDevicesSyncDeskphonesRequestBody, type PhoneDevicesUnassignEntityFromDevicePathParams, type PhoneDevicesUpdateDevicePathParams, type PhoneDevicesUpdateDeviceRequestBody, type PhoneDevicesUpdateProvisionTemplateOfDevicePathParams, type PhoneDevicesUpdateProvisionTemplateOfDeviceRequestBody, type PhoneEmergencyAlertEvent, PhoneEndpoints, PhoneEventProcessor, type PhoneGenericDeviceProvisionEvent, type PhoneGroupSettingsUpdatedEvent, type PhoneNumbersAddBYOCPhoneNumbersRequestBody, type PhoneNumbersAddBYOCPhoneNumbersResponse, type PhoneNumbersAssignPhoneNumberToUserPathParams, type PhoneNumbersAssignPhoneNumberToUserRequestBody, type PhoneNumbersAssignPhoneNumberToUserResponse, type PhoneNumbersDeleteUnassignedPhoneNumbersQueryParams, type PhoneNumbersGetPhoneNumberPathParams, type PhoneNumbersGetPhoneNumberResponse, type PhoneNumbersListPhoneNumbersQueryParams, type PhoneNumbersListPhoneNumbersResponse, type PhoneNumbersUnassignPhoneNumberPathParams, type PhoneNumbersUpdatePhoneNumberPathParams, type PhoneNumbersUpdatePhoneNumberRequestBody, type PhoneNumbersUpdateSitesUnassignedPhoneNumbersPathParams, type PhoneNumbersUpdateSitesUnassignedPhoneNumbersRequestBody, PhoneOAuthClient, type PhoneOptions, type PhonePeeringNumberCnamUpdatedEvent, type PhonePeeringNumberEmergencyAddressUpdatedEvent, type PhonePlansListCallingPlansResponse, type PhonePlansListPlanInformationResponse, type PhoneRecordingCompletedEvent, type PhoneRecordingCompletedForAccessMemberEvent, type PhoneRecordingDeletedEvent, type PhoneRecordingFailedEvent, type PhoneRecordingPausedEvent, type PhoneRecordingPermanentlyDeletedEvent, type PhoneRecordingResumedEvent, type PhoneRecordingStartedEvent, type PhoneRecordingStoppedEvent, type PhoneRecordingTranscriptCompletedEvent, type PhoneRolesAddMembersToRolesPathParams, type PhoneRolesAddMembersToRolesRequestBody, type PhoneRolesDeleteMembersInRolePathParams, type PhoneRolesDeleteMembersInRoleQueryParams, type PhoneRolesDeletePhoneRolePathParams, type PhoneRolesDuplicatePhoneRoleRequestBody, type PhoneRolesDuplicatePhoneRoleResponse, type PhoneRolesGetRoleInformationPathParams, type PhoneRolesGetRoleInformationResponse, type PhoneRolesListMembersInRolePathParams, type PhoneRolesListMembersInRoleQueryParams, type PhoneRolesListMembersInRoleResponse, type PhoneRolesListPhoneRolesResponse, type PhoneRolesUpdatePhoneRolePathParams, type PhoneRolesUpdatePhoneRoleRequestBody, PhoneS2SAuthClient, type PhoneS2SAuthOptions, type PhoneSmsCampaignNumberOptInEvent, type PhoneSmsCampaignNumberOptOutEvent, type PhoneSmsReceivedEvent, type PhoneSmsSentEvent, type PhoneSmsSentFailedEvent, type PhoneTransferCallToVoicemailInitiatedEvent, type PhoneVoicemailDeletedEvent, type PhoneVoicemailPermanentlyDeletedEvent, type PhoneVoicemailReceivedEvent, type PhoneVoicemailReceivedForAccessMemberEvent, type PhoneVoicemailTranscriptCompletedEvent, type PrivateDirectoryAddMembersToPrivateDirectoryRequestBody, type PrivateDirectoryListPrivateDirectoryMembersQueryParams, type PrivateDirectoryListPrivateDirectoryMembersResponse, type PrivateDirectoryRemoveMemberFromPrivateDirectoryPathParams, type PrivateDirectoryRemoveMemberFromPrivateDirectoryQueryParams, type PrivateDirectoryUpdatePrivateDirectoryMemberPathParams, type PrivateDirectoryUpdatePrivateDirectoryMemberRequestBody, ProductClientConstructionError, type ProviderExchangeAddPeeringPhoneNumbersRequestBody, type ProviderExchangeAddPeeringPhoneNumbersResponse, type ProviderExchangeListCarrierPeeringPhoneNumbersQueryParams, type ProviderExchangeListCarrierPeeringPhoneNumbersResponse, type ProviderExchangeListPeeringPhoneNumbersQueryParams, type ProviderExchangeListPeeringPhoneNumbersResponse, type ProviderExchangeRemovePeeringPhoneNumbersQueryParams, type ProviderExchangeRemovePeeringPhoneNumbersResponse, type ProviderExchangeUpdatePeeringPhoneNumbersRequestBody, type ProviderExchangeUpdatePeeringPhoneNumbersResponse, type ProvisionTemplatesAddProvisionTemplateRequestBody, type ProvisionTemplatesAddProvisionTemplateResponse, type ProvisionTemplatesDeleteProvisionTemplatePathParams, type ProvisionTemplatesGetProvisionTemplatePathParams, type ProvisionTemplatesGetProvisionTemplateResponse, type ProvisionTemplatesListProvisionTemplatesQueryParams, type ProvisionTemplatesListProvisionTemplatesResponse, type ProvisionTemplatesUpdateProvisionTemplatePathParams, type ProvisionTemplatesUpdateProvisionTemplateRequestBody, type Receiver, ReceiverInconsistentStateError, type ReceiverInitOptions, ReceiverOAuthFlowError, type RecordingsDeleteCallRecordingPathParams, type RecordingsDownloadPhoneRecordingPathParams, type RecordingsDownloadPhoneRecordingTranscriptPathParams, type RecordingsGetCallRecordingsQueryParams, type RecordingsGetCallRecordingsResponse, type RecordingsGetRecordingByCallIDPathParams, type RecordingsGetRecordingByCallIDResponse, type RecordingsGetUsersRecordingsPathParams, type RecordingsGetUsersRecordingsQueryParams, type RecordingsGetUsersRecordingsResponse, type RecordingsUpdateAutoDeleteFieldPathParams, type RecordingsUpdateAutoDeleteFieldRequestBody, type RecordingsUpdateRecordingStatusPathParams, type RecordingsUpdateRecordingStatusRequestBody, type ReportsGetCallChargesUsageReportQueryParams, type ReportsGetCallChargesUsageReportResponse, type ReportsGetOperationLogsReportQueryParams, type ReportsGetOperationLogsReportResponse, type ReportsGetSMSMMSChargesUsageReportQueryParams, type ReportsGetSMSMMSChargesUsageReportResponse, type RoutingRulesAddDirectoryBackupRoutingRuleRequestBody, type RoutingRulesAddDirectoryBackupRoutingRuleResponse, type RoutingRulesDeleteDirectoryBackupRoutingRulePathParams, type RoutingRulesGetDirectoryBackupRoutingRulePathParams, type RoutingRulesGetDirectoryBackupRoutingRuleResponse, type RoutingRulesListDirectoryBackupRoutingRulesQueryParams, type RoutingRulesListDirectoryBackupRoutingRulesResponse, type RoutingRulesUpdateDirectoryBackupRoutingRulePathParams, type RoutingRulesUpdateDirectoryBackupRoutingRuleRequestBody, type S2SAuthToken, S2SRawResponseError, type SMSCampaignAssignPhoneNumberToSMSCampaignPathParams, type SMSCampaignAssignPhoneNumberToSMSCampaignRequestBody, type SMSCampaignAssignPhoneNumberToSMSCampaignResponse, type SMSCampaignGetSMSCampaignPathParams, type SMSCampaignGetSMSCampaignResponse, type SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams, type SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignQueryParams, type SMSCampaignListOptStatusesOfPhoneNumbersAssignedToSMSCampaignResponse, type SMSCampaignListSMSCampaignsQueryParams, type SMSCampaignListSMSCampaignsResponse, type SMSCampaignUnassignPhoneNumberPathParams, type SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignPathParams, type SMSCampaignUpdateOptStatusesOfPhoneNumbersAssignedToSMSCampaignRequestBody, type SMSGetAccountsSMSSessionsQueryParams, type SMSGetAccountsSMSSessionsResponse, type SMSGetSMSByMessageIDPathParams, type SMSGetSMSByMessageIDResponse, type SMSGetSMSSessionDetailsPathParams, type SMSGetSMSSessionDetailsQueryParams, type SMSGetSMSSessionDetailsResponse, type SMSGetUsersSMSSessionsPathParams, type SMSGetUsersSMSSessionsQueryParams, type SMSGetUsersSMSSessionsResponse, type SMSListUsersSMSSessionsInDescendingOrderPathParams, type SMSListUsersSMSSessionsInDescendingOrderQueryParams, type SMSListUsersSMSSessionsInDescendingOrderResponse, type SMSSyncSMSBySessionIDPathParams, type SMSSyncSMSBySessionIDQueryParams, type SMSSyncSMSBySessionIDResponse, type SettingTemplatesAddSettingTemplateRequestBody, type SettingTemplatesAddSettingTemplateResponse, type SettingTemplatesGetSettingTemplateDetailsPathParams, type SettingTemplatesGetSettingTemplateDetailsQueryParams, type SettingTemplatesGetSettingTemplateDetailsResponse, type SettingTemplatesListSettingTemplatesQueryParams, type SettingTemplatesListSettingTemplatesResponse, type SettingTemplatesUpdateSettingTemplatePathParams, type SettingTemplatesUpdateSettingTemplateRequestBody, type SettingsGetPhoneAccountSettingsResponse, type SettingsGetPortedNumberDetailsPathParams, type SettingsGetPortedNumberDetailsResponse, type SettingsListBYOCSIPTrunksQueryParams, type SettingsListBYOCSIPTrunksResponse, type SettingsListPortedNumbersQueryParams, type SettingsListPortedNumbersResponse, type SettingsListSIPGroupsQueryParams, type SettingsListSIPGroupsResponse, type SettingsUpdatePhoneAccountSettingsRequestBody, type SharedLineAppearanceListSharedLineAppearancesQueryParams, type SharedLineAppearanceListSharedLineAppearancesResponse, type SharedLineGroupAddMembersToSharedLineGroupPathParams, type SharedLineGroupAddMembersToSharedLineGroupRequestBody, type SharedLineGroupAddPolicySettingToSharedLineGroupPathParams, type SharedLineGroupAddPolicySettingToSharedLineGroupRequestBody, type SharedLineGroupAddPolicySettingToSharedLineGroupResponse, type SharedLineGroupAssignPhoneNumbersPathParams, type SharedLineGroupAssignPhoneNumbersRequestBody, type SharedLineGroupCreateSharedLineGroupRequestBody, type SharedLineGroupCreateSharedLineGroupResponse, type SharedLineGroupDeleteSLGPolicySettingPathParams, type SharedLineGroupDeleteSLGPolicySettingQueryParams, type SharedLineGroupDeleteSharedLineGroupPathParams, type SharedLineGroupGetSharedLineGroupPathParams, type SharedLineGroupGetSharedLineGroupPolicyPathParams, type SharedLineGroupGetSharedLineGroupPolicyResponse, type SharedLineGroupGetSharedLineGroupResponse, type SharedLineGroupListSharedLineGroupsQueryParams, type SharedLineGroupListSharedLineGroupsResponse, type SharedLineGroupUnassignAllPhoneNumbersPathParams, type SharedLineGroupUnassignMemberFromSharedLineGroupPathParams, type SharedLineGroupUnassignMembersFromSharedLineGroupPathParams, type SharedLineGroupUnassignPhoneNumberPathParams, type SharedLineGroupUpdateSLGPolicySettingPathParams, type SharedLineGroupUpdateSLGPolicySettingRequestBody, type SharedLineGroupUpdateSharedLineGroupPathParams, type SharedLineGroupUpdateSharedLineGroupPolicyPathParams, type SharedLineGroupUpdateSharedLineGroupPolicyRequestBody, type SharedLineGroupUpdateSharedLineGroupRequestBody, type SitesAddCustomizedOutboundCallerIDPhoneNumbersPathParams, type SitesAddCustomizedOutboundCallerIDPhoneNumbersRequestBody, type SitesAddSiteSettingPathParams, type SitesAddSiteSettingRequestBody, type SitesAddSiteSettingResponse, type SitesCreatePhoneSiteRequestBody, type SitesCreatePhoneSiteResponse, type SitesDeletePhoneSitePathParams, type SitesDeletePhoneSiteQueryParams, type SitesDeleteSiteSettingPathParams, type SitesDeleteSiteSettingQueryParams, type SitesGetPhoneSiteDetailsPathParams, type SitesGetPhoneSiteDetailsResponse, type SitesGetPhoneSiteSettingPathParams, type SitesGetPhoneSiteSettingResponse, type SitesListCustomizedOutboundCallerIDPhoneNumbersPathParams, type SitesListCustomizedOutboundCallerIDPhoneNumbersQueryParams, type SitesListCustomizedOutboundCallerIDPhoneNumbersResponse, type SitesListPhoneSitesQueryParams, type SitesListPhoneSitesResponse, type SitesRemoveCustomizedOutboundCallerIDPhoneNumbersPathParams, type SitesRemoveCustomizedOutboundCallerIDPhoneNumbersQueryParams, type SitesUpdatePhoneSiteDetailsPathParams, type SitesUpdatePhoneSiteDetailsRequestBody, type SitesUpdateSiteSettingPathParams, type SitesUpdateSiteSettingRequestBody, type StateStore, StatusCode, type TokenStore, type UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDPathParams, type UsersAddPhoneNumbersForUsersCustomizedOutboundCallerIDRequestBody, type UsersAddUsersSharedAccessSettingPathParams, type UsersAddUsersSharedAccessSettingRequestBody, type UsersAddUsersSharedAccessSettingResponse, type UsersAssignCallingPlanToUserPathParams, type UsersAssignCallingPlanToUserRequestBody, type UsersBatchAddUsersRequestBody, type UsersBatchAddUsersResponse, type UsersDeleteUsersSharedAccessSettingPathParams, type UsersDeleteUsersSharedAccessSettingQueryParams, type UsersGetUsersProfilePathParams, type UsersGetUsersProfileResponse, type UsersGetUsersProfileSettingsPathParams, type UsersGetUsersProfileSettingsResponse, type UsersListPhoneUsersQueryParams, type UsersListPhoneUsersResponse, type UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDPathParams, type UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDQueryParams, type UsersListUsersPhoneNumbersForCustomizedOutboundCallerIDResponse, type UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersPathParams, type UsersRemoveUsersCustomizedOutboundCallerIDPhoneNumbersQueryParams, type UsersUnassignUsersCallingPlanPathParams, type UsersUnassignUsersCallingPlanQueryParams, type UsersUpdateMultipleUsersPropertiesInBatchRequestBody, type UsersUpdateUsersCallingPlanPathParams, type UsersUpdateUsersCallingPlanRequestBody, type UsersUpdateUsersProfilePathParams, type UsersUpdateUsersProfileRequestBody, type UsersUpdateUsersProfileSettingsPathParams, type UsersUpdateUsersProfileSettingsRequestBody, type UsersUpdateUsersSharedAccessSettingPathParams, type UsersUpdateUsersSharedAccessSettingRequestBody, type VoicemailsDownloadPhoneVoicemailPathParams, type VoicemailsGetAccountVoicemailsQueryParams, type VoicemailsGetAccountVoicemailsResponse, type VoicemailsGetUserVoicemailDetailsFromCallLogPathParams, type VoicemailsGetUserVoicemailDetailsFromCallLogResponse, type VoicemailsGetUsersVoicemailsPathParams, type VoicemailsGetUsersVoicemailsQueryParams, type VoicemailsGetUsersVoicemailsResponse, type VoicemailsGetVoicemailDetailsPathParams, type VoicemailsGetVoicemailDetailsResponse, type VoicemailsUpdateVoicemailReadStatusPathParams, type VoicemailsUpdateVoicemailReadStatusQueryParams, type ZoomRoomsAddZoomRoomToZoomPhoneRequestBody, type ZoomRoomsAssignCallingPlansToZoomRoomPathParams, type ZoomRoomsAssignCallingPlansToZoomRoomRequestBody, type ZoomRoomsAssignPhoneNumbersToZoomRoomPathParams, type ZoomRoomsAssignPhoneNumbersToZoomRoomRequestBody, type ZoomRoomsGetZoomRoomUnderZoomPhoneLicensePathParams, type ZoomRoomsGetZoomRoomUnderZoomPhoneLicenseResponse, type ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseQueryParams, type ZoomRoomsListZoomRoomsUnderZoomPhoneLicenseResponse, type ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentQueryParams, type ZoomRoomsListZoomRoomsWithoutZoomPhoneAssignmentResponse, type ZoomRoomsRemoveCallingPlanFromZoomRoomPathParams, type ZoomRoomsRemoveCallingPlanFromZoomRoomQueryParams, type ZoomRoomsRemovePhoneNumberFromZoomRoomPathParams, type ZoomRoomsRemoveZoomRoomFromZPAccountPathParams, type ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicensePathParams, type ZoomRoomsUpdateZoomRoomUnderZoomPhoneLicenseRequestBody, isCoreError, isStateStore };
