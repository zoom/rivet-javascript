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

type AccountsGetLockedSettingsPathParams = {
    accountId: string;
};
type AccountsGetLockedSettingsQueryParams = {
    option?: string;
    custom_query_fields?: string;
};
type AccountsGetLockedSettingsResponse = {
    audio_conferencing?: {
        toll_free_and_fee_based_toll_call?: boolean;
    };
    chat?: {
        share_files?: boolean;
        chat_emojis?: boolean;
        record_voice_messages?: boolean;
        record_video_messages?: boolean;
        screen_capture?: boolean;
        share_links_in_chat?: boolean;
        schedule_meetings_in_chat?: boolean;
        set_retention_period_in_cloud?: boolean;
        set_retention_period_in_local?: boolean;
        allow_users_to_add_contacts?: boolean;
        allow_users_to_chat_with_others?: boolean;
        chat_etiquette_tool?: boolean;
        send_data_to_third_party_archiving_service?: boolean;
        translate_messages?: boolean;
        search_and_send_animated_gif_images?: boolean;
    };
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        schedule_for_reminder?: boolean;
    };
    in_meeting?: {
        alert_guest_join?: boolean;
        allow_users_to_delete_messages_in_meeting_chat?: boolean;
        allow_live_streaming?: boolean;
        allow_show_zoom_windows?: boolean;
        annotation?: boolean;
        anonymous_question_answer?: boolean;
        attendee_on_hold?: boolean;
        attention_mode_focus_mode?: boolean;
        auto_answer?: boolean;
        auto_generated_captions?: boolean;
        auto_saving_chat?: boolean;
        breakout_room?: boolean;
        chat?: boolean;
        meeting_question_answer?: boolean;
        closed_caption?: boolean;
        co_host?: boolean;
        custom_data_center_regions?: boolean;
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
        dscp_marking?: boolean;
        e2e_encryption?: boolean;
        entry_exit_chime?: string;
        far_end_camera_control?: boolean;
        feedback?: boolean;
        file_transfer?: boolean;
        full_transcript?: boolean;
        group_hd?: boolean;
        webinar_group_hd?: boolean;
        language_interpretation?: boolean;
        sign_language_interpretation?: boolean;
        manual_captions?: boolean;
        meeting_reactions?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        original_audio?: boolean;
        polling?: boolean;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        remote_control?: boolean;
        non_verbal_feedback?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        save_caption?: boolean;
        save_captions?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        stereo_audio?: boolean;
        use_html_format_email?: boolean;
        virtual_background?: boolean;
        webinar_chat?: boolean;
        webinar_live_streaming?: boolean;
        webinar_polling?: boolean;
        webinar_question_answer?: boolean;
        webinar_survey?: boolean;
        whiteboard?: boolean;
    };
    other_options?: {
        blur_snapshot?: boolean;
        webinar_registration_options?: boolean;
    };
    recording?: {
        account_user_access_recording?: boolean;
        auto_delete_cmr?: boolean;
        auto_recording?: boolean;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        host_delete_cloud_recording?: boolean;
        ip_address_access_control?: boolean;
        local_recording?: boolean;
        prevent_host_access_recording?: boolean;
        recording_authentication?: boolean;
        archive?: boolean;
    };
    schedule_meeting?: {
        audio_type?: boolean;
        embed_password_in_join_link?: boolean;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        enforce_login_with_domains?: boolean;
        host_video?: boolean;
        join_before_host?: boolean;
        meeting_authentication?: boolean;
        not_store_meeting_topic?: boolean;
        always_display_zoom_webinar_as_topic?: boolean;
        participant_video?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        use_pmi_for_instant_meetings?: boolean;
        use_pmi_for_scheduled_meetings?: boolean;
        continuous_meeting_chat?: boolean;
    };
    telephony?: {
        telephony_regions?: boolean;
        third_party_audio?: boolean;
    };
    tsp?: {
        call_out?: boolean;
        show_international_numbers_link?: boolean;
    };
} | {
    meeting_security?: {
        approved_or_denied_countries_or_regions?: boolean;
        auto_security?: boolean;
        block_user_domain?: boolean;
        chat_etiquette_tool?: boolean;
        embed_password_in_join_link?: boolean;
        encryption_type?: boolean;
        end_to_end_encrypted_meetings?: boolean;
        meeting_password?: boolean;
        only_authenticated_can_join_from_webclient?: boolean;
        phone_password?: boolean;
        pmi_password?: boolean;
        waiting_room?: boolean;
        webinar_password?: boolean;
    };
};
type AccountsUpdateLockedSettingsPathParams = {
    accountId: string;
};
type AccountsUpdateLockedSettingsRequestBody = {
    audio_conferencing?: {
        toll_free_and_fee_based_toll_call?: boolean;
    };
    chat?: {
        share_files?: boolean;
        chat_emojis?: boolean;
        record_voice_messages?: boolean;
        record_video_messages?: boolean;
        screen_capture?: boolean;
        share_links_in_chat?: boolean;
        schedule_meetings_in_chat?: boolean;
        set_retention_period_in_cloud?: boolean;
        set_retention_period_in_local?: boolean;
        allow_users_to_add_contacts?: boolean;
        allow_users_to_chat_with_others?: boolean;
        chat_etiquette_tool?: boolean;
        send_data_to_third_party_archiving_service?: boolean;
        translate_messages?: boolean;
        search_and_send_animated_gif_images?: boolean;
    };
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        schedule_for_reminder?: boolean;
    };
    in_meeting?: {
        alert_guest_join?: boolean;
        allow_users_to_delete_messages_in_meeting_chat?: boolean;
        allow_live_streaming?: boolean;
        allow_show_zoom_windows?: boolean;
        annotation?: boolean;
        anonymous_question_answer?: boolean;
        attendee_on_hold?: boolean;
        attention_mode_focus_mode?: boolean;
        auto_answer?: boolean;
        auto_generated_captions?: boolean;
        auto_saving_chat?: boolean;
        breakout_room?: boolean;
        chat?: boolean;
        meeting_question_answer?: boolean;
        closed_caption?: boolean;
        co_host?: boolean;
        custom_data_center_regions?: boolean;
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
        dscp_marking?: boolean;
        e2e_encryption?: boolean;
        entry_exit_chime?: string;
        far_end_camera_control?: boolean;
        feedback?: boolean;
        file_transfer?: boolean;
        full_transcript?: boolean;
        group_hd?: boolean;
        webinar_group_hd?: boolean;
        language_interpretation?: boolean;
        sign_language_interpretation?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        original_audio?: boolean;
        polling?: boolean;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        remote_control?: boolean;
        non_verbal_feedback?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        save_caption?: boolean;
        save_captions?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        stereo_audio?: boolean;
        use_html_format_email?: boolean;
        virtual_background?: boolean;
        webinar_chat?: boolean;
        webinar_live_streaming?: boolean;
        webinar_polling?: boolean;
        webinar_question_answer?: boolean;
        webinar_survey?: boolean;
        whiteboard?: boolean;
    };
    other_options?: {
        blur_snapshot?: boolean;
        webinar_registration_options?: boolean;
    };
    recording?: {
        account_user_access_recording?: boolean;
        auto_delete_cmr?: boolean;
        auto_recording?: boolean;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        host_delete_cloud_recording?: boolean;
        ip_address_access_control?: boolean;
        local_recording?: boolean;
        prevent_host_access_recording?: boolean;
        recording_authentication?: boolean;
        archive?: boolean;
    };
    schedule_meeting?: {
        audio_type?: boolean;
        embed_password_in_join_link?: boolean;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        enforce_login_with_domains?: boolean;
        host_video?: boolean;
        join_before_host?: boolean;
        meeting_authentication?: boolean;
        not_store_meeting_topic?: boolean;
        always_display_zoom_webinar_as_topic?: boolean;
        participant_video?: boolean;
        personal_meeting?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        use_pmi_for_instant_meetings?: boolean;
        use_pmi_for_scheduled_meetings?: boolean;
        continuous_meeting_chat?: boolean;
    };
    telephony?: {
        telephony_regions?: boolean;
        third_party_audio?: boolean;
    };
    tsp?: {
        call_out?: boolean;
        show_international_numbers_link?: boolean;
    };
} | {
    meeting_security?: {
        approved_or_denied_countries_or_regions?: boolean;
        auto_security?: boolean;
        block_user_domain?: boolean;
        chat_etiquette_tool?: boolean;
        embed_password_in_join_link?: boolean;
        encryption_type?: string;
        end_to_end_encrypted_meetings?: boolean;
        meeting_password?: boolean;
        only_authenticated_can_join_from_webclient?: boolean;
        phone_password?: boolean;
        pmi_password?: boolean;
        waiting_room?: boolean;
        webinar_password?: boolean;
    };
};
type AccountsGetAccountsManagedDomainsPathParams = {
    accountId: string;
};
type AccountsGetAccountsManagedDomainsResponse = {
    domains?: {
        domain?: string;
        status?: string;
    }[];
    total_records?: number;
};
type AccountsUpdateAccountOwnerPathParams = {
    accountId: string;
};
type AccountsUpdateAccountOwnerRequestBody = {
    email: string;
};
type AccountsGetAccountSettingsPathParams = {
    accountId: string;
};
type AccountsGetAccountSettingsQueryParams = {
    option?: string;
    custom_query_fields?: string;
};
type AccountsGetAccountSettingsResponse = {
    security?: {
        admin_change_name_pic?: boolean;
        admin_change_user_info?: boolean;
        user_modifiable_info_by_admin?: string[];
        signin_with_sso?: {
            enable?: boolean;
            require_sso_for_domains?: boolean;
            domains?: string[];
            sso_bypass_users?: {
                id?: string;
                email?: string;
            }[];
        };
        hide_billing_info?: boolean;
        import_photos_from_devices?: boolean;
        password_requirement?: {
            consecutive_characters_length?: number;
            have_special_character?: boolean;
            minimum_password_length?: number;
            weak_enhance_detection?: boolean;
        };
        sign_again_period_for_inactivity_on_client?: number;
        sign_again_period_for_inactivity_on_web?: number;
        sign_in_with_two_factor_auth?: string;
        sign_in_with_two_factor_auth_groups?: string[];
        sign_in_with_two_factor_auth_roles?: string[];
    };
    audio_conferencing?: {
        toll_free_and_fee_based_toll_call?: {
            allow_webinar_attendees_dial?: boolean;
            enable?: boolean;
            numbers?: {
                code?: string;
                country_code?: string;
                country_name?: string;
                display_number?: string;
                number?: string;
            }[];
        };
    };
    chat?: {
        allow_bots_chat?: boolean;
        share_files?: {
            enable?: boolean;
            share_option?: string;
            restrictions?: {
                only_allow_specific_file_types?: boolean;
                file_type_restrictions?: string[];
                file_type_restrictions_for_external?: string[];
                maximum_file_size?: boolean;
                file_size_restrictions?: number;
                file_size_restrictions_for_external?: number;
            };
        };
        chat_emojis?: {
            enable?: boolean;
            emojis_option?: string;
        };
        record_voice_messages?: boolean;
        record_video_messages?: boolean;
        screen_capture?: boolean;
        create_public_channels?: boolean;
        create_private_channels?: boolean;
        share_links_in_chat?: boolean;
        schedule_meetings_in_chat?: boolean;
        set_retention_period_in_cloud?: {
            enable?: boolean;
            retention_period_of_direct_messages_and_group_conversation?: string;
            retention_period_of_channels?: string;
        };
        set_retention_period_in_local?: {
            enable?: boolean;
            retention_period_of_direct_messages_and_group_conversation?: string;
            retention_period_of_channels?: string;
        };
        allow_users_to_add_contacts?: {
            enable?: boolean;
            selected_option?: number;
            user_email_addresses?: string;
        };
        allow_users_to_chat_with_others?: {
            enable?: boolean;
            selected_option?: number;
            user_email_addresses?: string;
        };
        chat_etiquette_tool?: {
            enable?: boolean;
            policies?: {
                description?: string;
                id?: string;
                is_locked?: boolean;
                keywords?: string[];
                name?: string;
                regular_expression?: string;
                status?: string;
                trigger_action?: number;
            }[];
            policy_max_count?: number;
        };
        send_data_to_third_party_archiving_service?: {
            enable?: boolean;
            type?: string;
            smtp_delivery_address?: string;
            user_name?: string;
            passcode?: string;
            authorized_channel_token?: string;
        };
        apply_local_storage_to_personal_channel?: {
            enable?: boolean;
            retention_period?: string;
        };
        translate_messages?: boolean;
        search_and_send_animated_gif_images?: {
            enable?: boolean;
            giphy_content_rating?: number;
        };
        external_user_control?: {
            enable?: boolean;
            selected_option?: number;
            external_account?: boolean;
        };
        external_invite_approve?: {
            enable?: boolean;
            selected_option?: number;
            channel_id?: string;
            external_account?: boolean;
        };
        external_member_join?: {
            enable?: boolean;
            external_account?: boolean;
        };
        external_join_approve?: {
            enable?: boolean;
            selected_option?: number;
            channel_id?: string;
            external_account?: boolean;
        };
    };
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        low_host_count_reminder?: boolean;
        recording_available_reminder_alternative_hosts?: boolean;
        recording_available_reminder_schedulers?: boolean;
        schedule_for_reminder?: boolean;
    };
    feature?: {
        meeting_capacity?: number;
    };
    in_meeting?: {
        auto_generated_translation?: {
            language_item_pairList?: {
                trans_lang_config?: {
                    speak_language?: {
                        name?: string;
                        code?: string;
                    };
                    translate_to?: {
                        all?: boolean;
                        language_config?: {
                            name?: string;
                            code?: string;
                        }[];
                    };
                }[];
                all?: boolean;
            };
            enable?: boolean;
        };
        alert_guest_join?: boolean;
        allow_host_to_enable_focus_mode?: boolean;
        allow_live_streaming?: boolean;
        allow_participants_chat_with?: number;
        allow_participants_to_rename?: boolean;
        allow_show_zoom_windows?: boolean;
        allow_users_save_chats?: number;
        annotation?: boolean;
        anonymous_question_answer?: boolean;
        attendee_on_hold?: boolean;
        attention_mode_focus_mode?: boolean;
        auto_answer?: boolean;
        auto_saving_chat?: boolean;
        breakout_room?: boolean;
        breakout_room_schedule?: boolean;
        chat?: boolean;
        meeting_question_answer?: boolean;
        closed_caption?: boolean;
        closed_captioning?: {
            auto_transcribing?: boolean;
            enable?: boolean;
            save_caption?: boolean;
            third_party_captioning_service?: boolean;
            view_full_transcript?: boolean;
        };
        co_host?: boolean;
        custom_data_center_regions?: boolean;
        custom_live_streaming_service?: boolean;
        custom_service_instructions?: string;
        meeting_data_transit_and_residency_method?: string;
        data_center_regions?: string[];
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
        dscp_audio?: number;
        dscp_marking?: boolean;
        dscp_video?: number;
        dscp_dual?: boolean;
        e2e_encryption?: boolean;
        entry_exit_chime?: string;
        far_end_camera_control?: boolean;
        feedback?: boolean;
        file_transfer?: boolean;
        group_hd?: boolean;
        webinar_group_hd?: boolean;
        join_from_desktop?: boolean;
        join_from_mobile?: boolean;
        language_interpretation?: {
            custom_languages?: string[];
            enable?: boolean;
            enable_language_interpretation_by_default?: boolean;
            allow_participants_to_speak_in_listening_channel?: boolean;
            allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
            languages?: string[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            enable_sign_language_interpretation_by_default?: boolean;
            languages?: string[];
            custom_languages?: string[];
        };
        live_streaming_facebook?: boolean;
        live_streaming_youtube?: boolean;
        manual_captioning?: {
            allow_to_type?: boolean;
            auto_generated_captions?: boolean;
            full_transcript?: boolean;
            manual_captions?: boolean;
            save_captions?: boolean;
            third_party_captioning_service?: boolean;
        };
        meeting_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            allow_host_to_upload_image?: boolean;
            require_answers_to_be_anonymous?: boolean;
            enable?: boolean;
        };
        meeting_reactions?: boolean;
        meeting_reactions_emojis?: string;
        allow_host_panelists_to_use_audible_clap?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        original_audio?: boolean;
        p2p_connetion?: boolean;
        p2p_ports?: boolean;
        polling?: boolean;
        ports_range?: string;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        record_play_own_voice?: boolean;
        remote_control?: boolean;
        non_verbal_feedback?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        stereo_audio?: boolean;
        unchecked_data_center_regions?: string[];
        use_html_format_email?: boolean;
        virtual_background?: boolean;
        virtual_background_settings?: {
            allow_upload_custom?: boolean;
            allow_videos?: boolean;
            enable?: boolean;
            files?: {
                id?: string;
                is_default?: boolean;
                name?: string;
                size?: number;
                type?: string;
            }[];
        };
        watermark?: boolean;
        webinar_chat?: {
            allow_attendees_chat_with?: number;
            allow_auto_save_local_chat_file?: boolean;
            allow_panelists_chat_with?: number;
            allow_panelists_send_direct_message?: boolean;
            allow_users_save_chats?: number;
            allow_users_to_delete_messages_in_meeting_chat?: boolean;
            default_attendees_chat_with?: number;
            enable?: boolean;
        };
        webinar_live_streaming?: {
            custom_service_instructions?: string;
            enable?: boolean;
            live_streaming_reminder?: boolean;
            live_streaming_service?: string[];
        };
        webinar_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            require_answers_to_be_anonymous?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            allow_host_to_upload_image?: boolean;
            enable?: boolean;
        };
        webinar_question_answer?: boolean;
        webinar_survey?: boolean;
        whiteboard?: boolean;
        who_can_share_screen?: string;
        who_can_share_screen_when_someone_is_sharing?: string;
        participants_share_simultaneously?: string;
        workplace_by_facebook?: boolean;
        transfer_meetings_between_devices?: boolean;
    };
    integration?: {
        box?: boolean;
        dropbox?: boolean;
        google_calendar?: boolean;
        google_drive?: boolean;
        kubi?: boolean;
        microsoft_one_drive?: boolean;
    };
    other_options?: {
        allow_auto_active_users?: boolean;
        allow_users_contact_support_via_chat?: boolean;
        allow_users_enter_and_share_pronouns?: boolean;
        blur_snapshot?: boolean;
        display_meetings_scheduled_for_others?: boolean;
        meeting_qos_and_mos?: number;
        show_one_user_meeting_on_dashboard?: boolean;
        use_cdn?: string;
        webinar_registration_options?: {
            allow_host_to_enable_join_info?: boolean;
            allow_host_to_enable_social_share_buttons?: boolean;
            enable_custom_questions?: boolean;
        };
        email_in_attendee_report_for_meeting?: boolean;
    };
    profile?: {
        recording_storage_location?: {
            allowed_values?: string[];
            value?: string;
        };
    };
    recording?: {
        account_user_access_recording?: boolean;
        allow_recovery_deleted_cloud_recordings?: boolean;
        archive?: {
            enable?: boolean;
            settings?: {
                audio_file?: boolean;
                cc_transcript_file?: boolean;
                chat_file?: boolean;
                chat_with_sender_email?: boolean;
                video_file?: boolean;
                chat_with_direct_message?: boolean;
                archive_retention?: number;
                action_when_archive_failed?: number;
                notification_when_archiving_starts?: string;
                play_voice_prompt_when_archiving_starts?: string;
            };
            type?: number;
        };
        auto_delete_cmr?: boolean;
        auto_delete_cmr_days?: number;
        auto_recording?: string;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        cloud_recording_download_host?: boolean;
        display_participant_name?: boolean;
        host_delete_cloud_recording?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        optimize_recording_for_3rd_party_video_editor?: boolean;
        prevent_host_access_recording?: boolean;
        record_audio_file?: boolean;
        record_audio_file_each_participant?: boolean;
        record_files_separately?: {
            active_speaker?: boolean;
            gallery_view?: boolean;
            shared_screen?: boolean;
        };
        record_gallery_view?: boolean;
        record_speaker_view?: boolean;
        recording_audio_transcript?: boolean;
        recording_disclaimer?: boolean;
        recording_highlight?: boolean;
        smart_recording?: {
            create_recording_highlights?: boolean;
            create_smart_chapters?: boolean;
            create_next_steps?: boolean;
        };
        recording_password_requirement?: {
            have_letter?: boolean;
            have_number?: boolean;
            have_special_character?: boolean;
            length?: number;
            only_allow_numeric?: boolean;
        };
        recording_thumbnails?: boolean;
        required_password_for_existing_cloud_recordings?: boolean;
        required_password_for_shared_cloud_recordings?: boolean;
        save_chat_text?: boolean;
        save_close_caption?: boolean;
        save_panelist_chat?: boolean;
        save_poll_results?: boolean;
        show_timestamp?: boolean;
    };
    schedule_meeting?: {
        audio_type?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        enforce_login_with_domains?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
        enable_dedicated_group_chat?: boolean;
        jbh_time?: number;
        join_before_host?: boolean;
        meeting_password_requirement?: {
            consecutive_characters_length?: number;
            have_letter?: boolean;
            have_number?: boolean;
            have_special_character?: boolean;
            have_upper_and_lower_characters?: boolean;
            length?: number;
            only_allow_numeric?: boolean;
            weak_enhance_detection?: boolean;
        };
        not_store_meeting_topic?: boolean;
        participant_video?: boolean;
        allow_host_to_disable_participant_video?: boolean;
        personal_meeting?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: string;
        require_password_for_scheduled_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        use_pmi_for_instant_meetings?: boolean;
        use_pmi_for_scheduled_meetings?: boolean;
        always_display_zoom_meeting_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_meetings?: boolean;
        };
        hide_meeting_description?: {
            enable?: boolean;
            hide_description_for_scheduled_meetings?: boolean;
        };
        always_display_zoom_webinar_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_webinars?: boolean;
        };
        hide_webinar_description?: {
            enable?: boolean;
            hide_description_for_scheduled_webinars?: boolean;
        };
        meeting_template?: {
            enable?: boolean;
            templates?: {
                id?: string;
                name?: string;
                enable?: boolean;
            }[];
        };
        continuous_meeting_chat?: {
            enable?: boolean;
            can_add_external_users?: boolean;
            auto_add_invited_external_users?: boolean;
        };
    };
    telephony?: {
        audio_conference_info?: string;
        telephony_regions?: {
            allowed_values?: string[];
            selection_values?: string;
        };
        third_party_audio?: boolean;
    };
    tsp?: {
        call_out?: boolean;
        call_out_countries?: string[];
        display_toll_free_numbers?: boolean;
        show_international_numbers_link?: boolean;
    };
    zoom_rooms?: {
        auto_start_stop_scheduled_meetings?: boolean;
        cmr_for_instant_meeting?: boolean;
        force_private_meeting?: boolean;
        hide_host_information?: boolean;
        list_meetings_with_calendar?: boolean;
        start_airplay_manually?: boolean;
        ultrasonic?: boolean;
        upcoming_meeting_alert?: boolean;
        weekly_system_restart?: boolean;
        zr_post_meeting_feedback?: boolean;
    };
} | ({
    allow_authentication_exception?: boolean;
    authentication_options?: {
        default_option?: boolean;
        domains?: string;
        id?: string;
        name?: string;
        type?: string;
        visible?: boolean;
    }[];
    meeting_authentication?: boolean;
} | {
    authentication_options?: {
        default_option?: boolean;
        domains?: string;
        id?: string;
        name?: string;
        type?: string;
        visible?: boolean;
    }[];
    recording_authentication?: boolean;
}) | {
    meeting_security?: {
        auto_security?: boolean;
        block_user_domain?: boolean;
        block_user_domain_list?: string[];
        chat_etiquette_tool?: {
            enable?: boolean;
            policies?: {
                description?: string;
                id?: string;
                is_locked?: boolean;
                keywords?: string[];
                name?: string;
                regular_expression?: string;
                status?: string;
                trigger_action?: number;
            }[];
            policy_max_count?: number;
        };
        embed_password_in_join_link?: boolean;
        encryption_type?: string;
        end_to_end_encrypted_meetings?: boolean;
        meeting_password?: boolean;
        meeting_password_requirement?: {
            consecutive_characters_length?: number;
            have_letter?: boolean;
            have_number?: boolean;
            have_special_character?: boolean;
            have_upper_and_lower_characters?: boolean;
            length?: number;
            only_allow_numeric?: boolean;
            weak_enhance_detection?: boolean;
        };
        only_authenticated_can_join_from_webclient?: boolean;
        phone_password?: boolean;
        pmi_password?: boolean;
        require_password_for_scheduled_meeting?: boolean;
        require_password_for_scheduled_webinar?: boolean;
        waiting_room?: boolean;
        waiting_room_settings?: {
            participants_to_place_in_waiting_room?: number;
            users_who_can_admit_participants_from_waiting_room?: number;
            whitelisted_domains_for_waiting_room?: string;
        };
        webinar_password?: boolean;
        waiting_room_options?: {
            enable?: boolean;
            locked?: boolean;
            admit_type?: number;
            internal_user_auto_admit?: number;
            admit_domain_allowlist?: string;
            who_can_admit_participants?: number;
            sort_order_of_people?: number;
            more_options?: {
                user_invited_by_host_can_bypass_waiting_room?: boolean;
                move_participants_to_waiting_room_when_host_dropped?: boolean;
                allow_participants_to_reply_to_host?: boolean;
            };
        };
    };
} | {
    in_meeting?: {
        custom_data_center_regions?: boolean;
        data_center_regions?: string[];
        unchecked_data_center_regions?: string[];
    };
    in_session?: {
        custom_data_center_regions?: boolean;
        data_center_regions?: string[];
        unchecked_data_center_regions?: string[];
        p2p_connetion?: boolean;
        p2p_ports?: boolean;
        ports_range?: string;
        dscp_audio?: number;
        dscp_marking?: boolean;
        dscp_video?: number;
        dscp_dual?: boolean;
        subsession?: boolean;
    };
    session_security?: {
        approved_or_denied_countries_or_regions?: {
            approved_list?: string[];
            denied_list?: string[];
            enable?: boolean;
            method?: string;
        };
    };
    recording?: {
        cloud_recording?: boolean;
        record_speaker_view?: boolean;
        record_gallery_view?: boolean;
        record_audio_file?: boolean;
        save_chat_text?: boolean;
        show_timestamp?: boolean;
        recording_audio_transcript?: boolean;
        cloud_recording_download?: boolean;
        auto_delete_cmr?: boolean;
        auto_delete_cmr_days?: number;
    };
};
type AccountsUpdateAccountSettingsPathParams = {
    accountId: string;
};
type AccountsUpdateAccountSettingsQueryParams = {
    option?: string;
};
type AccountsUpdateAccountSettingsRequestBody = {
    security?: {
        admin_change_name_pic?: boolean;
        admin_change_user_info?: boolean;
        user_modifiable_info_by_admin?: string[];
        signin_with_sso?: {
            enable?: boolean;
            require_sso_for_domains?: boolean;
            domains?: string[];
            sso_bypass_user_ids?: string[];
            operation?: string;
        };
        hide_billing_info?: boolean;
        import_photos_from_devices?: boolean;
        password_requirement?: {
            consecutive_characters_length?: number;
            have_special_character?: boolean;
            minimum_password_length?: number;
            weak_enhance_detection?: boolean;
        };
        sign_again_period_for_inactivity_on_client?: number;
        sign_again_period_for_inactivity_on_web?: number;
        sign_in_with_two_factor_auth?: string;
        sign_in_with_two_factor_auth_groups?: string[];
        sign_in_with_two_factor_auth_roles?: string[];
    };
    audio_conferencing?: {
        toll_free_and_fee_based_toll_call?: {
            allow_webinar_attendees_dial?: boolean;
            enable?: boolean;
            numbers?: {
                code?: string;
                country_code?: string;
                country_name?: string;
                display_number?: string;
                number?: string;
            }[];
        };
    };
    chat?: {
        allow_bots_chat?: boolean;
        share_files?: {
            enable?: boolean;
            share_option?: string;
            restrictions?: {
                only_allow_specific_file_types?: boolean;
                file_type_restrictions?: string[];
                file_type_restrictions_for_external?: string[];
                maximum_file_size?: boolean;
                file_size_restrictions?: number;
                file_size_restrictions_for_external?: number;
            };
        };
        chat_emojis?: {
            enable?: boolean;
            emojis_option?: string;
        };
        record_voice_messages?: boolean;
        record_video_messages?: boolean;
        screen_capture?: boolean;
        create_public_channels?: boolean;
        create_private_channels?: boolean;
        share_links_in_chat?: boolean;
        schedule_meetings_in_chat?: boolean;
        set_retention_period_in_cloud?: {
            enable?: boolean;
            retention_period_of_direct_messages_and_group_conversation?: string;
            retention_period_of_channels?: string;
        };
        set_retention_period_in_local?: {
            enable?: boolean;
            retention_period_of_direct_messages_and_group_conversation?: string;
            retention_period_of_channels?: string;
        };
        allow_users_to_add_contacts?: {
            enable?: boolean;
            selected_option?: number;
            user_email_addresses?: string;
        };
        allow_users_to_chat_with_others?: {
            enable?: boolean;
            selected_option?: number;
            user_email_addresses?: string;
        };
        chat_etiquette_tool?: {
            enable?: boolean;
            operate?: string;
            policies?: {
                description?: string;
                id?: string;
                is_locked?: boolean;
                keywords?: string[];
                name?: string;
                regular_expression?: string;
                status?: string;
                trigger_action?: number;
            }[];
        };
        send_data_to_third_party_archiving_service?: {
            enable?: boolean;
            type?: string;
            smtp_delivery_address?: string;
            user_name?: string;
            passcode?: string;
            authorized_channel_token?: string;
        };
        apply_local_storage_to_personal_channel?: {
            enable?: boolean;
            retention_period?: string;
        };
        translate_messages?: boolean;
        search_and_send_animated_gif_images?: {
            enable?: boolean;
            giphy_content_rating?: number;
        };
    };
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        low_host_count_reminder?: boolean;
        recording_available_reminder_alternative_hosts?: boolean;
        recording_available_reminder_schedulers?: boolean;
        schedule_for_reminder?: boolean;
    };
    feature?: {
        meeting_capacity?: number;
    };
    in_meeting?: {
        alert_guest_join?: boolean;
        allow_host_to_enable_focus_mode?: boolean;
        allow_live_streaming?: boolean;
        allow_users_to_delete_messages_in_meeting_chat?: boolean;
        allow_participants_chat_with?: number;
        allow_participants_to_rename?: boolean;
        allow_show_zoom_windows?: boolean;
        allow_users_save_chats?: number;
        annotation?: boolean;
        anonymous_question_answer?: boolean;
        attendee_on_hold?: boolean;
        attention_mode_focus_mode?: boolean;
        auto_answer?: boolean;
        auto_saving_chat?: boolean;
        breakout_room?: boolean;
        breakout_room_schedule?: boolean;
        chat?: boolean;
        meeting_question_answer?: boolean;
        closed_caption?: boolean;
        closed_captioning?: {
            auto_transcribing?: boolean;
            enable?: boolean;
            save_caption?: boolean;
            third_party_captioning_service?: boolean;
            view_full_transcript?: boolean;
        };
        co_host?: boolean;
        custom_data_center_regions?: boolean;
        custom_live_streaming_service?: boolean;
        custom_service_instructions?: string;
        meeting_data_transit_and_residency_method?: string;
        data_center_regions?: string[];
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
        dscp_audio?: number;
        dscp_marking?: boolean;
        dscp_video?: number;
        dscp_dual?: boolean;
        e2e_encryption?: boolean;
        entry_exit_chime?: string;
        far_end_camera_control?: boolean;
        feedback?: boolean;
        file_transfer?: boolean;
        group_hd?: boolean;
        webinar_group_hd?: boolean;
        join_from_desktop?: boolean;
        join_from_mobile?: boolean;
        auto_generated_translation?: {
            language_item_pairList?: {
                trans_lang_config?: {
                    speak_language?: {
                        name?: string;
                        code?: string;
                    };
                    translate_to?: {
                        all?: boolean;
                        language_config?: {
                            name?: string;
                            code?: string;
                        }[];
                    };
                }[];
                all?: boolean;
            };
            enable?: boolean;
        };
        language_interpretation?: {
            custom_languages?: string[];
            enable_language_interpretation_by_default?: boolean;
            allow_participants_to_speak_in_listening_channel?: boolean;
            allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
            enable?: boolean;
        };
        sign_language_interpretation?: {
            enable?: boolean;
            enable_sign_language_interpretation_by_default?: boolean;
            custom_languages?: string[];
        };
        live_streaming_facebook?: boolean;
        live_streaming_youtube?: boolean;
        manual_captioning?: {
            allow_to_type?: boolean;
            auto_generated_captions?: boolean;
            full_transcript?: boolean;
            manual_captions?: boolean;
            save_captions?: boolean;
            third_party_captioning_service?: boolean;
        };
        meeting_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            require_answers_to_be_anonymous?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            allow_host_to_upload_image?: boolean;
            enable?: boolean;
        };
        meeting_reactions?: boolean;
        meeting_reactions_emojis?: string;
        allow_host_panelists_to_use_audible_clap?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        original_audio?: boolean;
        p2p_connetion?: boolean;
        p2p_ports?: boolean;
        polling?: boolean;
        ports_range?: string;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        record_play_own_voice?: boolean;
        remote_control?: boolean;
        non_verbal_feedback?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        stereo_audio?: boolean;
        use_html_format_email?: boolean;
        virtual_background?: boolean;
        virtual_background_settings?: {
            allow_upload_custom?: boolean;
            allow_videos?: boolean;
            enable?: boolean;
            files?: {
                id?: string;
                is_default?: boolean;
                name?: string;
                size?: number;
                type?: string;
            }[];
        };
        watermark?: boolean;
        webinar_chat?: {
            allow_attendees_chat_with?: number;
            allow_auto_save_local_chat_file?: boolean;
            allow_panelists_chat_with?: number;
            allow_panelists_send_direct_message?: boolean;
            allow_users_save_chats?: number;
            default_attendees_chat_with?: number;
            enable?: boolean;
        };
        webinar_live_streaming?: {
            custom_service_instructions?: string;
            enable?: boolean;
            live_streaming_reminder?: boolean;
            live_streaming_service?: string[];
        };
        webinar_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            require_answers_to_be_anonymous?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            allow_host_to_upload_image?: boolean;
            enable?: boolean;
        };
        webinar_question_answer?: boolean;
        webinar_survey?: boolean;
        whiteboard?: boolean;
        who_can_share_screen?: string;
        who_can_share_screen_when_someone_is_sharing?: string;
        participants_share_simultaneously?: string;
        workplace_by_facebook?: boolean;
        transfer_meetings_between_devices?: boolean;
    };
    integration?: {
        box?: boolean;
        dropbox?: boolean;
        google_calendar?: boolean;
        google_drive?: boolean;
        kubi?: boolean;
        microsoft_one_drive?: boolean;
    };
    other_options?: {
        allow_auto_active_users?: boolean;
        allow_users_contact_support_via_chat?: boolean;
        allow_users_enter_and_share_pronouns?: boolean;
        blur_snapshot?: boolean;
        display_meetings_scheduled_for_others?: boolean;
        meeting_qos_and_mos?: number;
        show_one_user_meeting_on_dashboard?: boolean;
        use_cdn?: string;
        webinar_registration_options?: {
            allow_host_to_enable_join_info?: boolean;
            allow_host_to_enable_social_share_buttons?: boolean;
            enable_custom_questions?: boolean;
        };
        email_in_attendee_report_for_meeting?: boolean;
    };
    profile?: {
        recording_storage_location?: {
            allowed_values?: string[];
            value?: string;
        };
    };
    recording?: {
        account_user_access_recording?: boolean;
        allow_recovery_deleted_cloud_recordings?: boolean;
        archive?: {
            enable?: boolean;
            settings?: {
                audio_file?: boolean;
                cc_transcript_file?: boolean;
                chat_file?: boolean;
                chat_with_sender_email?: boolean;
                video_file?: boolean;
                chat_with_direct_message?: boolean;
                archive_retention?: number;
                action_when_archive_failed?: number;
                notification_when_archiving_starts?: string;
                play_voice_prompt_when_archiving_starts?: string;
            };
            type?: number;
        };
        auto_delete_cmr?: boolean;
        auto_delete_cmr_days?: number;
        auto_recording?: string;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        cloud_recording_download_host?: boolean;
        display_participant_name?: boolean;
        host_delete_cloud_recording?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        optimize_recording_for_3rd_party_video_editor?: boolean;
        prevent_host_access_recording?: boolean;
        record_audio_file?: boolean;
        record_audio_file_each_participant?: boolean;
        record_files_separately?: {
            active_speaker?: boolean;
            gallery_view?: boolean;
            shared_screen?: boolean;
        };
        record_gallery_view?: boolean;
        record_speaker_view?: boolean;
        recording_audio_transcript?: boolean;
        recording_disclaimer?: boolean;
        recording_highlight?: boolean;
        smart_recording?: {
            create_recording_highlights?: boolean;
            create_smart_chapters?: boolean;
            create_next_steps?: boolean;
        };
        recording_password_requirement?: {
            have_letter?: boolean;
            have_number?: boolean;
            have_special_character?: boolean;
            length?: number;
            only_allow_numeric?: boolean;
        };
        recording_thumbnails?: boolean;
        required_password_for_existing_cloud_recordings?: boolean;
        required_password_for_shared_cloud_recordings?: boolean;
        save_chat_text?: boolean;
        save_close_caption?: boolean;
        save_panelist_chat?: boolean;
        save_poll_results?: boolean;
        show_timestamp?: boolean;
    };
    schedule_meeting?: {
        audio_type?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        enforce_login_with_domains?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
        enable_dedicated_group_chat?: boolean;
        jbh_time?: number;
        join_before_host?: boolean;
        meeting_password_requirement?: {
            consecutive_characters_length?: number;
            have_letter?: boolean;
            have_number?: boolean;
            have_special_character?: boolean;
            have_upper_and_lower_characters?: boolean;
            length?: number;
            only_allow_numeric?: boolean;
            weak_enhance_detection?: boolean;
        };
        not_store_meeting_topic?: boolean;
        participant_video?: boolean;
        allow_host_to_disable_participant_video?: boolean;
        personal_meeting?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: string;
        require_password_for_scheduled_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        use_pmi_for_instant_meetings?: boolean;
        use_pmi_for_scheduled_meetings?: boolean;
        always_display_zoom_meeting_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_meetings?: boolean;
        };
        hide_meeting_description?: {
            enable?: boolean;
            hide_description_for_scheduled_meetings?: boolean;
        };
        always_display_zoom_webinar_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_webinars?: boolean;
        };
        hide_webinar_description?: {
            enable?: boolean;
            hide_description_for_scheduled_webinars?: boolean;
        };
        meeting_template?: {
            enable?: boolean;
            action?: string;
            templates?: {
                id?: string;
                enable?: boolean;
            }[];
        };
        continuous_meeting_chat?: {
            enable?: boolean;
            can_add_external_users?: boolean;
            auto_add_invited_external_users?: boolean;
        };
    };
    telephony?: {
        audio_conference_info?: string;
        telephony_regions?: {
            selection_values?: string;
        };
        third_party_audio?: boolean;
    };
    tsp?: {
        call_out?: boolean;
        call_out_countries?: string[];
        display_toll_free_numbers?: boolean;
        show_international_numbers_link?: boolean;
    };
    zoom_rooms?: {
        auto_start_stop_scheduled_meetings?: boolean;
        cmr_for_instant_meeting?: boolean;
        force_private_meeting?: boolean;
        hide_host_information?: boolean;
        list_meetings_with_calendar?: boolean;
        start_airplay_manually?: boolean;
        ultrasonic?: boolean;
        upcoming_meeting_alert?: boolean;
        weekly_system_restart?: boolean;
        zr_post_meeting_feedback?: boolean;
    };
} | ({
    allow_authentication_exception?: boolean;
    authentication_option?: {
        action?: string;
        default_option?: boolean;
        domains?: string;
        id?: string;
        name?: string;
        type?: string;
    };
    meeting_authentication?: boolean;
} | {
    authentication_option?: {
        action?: string;
        default_option?: boolean;
        domains?: string;
        id?: string;
        name?: string;
        type?: string;
    };
    recording_authentication?: boolean;
}) | {
    meeting_security?: {
        auto_security?: boolean;
        block_user_domain?: boolean;
        block_user_domain_list?: string[];
        chat_etiquette_tool?: {
            enable?: boolean;
            operate?: string;
            policies?: {
                description?: string;
                id?: string;
                is_locked?: boolean;
                keywords?: string[];
                name?: string;
                regular_expression?: string;
                status?: string;
                trigger_action?: number;
            }[];
        };
        embed_password_in_join_link?: boolean;
        encryption_type?: string;
        end_to_end_encrypted_meetings?: boolean;
        meeting_password?: boolean;
        meeting_password_requirement?: {
            consecutive_characters_length?: number;
            have_letter?: boolean;
            have_number?: boolean;
            have_special_character?: boolean;
            have_upper_and_lower_characters?: boolean;
            length?: number;
            only_allow_numeric?: boolean;
            weak_enhance_detection?: boolean;
        };
        only_authenticated_can_join_from_webclient?: boolean;
        phone_password?: boolean;
        pmi_password?: boolean;
        require_password_for_scheduled_meeting?: boolean;
        require_password_for_scheduled_webinar?: boolean;
        waiting_room?: boolean;
        waiting_room_settings?: {
            participants_to_place_in_waiting_room?: number;
            users_who_can_admit_participants_from_waiting_room?: number;
            whitelisted_domains_for_waiting_room?: string;
        };
        webinar_password?: boolean;
        waiting_room_options?: {
            enable?: boolean;
            locked?: boolean;
            admit_type?: number;
            internal_user_auto_admit?: number;
            admit_domain_allowlist?: string;
            who_can_admit_participants?: number;
            sort_order_of_people?: number;
            more_options?: {
                user_invited_by_host_can_bypass_waiting_room?: boolean;
                move_participants_to_waiting_room_when_host_dropped?: boolean;
                allow_participants_to_reply_to_host?: boolean;
            };
        };
    };
} | {
    in_meeting?: {
        custom_data_center_regions?: boolean;
        data_center_regions?: string[];
    };
    in_session?: {
        custom_data_center_regions?: boolean;
        data_center_regions?: string[];
        p2p_connetion?: boolean;
        p2p_ports?: boolean;
        ports_range?: string;
        dscp_audio?: number;
        dscp_marking?: boolean;
        dscp_video?: number;
        dscp_dual?: boolean;
        subsession?: boolean;
    };
    session_security?: {
        approved_or_denied_countries_or_regions?: {
            approved_list?: string[];
            denied_list?: string[];
            enable?: boolean;
            method?: string;
        };
    };
    recording?: {
        record_speaker_view?: boolean;
        record_gallery_view?: boolean;
        record_audio_file?: boolean;
        save_chat_text?: boolean;
        show_timestamp?: boolean;
        cloud_recording_download?: boolean;
        auto_delete_cmr?: boolean;
        auto_delete_cmr_days?: number;
    };
};
type AccountsGetAccountsWebinarRegistrationSettingsPathParams = {
    accountId: string;
};
type AccountsGetAccountsWebinarRegistrationSettingsQueryParams = {
    type?: string;
};
type AccountsGetAccountsWebinarRegistrationSettingsResponse = {
    options?: {
        host_email_notification?: boolean;
        close_registration?: boolean;
        allow_participants_to_join_from_multiple_devices?: boolean;
        show_social_share_buttons?: boolean;
    };
    questions?: {
        field_name?: string;
        required?: boolean;
        selected?: boolean;
    }[];
    approve_type?: number;
    custom_questions?: {
        title?: string;
        type?: string;
        required?: boolean;
        selected?: boolean;
        answers?: string[];
    }[];
};
type AccountsUpdateAccountsWebinarRegistrationSettingsPathParams = {
    accountId: string;
};
type AccountsUpdateAccountsWebinarRegistrationSettingsQueryParams = {
    type?: string;
};
type AccountsUpdateAccountsWebinarRegistrationSettingsRequestBody = {
    options?: {
        host_email_notification?: boolean;
        close_registration?: boolean;
        allow_participants_to_join_from_multiple_devices?: boolean;
        show_social_share_buttons?: boolean;
    };
    questions?: {
        field_name?: string;
        required?: boolean;
        selected?: boolean;
    }[];
    approve_type?: number;
    custom_questions?: {
        title?: string;
        type?: string;
        required?: boolean;
        selected?: boolean;
        answers?: string[];
    }[];
};
type AccountsUploadVirtualBackgroundFilesPathParams = {
    accountId: string;
};
type AccountsUploadVirtualBackgroundFilesRequestBody = {
    file?: string;
};
type AccountsUploadVirtualBackgroundFilesResponse = {
    id?: string;
    is_default?: boolean;
    name?: string;
    size?: number;
    type?: string;
};
type AccountsDeleteVirtualBackgroundFilesPathParams = {
    accountId: string;
};
type AccountsDeleteVirtualBackgroundFilesQueryParams = {
    file_ids?: string;
};
type AccountsGetAccountsTrustedDomainsPathParams = {
    accountId: string;
};
type AccountsGetAccountsTrustedDomainsResponse = {
    trusted_domains?: string[];
};
type DashboardsGetChatMetricsQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsGetChatMetricsResponse = {
    from?: string;
    next_page_token?: string;
    page_size?: number;
    to?: string;
} & {
    users?: {
        audio_sent?: number;
        code_sippet_sent?: number;
        email?: string;
        files_sent?: number;
        giphys_sent?: number;
        group_sent?: number;
        images_sent?: number;
        p2p_sent?: number;
        text_sent?: number;
        total_sent?: number;
        user_id?: string;
        user_name?: string;
        video_sent?: number;
    }[];
};
type DashboardsListZoomMeetingsClientFeedbackQueryParams = {
    from: string;
    to: string;
};
type DashboardsListZoomMeetingsClientFeedbackResponse = {
    client_feedbacks?: {
        feedback_id?: string;
        feedback_name?: string;
        participants_count?: number;
    }[];
    from?: string;
    to?: string;
    total_records?: number;
};
type DashboardsGetZoomMeetingsClientFeedbackPathParams = {
    feedbackId: string;
};
type DashboardsGetZoomMeetingsClientFeedbackQueryParams = {
    from?: string;
    to?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsGetZoomMeetingsClientFeedbackResponse = {
    from?: string;
    to?: string;
} & {
    next_page_token?: string;
    page_size?: number;
} & {
    client_feedback_details?: {
        email?: string;
        meeting_id?: string;
        participant_name?: string;
        time?: string;
    }[];
};
type DashboardsListClientMeetingSatisfactionQueryParams = {
    from?: string;
    to?: string;
};
type DashboardsListClientMeetingSatisfactionResponse = {
    client_satisfaction?: {
        date?: string;
        good_count?: number;
        none_count?: number;
        not_good_count?: number;
        satisfaction_percent?: number;
    }[];
    from?: string;
    to?: string;
    total_records?: number;
};
type DashboardsListClientVersionsResponse = {
    client_versions?: {
        client_version?: string;
        total_count?: number;
    }[];
};
type DashboardsGetCRCPortUsageQueryParams = {
    from: string;
    to: string;
};
type DashboardsGetCRCPortUsageResponse = {
    from?: string;
    to?: string;
} & {
    crc_ports_usage?: {
        crc_ports_hour_usage?: {
            hour?: string;
            max_usage?: number;
            total_usage?: number;
        }[];
        date_time?: string;
    }[];
};
type DashboardsGetTopZoomRoomsWithIssuesQueryParams = {
    from: string;
    to: string;
};
type DashboardsGetTopZoomRoomsWithIssuesResponse = {
    from?: string;
    to?: string;
    total_records?: number;
} & {
    zoom_rooms?: {
        id?: string;
        issues_count?: number;
        room_name?: string;
    }[];
};
type DashboardsGetIssuesOfZoomRoomsPathParams = {
    zoomroomId: string;
};
type DashboardsGetIssuesOfZoomRoomsQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsGetIssuesOfZoomRoomsResponse = {
    from?: string;
    to?: string;
} & {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    issue_details?: {
        issue?: string;
        time?: string;
    }[];
};
type DashboardsListMeetingsQueryParams = {
    type?: string;
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    group_id?: string;
    group_include_participant?: boolean;
    include_fields?: string;
    query_date_type?: string;
};
type DashboardsListMeetingsResponse = {
    from?: string;
    to?: string;
} & {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    meetings?: {
        host?: string;
        audio_quality?: string;
        custom_keys?: {
            key?: string;
            value?: string;
        }[];
        dept?: string;
        duration?: string;
        email?: string;
        end_time?: string;
        has_3rd_party_audio?: boolean;
        has_archiving?: boolean;
        has_pstn?: boolean;
        has_recording?: boolean;
        has_screen_share?: boolean;
        has_sip?: boolean;
        has_video?: boolean;
        has_voip?: boolean;
        has_manual_captions?: boolean;
        has_automated_captions?: boolean;
        id?: number;
        participants?: number;
        screen_share_quality?: string;
        session_key?: string;
        start_time?: string;
        topic?: string;
        tracking_fields?: {
            field?: string;
            value?: string;
        }[];
        user_type?: string;
        uuid?: string;
        video_quality?: string;
    }[];
};
type DashboardsGetMeetingDetailsPathParams = {
    meetingId: string;
};
type DashboardsGetMeetingDetailsQueryParams = {
    type?: string;
};
type DashboardsGetMeetingDetailsResponse = {
    host?: string;
    custom_keys?: {
        key?: string;
        value?: string;
    }[];
    dept?: string;
    duration?: string;
    email?: string;
    end_time?: string;
    has_3rd_party_audio?: boolean;
    has_archiving?: boolean;
    has_pstn?: boolean;
    has_recording?: boolean;
    has_screen_share?: boolean;
    has_sip?: boolean;
    has_video?: boolean;
    has_voip?: boolean;
    has_manual_captions?: boolean;
    has_automated_captions?: boolean;
    id?: number;
    in_room_participants?: number;
    participants?: number;
    start_time?: string;
    topic?: string;
    user_type?: string;
    uuid?: string;
    has_meeting_summary?: boolean;
};
type DashboardsListMeetingParticipantsPathParams = {
    meetingId: string;
};
type DashboardsListMeetingParticipantsQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
    include_fields?: string;
};
type DashboardsListMeetingParticipantsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        audio_quality?: string;
        camera?: string;
        connection_type?: string;
        customer_key?: string;
        data_center?: string;
        device?: string;
        domain?: string;
        email?: string;
        from_sip_uri?: string;
        full_data_center?: string;
        harddisk_id?: string;
        id?: string;
        in_room_participants?: number;
        internal_ip_addresses?: string[];
        ip_address?: string;
        join_time?: string;
        leave_reason?: string;
        leave_time?: string;
        location?: string;
        mac_addr?: string;
        microphone?: string;
        network_type?: string;
        participant_user_id?: string;
        pc_name?: string;
        recording?: boolean;
        registrant_id?: string;
        role?: string;
        screen_share_quality?: string;
        share_application?: boolean;
        share_desktop?: boolean;
        share_whiteboard?: boolean;
        sip_uri?: string;
        speaker?: string;
        status?: string;
        user_id?: string;
        participant_uuid?: string;
        user_name?: string;
        version?: string;
        video_quality?: string;
        bo_mtg_id?: string;
        audio_call?: {
            call_number?: string;
            call_type?: string;
            zoom_number?: string;
        }[];
        os?: string;
        os_version?: string;
        device_name?: string;
        groupId?: string;
        has_archiving?: boolean;
        optional_archiving?: string;
        client?: string;
    }[];
};
type DashboardsListMeetingParticipantsQoSPathParams = {
    meetingId: string;
};
type DashboardsListMeetingParticipantsQoSQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsListMeetingParticipantsQoSResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        id?: string;
        device?: string;
        client?: string;
        domain?: string;
        harddisk_id?: string;
        internal_ip_addresses?: string[];
        ip_address?: string;
        join_time?: string;
        leave_time?: string;
        location?: string;
        mac_addr?: string;
        pc_name?: string;
        user_id?: string;
        user_name?: string;
        user_qos?: {
            as_device_from_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            as_device_to_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            as_input?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            as_output?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            audio_device_from_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_device_to_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_input?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_output?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            cpu_usage?: {
                system_max_cpu_usage?: string;
                zoom_avg_cpu_usage?: string;
                zoom_max_cpu_usage?: string;
                zoom_min_cpu_usage?: string;
            };
            date_time?: string;
            video_device_from_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            video_device_to_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            video_input?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            video_output?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            as_device_from_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            as_device_to_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            audio_device_from_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_device_to_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            video_device_from_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            video_device_to_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            wifi_rssi?: {
                max_rssi?: number;
                avg_rssi?: number;
                min_rssi?: number;
                rssi_unit?: string;
            };
        }[];
        version?: string;
    }[];
};
type DashboardsGetPostMeetingFeedbackPathParams = {
    meetingId: number | string;
};
type DashboardsGetPostMeetingFeedbackQueryParams = {
    type?: string;
    next_page_token?: string;
    page_size?: number;
};
type DashboardsGetPostMeetingFeedbackResponse = {
    next_page_token?: string;
    page_size?: number;
    participants?: {
        date_time?: string;
        email?: string;
        quality?: string;
        user_id?: string;
        comment?: string;
    }[];
};
type DashboardsGetMeetingSharingRecordingDetailsPathParams = {
    meetingId: number | string;
};
type DashboardsGetMeetingSharingRecordingDetailsQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsGetMeetingSharingRecordingDetailsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        details?: {
            content?: string;
            end_time?: string;
            start_time?: string;
        }[];
        id?: string;
        user_id?: string;
        user_name?: string;
    }[];
};
type DashboardsGetMeetingParticipantQoSPathParams = {
    meetingId: string;
    participantId: string;
};
type DashboardsGetMeetingParticipantQoSQueryParams = {
    type?: string;
};
type DashboardsGetMeetingParticipantQoSResponse = {
    id?: string;
    device?: string;
    client?: string;
    domain?: string;
    harddisk_id?: string;
    internal_ip_addresses?: string[];
    ip_address?: string;
    join_time?: string;
    leave_time?: string;
    location?: string;
    mac_addr?: string;
    pc_name?: string;
    user_id?: string;
    user_name?: string;
    user_qos?: {
        as_device_from_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        as_device_to_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        as_input?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        as_output?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        audio_device_from_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_device_to_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_input?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_output?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        cpu_usage?: {
            system_max_cpu_usage?: string;
            zoom_avg_cpu_usage?: string;
            zoom_max_cpu_usage?: string;
            zoom_min_cpu_usage?: string;
        };
        date_time?: string;
        video_device_from_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        video_device_to_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        video_input?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        video_output?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        as_device_from_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        as_device_to_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        audio_device_from_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_device_to_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        video_device_from_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        video_device_to_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        wifi_rssi?: {
            max_rssi?: number;
            avg_rssi?: number;
            min_rssi?: number;
            rssi_unit?: string;
        };
    }[];
    version?: string;
};
type DashboardsGetMeetingQualityScoresQueryParams = {
    from: string;
    to: string;
    type?: string;
};
type DashboardsGetMeetingQualityScoresResponse = {
    from?: string;
    quality?: {
        audio?: {
            bad?: number;
            fair?: number;
            good?: number;
            poor?: number;
        };
        screen_share?: {
            bad?: number;
            fair?: number;
            good?: number;
            poor?: number;
        };
        video?: {
            bad?: number;
            fair?: number;
            good?: number;
            poor?: number;
        };
    };
    to?: string;
};
type DashboardsListWebinarsQueryParams = {
    type?: string;
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    group_id?: string;
};
type DashboardsListWebinarsResponse = {
    from?: string;
    to?: string;
} & {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    webinars?: {
        host?: string;
        custom_keys?: {
            key?: string;
            value?: string;
        }[];
        dept?: string;
        duration?: string;
        email?: string;
        end_time?: string;
        has_3rd_party_audio?: boolean;
        has_archiving?: boolean;
        has_pstn?: boolean;
        has_recording?: boolean;
        has_screen_share?: boolean;
        has_sip?: boolean;
        has_video?: boolean;
        has_voip?: boolean;
        has_manual_captions?: boolean;
        has_automated_captions?: boolean;
        id?: number;
        participants?: number;
        start_time?: string;
        topic?: string;
        user_type?: string;
        uuid?: string;
        audio_quality?: string;
        video_quality?: string;
        screen_share_quality?: string;
    }[];
};
type DashboardsGetWebinarDetailsPathParams = {
    webinarId: string;
};
type DashboardsGetWebinarDetailsQueryParams = {
    type?: string;
};
type DashboardsGetWebinarDetailsResponse = {
    host?: string;
    custom_keys?: {
        key?: string;
        value?: string;
    }[];
    dept?: string;
    duration?: string;
    email?: string;
    end_time?: string;
    has_3rd_party_audio?: boolean;
    has_archiving?: boolean;
    has_pstn?: boolean;
    has_recording?: boolean;
    has_screen_share?: boolean;
    has_sip?: boolean;
    has_video?: boolean;
    has_voip?: boolean;
    has_manual_captions?: boolean;
    has_automated_captions?: boolean;
    id?: number;
    participants?: number;
    start_time?: string;
    topic?: string;
    user_type?: string;
    uuid?: string;
    audio_quality?: string;
    video_quality?: string;
    screen_share_quality?: string;
};
type DashboardsGetWebinarParticipantsPathParams = {
    webinarId: string;
};
type DashboardsGetWebinarParticipantsQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
    include_fields?: string;
};
type DashboardsGetWebinarParticipantsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        audio_quality?: string;
        connection_type?: string;
        customer_key?: string;
        data_center?: string;
        device?: string;
        domain?: string;
        email?: string;
        from_sip_uri?: string;
        full_data_center?: string;
        harddisk_id?: string;
        id?: string;
        internal_ip_addresses?: string[];
        ip_address?: string;
        join_time?: string;
        leave_reason?: string;
        leave_time?: string;
        location?: string;
        mac_addr?: string;
        microphone?: string;
        network_type?: string;
        participant_user_id?: string;
        pc_name?: string;
        recording?: boolean;
        registrant_id?: string;
        role?: string;
        screen_share_quality?: string;
        share_application?: boolean;
        share_desktop?: boolean;
        share_whiteboard?: boolean;
        sip_uri?: string;
        speaker?: string;
        user_id?: string;
        participant_uuid?: string;
        user_name?: string;
        version?: string;
        video_quality?: string;
        audio_call?: {
            call_number?: string;
            call_type?: string;
            zoom_number?: string;
        }[];
        os?: string;
        os_version?: string;
        device_name?: string;
        client?: string;
        has_archiving?: boolean;
        optional_archiving?: string;
        bo_mtg_id?: string;
    }[];
};
type DashboardsListWebinarParticipantQoSPathParams = {
    webinarId: string;
};
type DashboardsListWebinarParticipantQoSQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsListWebinarParticipantQoSResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        id?: string;
        device?: string;
        client?: string;
        domain?: string;
        harddisk_id?: string;
        internal_ip_addresses?: string[];
        ip_address?: string;
        join_time?: string;
        leave_time?: string;
        location?: string;
        mac_addr?: string;
        pc_name?: string;
        user_id?: string;
        user_name?: string;
        user_qos?: {
            as_device_from_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            as_device_to_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            as_input?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            as_output?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            audio_device_from_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_device_to_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_input?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_output?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            cpu_usage?: {
                system_max_cpu_usage?: string;
                zoom_avg_cpu_usage?: string;
                zoom_max_cpu_usage?: string;
                zoom_min_cpu_usage?: string;
            };
            date_time?: string;
            video_device_from_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            video_device_to_crc?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            video_input?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            video_output?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            } & {
                frame_rate?: string;
                resolution?: string;
            };
            as_device_from_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            as_device_to_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            audio_device_from_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            audio_device_to_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
            };
            video_device_from_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            video_device_to_rwg?: {
                avg_loss?: string;
                bitrate?: string;
                jitter?: string;
                latency?: string;
                max_loss?: string;
                frame_rate?: string;
                resolution?: string;
            };
            wifi_rssi?: {
                max_rssi?: number;
                avg_rssi?: number;
                min_rssi?: number;
                rssi_unit?: string;
            };
        }[];
        version?: string;
    }[];
};
type DashboardsGetPostWebinarFeedbackPathParams = {
    webinarId: string;
};
type DashboardsGetPostWebinarFeedbackQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsGetPostWebinarFeedbackResponse = {
    next_page_token?: string;
    page_size?: number;
    participants?: {
        date_time?: string;
        email?: string;
        quality?: string;
        user_id?: string;
        comment?: string;
    }[];
};
type DashboardsGetWebinarSharingRecordingDetailsPathParams = {
    webinarId: string;
};
type DashboardsGetWebinarSharingRecordingDetailsQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsGetWebinarSharingRecordingDetailsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        details?: {
            content?: string;
            end_time?: string;
            start_time?: string;
        }[];
        id?: string;
        user_id?: string;
        user_name?: string;
    }[];
};
type DashboardsGetWebinarParticipantQoSPathParams = {
    webinarId: string;
    participantId: string;
};
type DashboardsGetWebinarParticipantQoSQueryParams = {
    type?: string;
};
type DashboardsGetWebinarParticipantQoSResponse = {
    id?: string;
    device?: string;
    client?: string;
    domain?: string;
    harddisk_id?: string;
    internal_ip_addresses?: string[];
    ip_address?: string;
    join_time?: string;
    leave_time?: string;
    location?: string;
    mac_addr?: string;
    pc_name?: string;
    user_id?: string;
    user_name?: string;
    user_qos?: {
        as_device_from_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        as_device_to_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        as_input?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        as_output?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        audio_device_from_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_device_to_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_input?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_output?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        cpu_usage?: {
            system_max_cpu_usage?: string;
            zoom_avg_cpu_usage?: string;
            zoom_max_cpu_usage?: string;
            zoom_min_cpu_usage?: string;
        };
        date_time?: string;
        video_device_from_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        video_device_to_crc?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        video_input?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        video_output?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        } & {
            frame_rate?: string;
            resolution?: string;
        };
        as_device_from_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        as_device_to_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        audio_device_from_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        audio_device_to_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
        };
        video_device_from_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        video_device_to_rwg?: {
            avg_loss?: string;
            bitrate?: string;
            jitter?: string;
            latency?: string;
            max_loss?: string;
            frame_rate?: string;
            resolution?: string;
        };
        wifi_rssi?: {
            max_rssi?: number;
            avg_rssi?: number;
            min_rssi?: number;
            rssi_unit?: string;
        };
    }[];
    version?: string;
    health?: string;
    issue_list?: string[];
};
type DashboardsListZoomRoomsQueryParams = {
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type DashboardsListZoomRoomsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    zoom_rooms?: {
        account_type?: string;
        calender_name?: string;
        camera?: string;
        device_ip?: string;
        email?: string;
        health?: string;
        id?: string;
        issues?: string[];
        last_start_time?: string;
        location?: string;
        location_id?: string;
        microphone?: string;
        room_name?: string;
        speaker?: string;
        status?: string;
    }[];
};
type DashboardsGetTopIssuesOfZoomRoomsQueryParams = {
    from: string;
    to: string;
};
type DashboardsGetTopIssuesOfZoomRoomsResponse = {
    from?: string;
    to?: string;
    total_records?: number;
} & {
    issues?: {
        issue_name?: string;
        zoom_rooms_count?: number;
    }[];
};
type DashboardsGetZoomRoomsDetailsPathParams = {
    zoomroomId: string;
};
type DashboardsGetZoomRoomsDetailsQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
};
type DashboardsGetZoomRoomsDetailsResponse = {
    account_type?: string;
    calender_name?: string;
    camera?: string;
    device_ip?: string;
    email?: string;
    health?: string;
    id?: string;
    issues?: string[];
    last_start_time?: string;
    location?: string;
    microphone?: string;
    room_name?: string;
    speaker?: string;
    status?: string;
} & {
    live_meeting?: {
        host?: string;
        custom_keys?: {
            key?: string;
            value?: string;
        }[];
        dept?: string;
        duration?: string;
        email?: string;
        end_time?: string;
        has_3rd_party_audio?: boolean;
        has_archiving?: boolean;
        has_pstn?: boolean;
        has_recording?: boolean;
        has_screen_share?: boolean;
        has_sip?: boolean;
        has_video?: boolean;
        has_voip?: boolean;
        has_manual_captions?: boolean;
        has_automated_captions?: boolean;
        id?: number;
        in_room_participants?: number;
        participants?: number;
        start_time?: string;
        topic?: string;
        user_type?: string;
        uuid?: string;
    };
    past_meetings?: {
        from?: string;
        to?: string;
    } & {
        next_page_token?: string;
        page_count?: number;
        page_size?: number;
        total_records?: number;
    } & {
        meetings?: {
            host?: string;
            custom_keys?: {
                key?: string;
                value?: string;
            }[];
            dept?: string;
            duration?: string;
            email?: string;
            end_time?: string;
            has_3rd_party_audio?: boolean;
            has_archiving?: boolean;
            has_pstn?: boolean;
            has_recording?: boolean;
            has_screen_share?: boolean;
            has_sip?: boolean;
            has_video?: boolean;
            has_voip?: boolean;
            has_manual_captions?: boolean;
            has_automated_captions?: boolean;
            id?: number;
            in_room_participants?: number;
            participants?: number;
            start_time?: string;
            topic?: string;
            user_type?: string;
            uuid?: string;
        }[];
    };
};
type InformationBarriersListInformationBarrierPoliciesResponse = {
    policies: {
        assigned_group_id: string;
        id: string;
        policy_name: string;
        settings: {
            complete_phone_calls: boolean;
            file_transfer: boolean;
            im: boolean;
            in_meeting_chat: boolean;
            meeting: boolean;
            message_via_sms: boolean;
            recording: boolean;
            screen_share: boolean;
        };
        status: number;
        to_group_id: string;
        type: number;
    }[];
    total_records: number;
};
type InformationBarriersCreateInformationBarrierPolicyRequestBody = {
    assigned_group_id: string;
    id: string;
    policy_name: string;
    settings: {
        complete_phone_calls: boolean;
        file_transfer: boolean;
        im: boolean;
        in_meeting_chat: boolean;
        meeting: boolean;
        message_via_sms: boolean;
        recording: boolean;
        screen_share: boolean;
    };
    status: number;
    to_group_id: string;
    type: number;
};
type InformationBarriersCreateInformationBarrierPolicyResponse = {
    assigned_group_id: string;
    id: string;
    policy_name: string;
    settings: {
        complete_phone_calls: boolean;
        file_transfer: boolean;
        im: boolean;
        in_meeting_chat: boolean;
        meeting: boolean;
        message_via_sms: boolean;
        recording: boolean;
        screen_share: boolean;
    };
    status: number;
    to_group_id: string;
    type: number;
};
type InformationBarriersGetInformationBarrierPolicyByIDPathParams = {
    policyId: string;
};
type InformationBarriersGetInformationBarrierPolicyByIDResponse = {
    assigned_group_id: string;
    id: string;
    policy_name: string;
    settings: {
        complete_phone_calls: boolean;
        file_transfer: boolean;
        im: boolean;
        in_meeting_chat: boolean;
        meeting: boolean;
        message_via_sms: boolean;
        recording: boolean;
        screen_share: boolean;
    };
    status: number;
    to_group_id: string;
    type: number;
};
type InformationBarriersRemoveInformationBarrierPolicyPathParams = {
    policyId: string;
};
type InformationBarriersUpdateInformationBarriersPolicyPathParams = {
    policyId: string;
};
type InformationBarriersUpdateInformationBarriersPolicyRequestBody = {
    assigned_group_id: string;
    id: string;
    policy_name: string;
    settings: {
        complete_phone_calls: boolean;
        file_transfer: boolean;
        im: boolean;
        in_meeting_chat: boolean;
        meeting: boolean;
        message_via_sms: boolean;
        recording: boolean;
        screen_share: boolean;
    };
    status: number;
    to_group_id: string;
    type: number;
};
type RolesListRolesQueryParams = {
    type?: string;
};
type RolesListRolesResponse = {
    roles?: {
        description?: string;
        id?: string;
        name?: string;
        type?: string;
        total_members?: number;
    }[];
    total_records?: number;
};
type RolesCreateRoleRequestBody = {
    description?: string;
    name?: string;
    type?: string;
    privileges?: string[];
};
type RolesCreateRoleResponse = {};
type RolesGetRoleInformationPathParams = {
    roleId: string;
};
type RolesGetRoleInformationResponse = {
    description?: string;
    id?: string;
    name?: string;
    type?: string;
    privileges?: string[];
    sub_account_privileges?: {
        second_level?: number;
    };
    total_members?: number;
};
type RolesDeleteRolePathParams = {
    roleId: string;
};
type RolesUpdateRoleInformationPathParams = {
    roleId: string;
};
type RolesUpdateRoleInformationRequestBody = {
    description?: string;
    name?: string;
    privileges?: string[];
    sub_account_privileges?: {
        second_level?: number;
    };
};
type RolesUpdateRoleInformationResponse = {};
type RolesListMembersInRolePathParams = {
    roleId: string;
};
type RolesListMembersInRoleQueryParams = {
    page_count?: string;
    page_number?: number;
    next_page_token?: string;
    page_size?: number;
};
type RolesListMembersInRoleResponse = {
    members?: {
        department?: string;
        email?: string;
        first_name?: string;
        id?: string;
        last_name?: string;
        type?: number;
    }[];
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
};
type RolesAssignRolePathParams = {
    roleId: string;
};
type RolesAssignRoleRequestBody = {
    members?: {
        email?: string;
        id?: string;
    }[];
};
type RolesAssignRoleResponse = {
    add_at?: string;
    ids?: string;
};
type RolesUnassignRolePathParams = {
    roleId: string;
    memberId: string;
};
declare class AccountsEndpoints extends WebEndpoints {
    readonly accounts: {
        getLockedSettings: (_: {
            path: AccountsGetLockedSettingsPathParams;
        } & object & {
            query?: AccountsGetLockedSettingsQueryParams;
        }) => Promise<BaseResponse<AccountsGetLockedSettingsResponse>>;
        updateLockedSettings: (_: {
            path: AccountsUpdateLockedSettingsPathParams;
        } & (({
            body?: {
                audio_conferencing?: {
                    toll_free_and_fee_based_toll_call?: boolean;
                };
                chat?: {
                    share_files?: boolean;
                    chat_emojis?: boolean;
                    record_voice_messages?: boolean;
                    record_video_messages?: boolean;
                    screen_capture?: boolean;
                    share_links_in_chat?: boolean;
                    schedule_meetings_in_chat?: boolean;
                    set_retention_period_in_cloud?: boolean;
                    set_retention_period_in_local?: boolean;
                    allow_users_to_add_contacts?: boolean;
                    allow_users_to_chat_with_others?: boolean;
                    chat_etiquette_tool?: boolean;
                    send_data_to_third_party_archiving_service?: boolean;
                    translate_messages?: boolean;
                    search_and_send_animated_gif_images?: boolean;
                };
                email_notification?: {
                    alternative_host_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    cloud_recording_available_reminder?: boolean;
                    jbh_reminder?: boolean;
                    schedule_for_reminder?: boolean;
                };
                in_meeting?: {
                    alert_guest_join?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_live_streaming?: boolean;
                    allow_show_zoom_windows?: boolean;
                    annotation?: boolean;
                    anonymous_question_answer?: boolean;
                    attendee_on_hold?: boolean;
                    attention_mode_focus_mode?: boolean;
                    auto_answer?: boolean;
                    auto_generated_captions?: boolean;
                    auto_saving_chat?: boolean;
                    breakout_room?: boolean;
                    chat?: boolean;
                    meeting_question_answer?: boolean;
                    closed_caption?: boolean;
                    co_host?: boolean;
                    custom_data_center_regions?: boolean;
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
                    dscp_marking?: boolean;
                    e2e_encryption?: boolean;
                    entry_exit_chime?: string;
                    far_end_camera_control?: boolean;
                    feedback?: boolean;
                    file_transfer?: boolean;
                    full_transcript?: boolean;
                    group_hd?: boolean;
                    webinar_group_hd?: boolean;
                    language_interpretation?: boolean;
                    sign_language_interpretation?: boolean;
                    webinar_reactions?: boolean;
                    meeting_survey?: boolean;
                    original_audio?: boolean;
                    polling?: boolean;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    remote_control?: boolean;
                    non_verbal_feedback?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute_participants?: boolean;
                    save_caption?: boolean;
                    save_captions?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
                    stereo_audio?: boolean;
                    use_html_format_email?: boolean;
                    virtual_background?: boolean;
                    webinar_chat?: boolean;
                    webinar_live_streaming?: boolean;
                    webinar_polling?: boolean;
                    webinar_question_answer?: boolean;
                    webinar_survey?: boolean;
                    whiteboard?: boolean;
                };
                other_options?: {
                    blur_snapshot?: boolean;
                    webinar_registration_options?: boolean;
                };
                recording?: {
                    account_user_access_recording?: boolean;
                    auto_delete_cmr?: boolean;
                    auto_recording?: boolean;
                    cloud_recording?: boolean;
                    cloud_recording_download?: boolean;
                    host_delete_cloud_recording?: boolean;
                    ip_address_access_control?: boolean;
                    local_recording?: boolean;
                    prevent_host_access_recording?: boolean;
                    recording_authentication?: boolean;
                    archive?: boolean;
                };
                schedule_meeting?: {
                    audio_type?: boolean;
                    embed_password_in_join_link?: boolean;
                    enforce_login?: boolean;
                    enforce_login_domains?: string;
                    enforce_login_with_domains?: boolean;
                    host_video?: boolean;
                    join_before_host?: boolean;
                    meeting_authentication?: boolean;
                    not_store_meeting_topic?: boolean;
                    always_display_zoom_webinar_as_topic?: boolean;
                    participant_video?: boolean;
                    personal_meeting?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    use_pmi_for_instant_meetings?: boolean;
                    use_pmi_for_scheduled_meetings?: boolean;
                    continuous_meeting_chat?: boolean;
                };
                telephony?: {
                    telephony_regions?: boolean;
                    third_party_audio?: boolean;
                };
                tsp?: {
                    call_out?: boolean;
                    show_international_numbers_link?: boolean;
                };
            };
        } | {
            body?: {
                meeting_security?: {
                    approved_or_denied_countries_or_regions?: boolean;
                    auto_security?: boolean;
                    block_user_domain?: boolean;
                    chat_etiquette_tool?: boolean;
                    embed_password_in_join_link?: boolean;
                    encryption_type?: string;
                    end_to_end_encrypted_meetings?: boolean;
                    meeting_password?: boolean;
                    only_authenticated_can_join_from_webclient?: boolean;
                    phone_password?: boolean;
                    pmi_password?: boolean;
                    waiting_room?: boolean;
                    webinar_password?: boolean;
                };
            };
        }) & object)) => Promise<BaseResponse<unknown>>;
        getAccountsManagedDomains: (_: {
            path: AccountsGetAccountsManagedDomainsPathParams;
        } & object) => Promise<BaseResponse<AccountsGetAccountsManagedDomainsResponse>>;
        updateAccountOwner: (_: {
            path: AccountsUpdateAccountOwnerPathParams;
        } & {
            body: AccountsUpdateAccountOwnerRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getAccountSettings: (_: {
            path: AccountsGetAccountSettingsPathParams;
        } & object & {
            query?: AccountsGetAccountSettingsQueryParams;
        }) => Promise<BaseResponse<AccountsGetAccountSettingsResponse>>;
        updateAccountSettings: (_: {
            path: AccountsUpdateAccountSettingsPathParams;
        } & (({
            body?: {
                security?: {
                    admin_change_name_pic?: boolean;
                    admin_change_user_info?: boolean;
                    user_modifiable_info_by_admin?: string[];
                    signin_with_sso?: {
                        enable?: boolean;
                        require_sso_for_domains?: boolean;
                        domains?: string[];
                        sso_bypass_user_ids?: string[];
                        operation?: string;
                    };
                    hide_billing_info?: boolean;
                    import_photos_from_devices?: boolean;
                    password_requirement?: {
                        consecutive_characters_length?: number;
                        have_special_character?: boolean;
                        minimum_password_length?: number;
                        weak_enhance_detection?: boolean;
                    };
                    sign_again_period_for_inactivity_on_client?: number;
                    sign_again_period_for_inactivity_on_web?: number;
                    sign_in_with_two_factor_auth?: string;
                    sign_in_with_two_factor_auth_groups?: string[];
                    sign_in_with_two_factor_auth_roles?: string[];
                };
                audio_conferencing?: {
                    toll_free_and_fee_based_toll_call?: {
                        allow_webinar_attendees_dial?: boolean;
                        enable?: boolean;
                        numbers?: {
                            code?: string;
                            country_code?: string;
                            country_name?: string;
                            display_number?: string;
                            number?: string;
                        }[];
                    };
                };
                chat?: {
                    allow_bots_chat?: boolean;
                    share_files?: {
                        enable?: boolean;
                        share_option?: string;
                        restrictions?: {
                            only_allow_specific_file_types?: boolean;
                            file_type_restrictions?: string[];
                            file_type_restrictions_for_external?: string[];
                            maximum_file_size?: boolean;
                            file_size_restrictions?: number;
                            file_size_restrictions_for_external?: number;
                        };
                    };
                    chat_emojis?: {
                        enable?: boolean;
                        emojis_option?: string;
                    };
                    record_voice_messages?: boolean;
                    record_video_messages?: boolean;
                    screen_capture?: boolean;
                    create_public_channels?: boolean;
                    create_private_channels?: boolean;
                    share_links_in_chat?: boolean;
                    schedule_meetings_in_chat?: boolean;
                    set_retention_period_in_cloud?: {
                        enable?: boolean;
                        retention_period_of_direct_messages_and_group_conversation?: string;
                        retention_period_of_channels?: string;
                    };
                    set_retention_period_in_local?: {
                        enable?: boolean;
                        retention_period_of_direct_messages_and_group_conversation?: string;
                        retention_period_of_channels?: string;
                    };
                    allow_users_to_add_contacts?: {
                        enable?: boolean;
                        selected_option?: number;
                        user_email_addresses?: string;
                    };
                    allow_users_to_chat_with_others?: {
                        enable?: boolean;
                        selected_option?: number;
                        user_email_addresses?: string;
                    };
                    chat_etiquette_tool?: {
                        enable?: boolean;
                        operate?: string;
                        policies?: {
                            description?: string;
                            id?: string;
                            is_locked?: boolean;
                            keywords?: string[];
                            name?: string;
                            regular_expression?: string;
                            status?: string;
                            trigger_action?: number;
                        }[];
                    };
                    send_data_to_third_party_archiving_service?: {
                        enable?: boolean;
                        type?: string;
                        smtp_delivery_address?: string;
                        user_name?: string;
                        passcode?: string;
                        authorized_channel_token?: string;
                    };
                    apply_local_storage_to_personal_channel?: {
                        enable?: boolean;
                        retention_period?: string;
                    };
                    translate_messages?: boolean;
                    search_and_send_animated_gif_images?: {
                        enable?: boolean;
                        giphy_content_rating?: number;
                    };
                };
                email_notification?: {
                    alternative_host_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    cloud_recording_available_reminder?: boolean;
                    jbh_reminder?: boolean;
                    low_host_count_reminder?: boolean;
                    recording_available_reminder_alternative_hosts?: boolean;
                    recording_available_reminder_schedulers?: boolean;
                    schedule_for_reminder?: boolean;
                };
                feature?: {
                    meeting_capacity?: number;
                };
                in_meeting?: {
                    alert_guest_join?: boolean;
                    allow_host_to_enable_focus_mode?: boolean;
                    allow_live_streaming?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_participants_chat_with?: number;
                    allow_participants_to_rename?: boolean;
                    allow_show_zoom_windows?: boolean;
                    allow_users_save_chats?: number;
                    annotation?: boolean;
                    anonymous_question_answer?: boolean;
                    attendee_on_hold?: boolean;
                    attention_mode_focus_mode?: boolean;
                    auto_answer?: boolean;
                    auto_saving_chat?: boolean;
                    breakout_room?: boolean;
                    breakout_room_schedule?: boolean;
                    chat?: boolean;
                    meeting_question_answer?: boolean;
                    closed_caption?: boolean;
                    closed_captioning?: {
                        auto_transcribing?: boolean;
                        enable?: boolean;
                        save_caption?: boolean;
                        third_party_captioning_service?: boolean;
                        view_full_transcript?: boolean;
                    };
                    co_host?: boolean;
                    custom_data_center_regions?: boolean;
                    custom_live_streaming_service?: boolean;
                    custom_service_instructions?: string;
                    meeting_data_transit_and_residency_method?: string;
                    data_center_regions?: string[];
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
                    dscp_audio?: number;
                    dscp_marking?: boolean;
                    dscp_video?: number;
                    dscp_dual?: boolean;
                    e2e_encryption?: boolean;
                    entry_exit_chime?: string;
                    far_end_camera_control?: boolean;
                    feedback?: boolean;
                    file_transfer?: boolean;
                    group_hd?: boolean;
                    webinar_group_hd?: boolean;
                    join_from_desktop?: boolean;
                    join_from_mobile?: boolean;
                    auto_generated_translation?: {
                        language_item_pairList?: {
                            trans_lang_config?: {
                                speak_language?: {
                                    name?: string;
                                    code?: string;
                                };
                                translate_to?: {
                                    all?: boolean;
                                    language_config?: {
                                        name?: string;
                                        code?: string;
                                    }[];
                                };
                            }[];
                            all?: boolean;
                        };
                        enable?: boolean;
                    };
                    language_interpretation?: {
                        custom_languages?: string[];
                        enable_language_interpretation_by_default?: boolean;
                        allow_participants_to_speak_in_listening_channel?: boolean;
                        allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
                        enable?: boolean;
                    };
                    sign_language_interpretation?: {
                        enable?: boolean;
                        enable_sign_language_interpretation_by_default?: boolean;
                        custom_languages?: string[];
                    };
                    live_streaming_facebook?: boolean;
                    live_streaming_youtube?: boolean;
                    manual_captioning?: {
                        allow_to_type?: boolean;
                        auto_generated_captions?: boolean;
                        full_transcript?: boolean;
                        manual_captions?: boolean;
                        save_captions?: boolean;
                        third_party_captioning_service?: boolean;
                    };
                    meeting_polling?: {
                        advanced_polls?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        manage_saved_polls_and_quizzes?: boolean;
                        allow_host_to_upload_image?: boolean;
                        enable?: boolean;
                    };
                    meeting_reactions?: boolean;
                    meeting_reactions_emojis?: string;
                    allow_host_panelists_to_use_audible_clap?: boolean;
                    webinar_reactions?: boolean;
                    meeting_survey?: boolean;
                    original_audio?: boolean;
                    p2p_connetion?: boolean;
                    p2p_ports?: boolean;
                    polling?: boolean;
                    ports_range?: string;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    record_play_own_voice?: boolean;
                    remote_control?: boolean;
                    non_verbal_feedback?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute_participants?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_a_join_from_your_browser_link?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
                    stereo_audio?: boolean;
                    use_html_format_email?: boolean;
                    virtual_background?: boolean;
                    virtual_background_settings?: {
                        allow_upload_custom?: boolean;
                        allow_videos?: boolean;
                        enable?: boolean;
                        files?: {
                            id?: string;
                            is_default?: boolean;
                            name?: string;
                            size?: number;
                            type?: string;
                        }[];
                    };
                    watermark?: boolean;
                    webinar_chat?: {
                        allow_attendees_chat_with?: number;
                        allow_auto_save_local_chat_file?: boolean;
                        allow_panelists_chat_with?: number;
                        allow_panelists_send_direct_message?: boolean;
                        allow_users_save_chats?: number;
                        default_attendees_chat_with?: number;
                        enable?: boolean;
                    };
                    webinar_live_streaming?: {
                        custom_service_instructions?: string;
                        enable?: boolean;
                        live_streaming_reminder?: boolean;
                        live_streaming_service?: string[];
                    };
                    webinar_polling?: {
                        advanced_polls?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        manage_saved_polls_and_quizzes?: boolean;
                        allow_host_to_upload_image?: boolean;
                        enable?: boolean;
                    };
                    webinar_question_answer?: boolean;
                    webinar_survey?: boolean;
                    whiteboard?: boolean;
                    who_can_share_screen?: string;
                    who_can_share_screen_when_someone_is_sharing?: string;
                    participants_share_simultaneously?: string;
                    workplace_by_facebook?: boolean;
                    transfer_meetings_between_devices?: boolean;
                };
                integration?: {
                    box?: boolean;
                    dropbox?: boolean;
                    google_calendar?: boolean;
                    google_drive?: boolean;
                    kubi?: boolean;
                    microsoft_one_drive?: boolean;
                };
                other_options?: {
                    allow_auto_active_users?: boolean;
                    allow_users_contact_support_via_chat?: boolean;
                    allow_users_enter_and_share_pronouns?: boolean;
                    blur_snapshot?: boolean;
                    display_meetings_scheduled_for_others?: boolean;
                    meeting_qos_and_mos?: number;
                    show_one_user_meeting_on_dashboard?: boolean;
                    use_cdn?: string;
                    webinar_registration_options?: {
                        allow_host_to_enable_join_info?: boolean;
                        allow_host_to_enable_social_share_buttons?: boolean;
                        enable_custom_questions?: boolean;
                    };
                    email_in_attendee_report_for_meeting?: boolean;
                };
                profile?: {
                    recording_storage_location?: {
                        allowed_values?: string[];
                        value?: string;
                    };
                };
                recording?: {
                    account_user_access_recording?: boolean;
                    allow_recovery_deleted_cloud_recordings?: boolean;
                    archive?: {
                        enable?: boolean;
                        settings?: {
                            audio_file?: boolean;
                            cc_transcript_file?: boolean;
                            chat_file?: boolean;
                            chat_with_sender_email?: boolean;
                            video_file?: boolean;
                            chat_with_direct_message?: boolean;
                            archive_retention?: number;
                            action_when_archive_failed?: number;
                            notification_when_archiving_starts?: string;
                            play_voice_prompt_when_archiving_starts?: string;
                        };
                        type?: number;
                    };
                    auto_delete_cmr?: boolean;
                    auto_delete_cmr_days?: number;
                    auto_recording?: string;
                    cloud_recording?: boolean;
                    cloud_recording_download?: boolean;
                    cloud_recording_download_host?: boolean;
                    display_participant_name?: boolean;
                    host_delete_cloud_recording?: boolean;
                    ip_address_access_control?: {
                        enable?: boolean;
                        ip_addresses_or_ranges?: string;
                    };
                    local_recording?: boolean;
                    optimize_recording_for_3rd_party_video_editor?: boolean;
                    prevent_host_access_recording?: boolean;
                    record_audio_file?: boolean;
                    record_audio_file_each_participant?: boolean;
                    record_files_separately?: {
                        active_speaker?: boolean;
                        gallery_view?: boolean;
                        shared_screen?: boolean;
                    };
                    record_gallery_view?: boolean;
                    record_speaker_view?: boolean;
                    recording_audio_transcript?: boolean;
                    recording_disclaimer?: boolean;
                    recording_highlight?: boolean;
                    smart_recording?: {
                        create_recording_highlights?: boolean;
                        create_smart_chapters?: boolean;
                        create_next_steps?: boolean;
                    };
                    recording_password_requirement?: {
                        have_letter?: boolean;
                        have_number?: boolean;
                        have_special_character?: boolean;
                        length?: number;
                        only_allow_numeric?: boolean;
                    };
                    recording_thumbnails?: boolean;
                    required_password_for_existing_cloud_recordings?: boolean;
                    required_password_for_shared_cloud_recordings?: boolean;
                    save_chat_text?: boolean;
                    save_close_caption?: boolean;
                    save_panelist_chat?: boolean;
                    save_poll_results?: boolean;
                    show_timestamp?: boolean;
                };
                schedule_meeting?: {
                    audio_type?: string;
                    enforce_login?: boolean;
                    enforce_login_domains?: string;
                    enforce_login_with_domains?: boolean;
                    force_pmi_jbh_password?: boolean;
                    host_video?: boolean;
                    enable_dedicated_group_chat?: boolean;
                    jbh_time?: number;
                    join_before_host?: boolean;
                    meeting_password_requirement?: {
                        consecutive_characters_length?: number;
                        have_letter?: boolean;
                        have_number?: boolean;
                        have_special_character?: boolean;
                        have_upper_and_lower_characters?: boolean;
                        length?: number;
                        only_allow_numeric?: boolean;
                        weak_enhance_detection?: boolean;
                    };
                    not_store_meeting_topic?: boolean;
                    participant_video?: boolean;
                    allow_host_to_disable_participant_video?: boolean;
                    personal_meeting?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: string;
                    require_password_for_scheduled_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    use_pmi_for_instant_meetings?: boolean;
                    use_pmi_for_scheduled_meetings?: boolean;
                    always_display_zoom_meeting_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_meetings?: boolean;
                    };
                    hide_meeting_description?: {
                        enable?: boolean;
                        hide_description_for_scheduled_meetings?: boolean;
                    };
                    always_display_zoom_webinar_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_webinars?: boolean;
                    };
                    hide_webinar_description?: {
                        enable?: boolean;
                        hide_description_for_scheduled_webinars?: boolean;
                    };
                    meeting_template?: {
                        enable?: boolean;
                        action?: string;
                        templates?: {
                            id?: string;
                            enable?: boolean;
                        }[];
                    };
                    continuous_meeting_chat?: {
                        enable?: boolean;
                        can_add_external_users?: boolean;
                        auto_add_invited_external_users?: boolean;
                    };
                };
                telephony?: {
                    audio_conference_info?: string;
                    telephony_regions?: {
                        selection_values?: string;
                    };
                    third_party_audio?: boolean;
                };
                tsp?: {
                    call_out?: boolean;
                    call_out_countries?: string[];
                    display_toll_free_numbers?: boolean;
                    show_international_numbers_link?: boolean;
                };
                zoom_rooms?: {
                    auto_start_stop_scheduled_meetings?: boolean;
                    cmr_for_instant_meeting?: boolean;
                    force_private_meeting?: boolean;
                    hide_host_information?: boolean;
                    list_meetings_with_calendar?: boolean;
                    start_airplay_manually?: boolean;
                    ultrasonic?: boolean;
                    upcoming_meeting_alert?: boolean;
                    weekly_system_restart?: boolean;
                    zr_post_meeting_feedback?: boolean;
                };
            };
        } | {
            body?: {
                allow_authentication_exception?: boolean;
                authentication_option?: {
                    action?: string;
                    default_option?: boolean;
                    domains?: string;
                    id?: string;
                    name?: string;
                    type?: string;
                };
                meeting_authentication?: boolean;
            };
        } | {
            body?: {
                authentication_option?: {
                    action?: string;
                    default_option?: boolean;
                    domains?: string;
                    id?: string;
                    name?: string;
                    type?: string;
                };
                recording_authentication?: boolean;
            };
        } | {
            body?: {
                meeting_security?: {
                    auto_security?: boolean;
                    block_user_domain?: boolean;
                    block_user_domain_list?: string[];
                    chat_etiquette_tool?: {
                        enable?: boolean;
                        operate?: string;
                        policies?: {
                            description?: string;
                            id?: string;
                            is_locked?: boolean;
                            keywords?: string[];
                            name?: string;
                            regular_expression?: string;
                            status?: string;
                            trigger_action?: number;
                        }[];
                    };
                    embed_password_in_join_link?: boolean;
                    encryption_type?: string;
                    end_to_end_encrypted_meetings?: boolean;
                    meeting_password?: boolean;
                    meeting_password_requirement?: {
                        consecutive_characters_length?: number;
                        have_letter?: boolean;
                        have_number?: boolean;
                        have_special_character?: boolean;
                        have_upper_and_lower_characters?: boolean;
                        length?: number;
                        only_allow_numeric?: boolean;
                        weak_enhance_detection?: boolean;
                    };
                    only_authenticated_can_join_from_webclient?: boolean;
                    phone_password?: boolean;
                    pmi_password?: boolean;
                    require_password_for_scheduled_meeting?: boolean;
                    require_password_for_scheduled_webinar?: boolean;
                    waiting_room?: boolean;
                    waiting_room_settings?: {
                        participants_to_place_in_waiting_room?: number;
                        users_who_can_admit_participants_from_waiting_room?: number;
                        whitelisted_domains_for_waiting_room?: string;
                    };
                    webinar_password?: boolean;
                    waiting_room_options?: {
                        enable?: boolean;
                        locked?: boolean;
                        admit_type?: number;
                        internal_user_auto_admit?: number;
                        admit_domain_allowlist?: string;
                        who_can_admit_participants?: number;
                        sort_order_of_people?: number;
                        more_options?: {
                            user_invited_by_host_can_bypass_waiting_room?: boolean;
                            move_participants_to_waiting_room_when_host_dropped?: boolean;
                            allow_participants_to_reply_to_host?: boolean;
                        };
                    };
                };
            };
        } | {
            body?: {
                in_meeting?: {
                    custom_data_center_regions?: boolean;
                    data_center_regions?: string[];
                };
                in_session?: {
                    custom_data_center_regions?: boolean;
                    data_center_regions?: string[];
                    p2p_connetion?: boolean;
                    p2p_ports?: boolean;
                    ports_range?: string;
                    dscp_audio?: number;
                    dscp_marking?: boolean;
                    dscp_video?: number;
                    dscp_dual?: boolean;
                    subsession?: boolean;
                };
                session_security?: {
                    approved_or_denied_countries_or_regions?: {
                        approved_list?: string[];
                        denied_list?: string[];
                        enable?: boolean;
                        method?: string;
                    };
                };
                recording?: {
                    record_speaker_view?: boolean;
                    record_gallery_view?: boolean;
                    record_audio_file?: boolean;
                    save_chat_text?: boolean;
                    show_timestamp?: boolean;
                    cloud_recording_download?: boolean;
                    auto_delete_cmr?: boolean;
                    auto_delete_cmr_days?: number;
                };
            };
        }) & {
            query?: AccountsUpdateAccountSettingsQueryParams;
        })) => Promise<BaseResponse<unknown>>;
        getAccountsWebinarRegistrationSettings: (_: {
            path: AccountsGetAccountsWebinarRegistrationSettingsPathParams;
        } & object & {
            query?: AccountsGetAccountsWebinarRegistrationSettingsQueryParams;
        }) => Promise<BaseResponse<AccountsGetAccountsWebinarRegistrationSettingsResponse>>;
        updateAccountsWebinarRegistrationSettings: (_: {
            path: AccountsUpdateAccountsWebinarRegistrationSettingsPathParams;
        } & {
            body?: AccountsUpdateAccountsWebinarRegistrationSettingsRequestBody;
        } & {
            query?: AccountsUpdateAccountsWebinarRegistrationSettingsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        uploadVirtualBackgroundFiles: (_: {
            path: AccountsUploadVirtualBackgroundFilesPathParams;
        } & {
            body?: AccountsUploadVirtualBackgroundFilesRequestBody;
        } & object) => Promise<BaseResponse<AccountsUploadVirtualBackgroundFilesResponse>>;
        deleteVirtualBackgroundFiles: (_: {
            path: AccountsDeleteVirtualBackgroundFilesPathParams;
        } & object & {
            query?: AccountsDeleteVirtualBackgroundFilesQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getAccountsTrustedDomains: (_: {
            path: AccountsGetAccountsTrustedDomainsPathParams;
        } & object) => Promise<BaseResponse<AccountsGetAccountsTrustedDomainsResponse>>;
    };
    readonly dashboards: {
        getChatMetrics: (_: object & {
            query: DashboardsGetChatMetricsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetChatMetricsResponse>>;
        listZoomMeetingsClientFeedback: (_: object & {
            query: DashboardsListZoomMeetingsClientFeedbackQueryParams;
        }) => Promise<BaseResponse<DashboardsListZoomMeetingsClientFeedbackResponse>>;
        getZoomMeetingsClientFeedback: (_: {
            path: DashboardsGetZoomMeetingsClientFeedbackPathParams;
        } & object & {
            query?: DashboardsGetZoomMeetingsClientFeedbackQueryParams;
        }) => Promise<BaseResponse<DashboardsGetZoomMeetingsClientFeedbackResponse>>;
        listClientMeetingSatisfaction: (_: object & {
            query?: DashboardsListClientMeetingSatisfactionQueryParams;
        }) => Promise<BaseResponse<DashboardsListClientMeetingSatisfactionResponse>>;
        listClientVersions: (_: object) => Promise<BaseResponse<DashboardsListClientVersionsResponse>>;
        getCRCPortUsage: (_: object & {
            query: DashboardsGetCRCPortUsageQueryParams;
        }) => Promise<BaseResponse<DashboardsGetCRCPortUsageResponse>>;
        getTopZoomRoomsWithIssues: (_: object & {
            query: DashboardsGetTopZoomRoomsWithIssuesQueryParams;
        }) => Promise<BaseResponse<DashboardsGetTopZoomRoomsWithIssuesResponse>>;
        getIssuesOfZoomRooms: (_: {
            path: DashboardsGetIssuesOfZoomRoomsPathParams;
        } & object & {
            query: DashboardsGetIssuesOfZoomRoomsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetIssuesOfZoomRoomsResponse>>;
        listMeetings: (_: object & {
            query: DashboardsListMeetingsQueryParams;
        }) => Promise<BaseResponse<DashboardsListMeetingsResponse>>;
        getMeetingDetails: (_: {
            path: DashboardsGetMeetingDetailsPathParams;
        } & object & {
            query?: DashboardsGetMeetingDetailsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetMeetingDetailsResponse>>;
        listMeetingParticipants: (_: {
            path: DashboardsListMeetingParticipantsPathParams;
        } & object & {
            query?: DashboardsListMeetingParticipantsQueryParams;
        }) => Promise<BaseResponse<DashboardsListMeetingParticipantsResponse>>;
        listMeetingParticipantsQoS: (_: {
            path: DashboardsListMeetingParticipantsQoSPathParams;
        } & object & {
            query?: DashboardsListMeetingParticipantsQoSQueryParams;
        }) => Promise<BaseResponse<DashboardsListMeetingParticipantsQoSResponse>>;
        getPostMeetingFeedback: (_: {
            path: DashboardsGetPostMeetingFeedbackPathParams;
        } & object & {
            query?: DashboardsGetPostMeetingFeedbackQueryParams;
        }) => Promise<BaseResponse<DashboardsGetPostMeetingFeedbackResponse>>;
        getMeetingSharingRecordingDetails: (_: {
            path: DashboardsGetMeetingSharingRecordingDetailsPathParams;
        } & object & {
            query?: DashboardsGetMeetingSharingRecordingDetailsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetMeetingSharingRecordingDetailsResponse>>;
        getMeetingParticipantQoS: (_: {
            path: DashboardsGetMeetingParticipantQoSPathParams;
        } & object & {
            query?: DashboardsGetMeetingParticipantQoSQueryParams;
        }) => Promise<BaseResponse<DashboardsGetMeetingParticipantQoSResponse>>;
        getMeetingQualityScores: (_: object & {
            query: DashboardsGetMeetingQualityScoresQueryParams;
        }) => Promise<BaseResponse<DashboardsGetMeetingQualityScoresResponse>>;
        listWebinars: (_: object & {
            query: DashboardsListWebinarsQueryParams;
        }) => Promise<BaseResponse<DashboardsListWebinarsResponse>>;
        getWebinarDetails: (_: {
            path: DashboardsGetWebinarDetailsPathParams;
        } & object & {
            query?: DashboardsGetWebinarDetailsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetWebinarDetailsResponse>>;
        getWebinarParticipants: (_: {
            path: DashboardsGetWebinarParticipantsPathParams;
        } & object & {
            query?: DashboardsGetWebinarParticipantsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetWebinarParticipantsResponse>>;
        listWebinarParticipantQoS: (_: {
            path: DashboardsListWebinarParticipantQoSPathParams;
        } & object & {
            query?: DashboardsListWebinarParticipantQoSQueryParams;
        }) => Promise<BaseResponse<DashboardsListWebinarParticipantQoSResponse>>;
        getPostWebinarFeedback: (_: {
            path: DashboardsGetPostWebinarFeedbackPathParams;
        } & object & {
            query?: DashboardsGetPostWebinarFeedbackQueryParams;
        }) => Promise<BaseResponse<DashboardsGetPostWebinarFeedbackResponse>>;
        getWebinarSharingRecordingDetails: (_: {
            path: DashboardsGetWebinarSharingRecordingDetailsPathParams;
        } & object & {
            query?: DashboardsGetWebinarSharingRecordingDetailsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetWebinarSharingRecordingDetailsResponse>>;
        getWebinarParticipantQoS: (_: {
            path: DashboardsGetWebinarParticipantQoSPathParams;
        } & object & {
            query?: DashboardsGetWebinarParticipantQoSQueryParams;
        }) => Promise<BaseResponse<DashboardsGetWebinarParticipantQoSResponse>>;
        listZoomRooms: (_: object & {
            query?: DashboardsListZoomRoomsQueryParams;
        }) => Promise<BaseResponse<DashboardsListZoomRoomsResponse>>;
        getTopIssuesOfZoomRooms: (_: object & {
            query: DashboardsGetTopIssuesOfZoomRoomsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetTopIssuesOfZoomRoomsResponse>>;
        getZoomRoomsDetails: (_: {
            path: DashboardsGetZoomRoomsDetailsPathParams;
        } & object & {
            query: DashboardsGetZoomRoomsDetailsQueryParams;
        }) => Promise<BaseResponse<DashboardsGetZoomRoomsDetailsResponse>>;
    };
    readonly informationBarriers: {
        listInformationBarrierPolicies: (_: object) => Promise<BaseResponse<InformationBarriersListInformationBarrierPoliciesResponse>>;
        createInformationBarrierPolicy: (_: object & {
            body: InformationBarriersCreateInformationBarrierPolicyRequestBody;
        }) => Promise<BaseResponse<InformationBarriersCreateInformationBarrierPolicyResponse>>;
        getInformationBarrierPolicyByID: (_: {
            path: InformationBarriersGetInformationBarrierPolicyByIDPathParams;
        } & object) => Promise<BaseResponse<InformationBarriersGetInformationBarrierPolicyByIDResponse>>;
        removeInformationBarrierPolicy: (_: {
            path: InformationBarriersRemoveInformationBarrierPolicyPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateInformationBarriersPolicy: (_: {
            path: InformationBarriersUpdateInformationBarriersPolicyPathParams;
        } & {
            body: InformationBarriersUpdateInformationBarriersPolicyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly roles: {
        listRoles: (_: object & {
            query?: RolesListRolesQueryParams;
        }) => Promise<BaseResponse<RolesListRolesResponse>>;
        createRole: (_: object & {
            body?: RolesCreateRoleRequestBody;
        }) => Promise<BaseResponse<RolesCreateRoleResponse>>;
        getRoleInformation: (_: {
            path: RolesGetRoleInformationPathParams;
        } & object) => Promise<BaseResponse<RolesGetRoleInformationResponse>>;
        deleteRole: (_: {
            path: RolesDeleteRolePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateRoleInformation: (_: {
            path: RolesUpdateRoleInformationPathParams;
        } & {
            body?: RolesUpdateRoleInformationRequestBody;
        } & object) => Promise<BaseResponse<RolesUpdateRoleInformationResponse>>;
        listMembersInRole: (_: {
            path: RolesListMembersInRolePathParams;
        } & object & {
            query?: RolesListMembersInRoleQueryParams;
        }) => Promise<BaseResponse<RolesListMembersInRoleResponse>>;
        assignRole: (_: {
            path: RolesAssignRolePathParams;
        } & {
            body?: RolesAssignRoleRequestBody;
        } & object) => Promise<BaseResponse<RolesAssignRoleResponse>>;
        unassignRole: (_: {
            path: RolesUnassignRolePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
}

type AccountVanityUrlRejectedEvent = Event<"account.vanity_url_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            id: string;
            vanity_url: string;
        };
    };
};
type AccountCreatedEvent = Event<"account.created"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operator_id?: string;
        object?: {
            id?: string;
            owner_id?: string;
            email?: string;
        };
    };
};
type InformationBarriersPolicyDeletedEvent = Event<"information_barriers.policy_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            assigned_group_id: string;
            id: string;
            policy_name: string;
            settings: {
                complete_phone_calls: boolean;
                file_transfer: boolean;
                im: boolean;
                in_meeting_chat: boolean;
                meeting: boolean;
                message_via_sms: boolean;
                recording: boolean;
                screen_share: boolean;
            };
            status: number;
            to_group_id: string;
            type: number;
        };
    };
};
type AccountUpdatedEvent = Event<"account.updated"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operation?: string;
        object?: {
            id?: string;
            account_name?: string;
            account_alias?: string;
            account_support_name?: string;
            account_support_email?: string;
            managed_domains?: string[];
        };
        old_object?: {
            $changed_field_name?: string;
        };
    };
};
type InformationBarriersPolicyCreatedEvent = Event<"information_barriers.policy_created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            assigned_group_id: string;
            id: string;
            policy_name: string;
            settings: {
                complete_phone_calls: boolean;
                file_transfer: boolean;
                im: boolean;
                in_meeting_chat: boolean;
                meeting: boolean;
                message_via_sms: boolean;
                recording: boolean;
                screen_share: boolean;
            };
            status: number;
            to_group_id: string;
            type: number;
        };
    };
};
type AccountLockSettingsUpdatedEvent = Event<"account.lock_settings_updated"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operator_id?: string;
        object?: {
            id?: string;
            settings?: {
                schedule_meeting?: {
                    audio_type?: boolean;
                    embed_password_in_join_link?: boolean;
                    enforce_login?: boolean;
                    enforce_login_with_domains?: boolean;
                    host_video?: boolean;
                    join_before_host?: boolean;
                    meeting_authentication?: boolean;
                    not_store_meeting_topic?: boolean;
                    participant_video?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    use_pmi_for_instant_meetings?: boolean;
                    use_pmi_for_scheduled_meetings?: boolean;
                    always_display_zoom_webinar_as_topic?: boolean;
                    meeting_template?: boolean;
                };
                in_meeting?: {
                    alert_guest_join?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_live_streaming?: boolean;
                    allow_show_zoom_windows?: boolean;
                    annotation?: boolean;
                    anonymous_question_answer?: boolean;
                    attendee_on_hold?: boolean;
                    attention_mode_focus_mode?: boolean;
                    auto_answer?: boolean;
                    auto_generated_captions?: boolean;
                    auto_saving_chat?: boolean;
                    breakout_room?: boolean;
                    chat?: boolean;
                    closed_caption?: boolean;
                    co_host?: boolean;
                    custom_data_center_regions?: boolean;
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
                    dscp_marking?: boolean;
                    e2e_encryption?: boolean;
                    far_end_camera_control?: boolean;
                    feedback?: boolean;
                    file_transfer?: boolean;
                    full_transcript?: boolean;
                    group_hd?: boolean;
                    language_interpretation?: boolean;
                    sign_language_interpretation?: boolean;
                    manual_captions?: boolean;
                    meeting_reactions?: boolean;
                    webinar_reactions?: boolean;
                    meeting_survey?: boolean;
                    original_audio?: boolean;
                    polling?: boolean;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    remote_control?: boolean;
                    non_verbal_feedback?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute_participants?: boolean;
                    save_caption?: boolean;
                    save_captions?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
                    stereo_audio?: boolean;
                    use_html_format_email?: boolean;
                    virtual_background?: boolean;
                    webinar_chat?: boolean;
                    webinar_live_streaming?: boolean;
                    webinar_polling?: boolean;
                    webinar_question_answer?: boolean;
                    meeting_question_answer?: boolean;
                    webinar_survey?: boolean;
                    whiteboard?: boolean;
                };
                email_notification?: {
                    alternative_host_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    cloud_recording_available_reminder?: boolean;
                    jbh_reminder?: boolean;
                    schedule_for_reminder?: boolean;
                };
                recording?: {
                    account_user_access_recording?: boolean;
                    auto_delete_cmr?: boolean;
                    auto_recording?: boolean;
                    cloud_recording?: boolean;
                    cloud_recording_download?: boolean;
                    host_delete_cloud_recording?: boolean;
                    ip_address_access_control?: boolean;
                    local_recording?: boolean;
                    recording_authentication?: boolean;
                    archive?: boolean;
                };
                telephony?: {
                    telephony_regions?: boolean;
                    third_party_audio?: boolean;
                };
                audio_conferencing?: {
                    toll_free_and_fee_based_toll_call?: boolean;
                };
                chat?: {
                    share_files?: boolean;
                    chat_emojis?: boolean;
                    record_voice_messages?: boolean;
                    record_video_messages?: boolean;
                    screen_capture?: boolean;
                    share_links_in_chat?: boolean;
                    schedule_meetings_in_chat?: boolean;
                    allow_users_to_add_contacts?: boolean;
                    allow_users_to_chat_with_others?: boolean;
                    chat_etiquette_tool?: boolean;
                    send_data_to_third_party_archiving_service?: boolean;
                    translate_messages?: boolean;
                    search_and_send_animated_gif_images?: boolean;
                };
                other_options?: {
                    blur_snapshot?: boolean;
                    webinar_registration_options?: boolean;
                };
                tsp?: {
                    call_out?: boolean;
                    show_international_numbers_link?: boolean;
                };
                meeting_security?: {
                    approved_or_denied_countries_or_regions?: boolean;
                    auto_security?: boolean;
                    block_user_domain?: boolean;
                    chat_etiquette_tool?: boolean;
                    embed_password_in_join_link?: boolean;
                    encryption_type?: boolean;
                    end_to_end_encrypted_meetings?: boolean;
                    meeting_password?: boolean;
                    only_authenticated_can_join_from_webclient?: boolean;
                    phone_password?: boolean;
                    pmi_password?: boolean;
                    waiting_room?: boolean;
                    webinar_password?: boolean;
                };
            };
        };
        time_stamp?: number;
        old_object?: {
            id?: string;
            settings?: {
                schedule_meeting?: {
                    audio_type?: boolean;
                    embed_password_in_join_link?: boolean;
                    enforce_login?: boolean;
                    enforce_login_with_domains?: boolean;
                    host_video?: boolean;
                    join_before_host?: boolean;
                    meeting_authentication?: boolean;
                    not_store_meeting_topic?: boolean;
                    participant_video?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    use_pmi_for_instant_meetings?: boolean;
                    use_pmi_for_scheduled_meetings?: boolean;
                    always_display_zoom_webinar_as_topic?: boolean;
                    meeting_template?: boolean;
                };
                in_meeting?: {
                    alert_guest_join?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_live_streaming?: boolean;
                    allow_show_zoom_windows?: boolean;
                    annotation?: boolean;
                    anonymous_question_answer?: boolean;
                    attendee_on_hold?: boolean;
                    attention_mode_focus_mode?: boolean;
                    auto_answer?: boolean;
                    auto_generated_captions?: boolean;
                    auto_saving_chat?: boolean;
                    breakout_room?: boolean;
                    chat?: boolean;
                    closed_caption?: boolean;
                    co_host?: boolean;
                    custom_data_center_regions?: boolean;
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
                    dscp_marking?: boolean;
                    e2e_encryption?: boolean;
                    far_end_camera_control?: boolean;
                    feedback?: boolean;
                    file_transfer?: boolean;
                    full_transcript?: boolean;
                    group_hd?: boolean;
                    language_interpretation?: boolean;
                    sign_language_interpretation?: boolean;
                    manual_captions?: boolean;
                    meeting_reactions?: boolean;
                    webinar_reactions?: boolean;
                    meeting_survey?: boolean;
                    original_audio?: boolean;
                    polling?: boolean;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    remote_control?: boolean;
                    non_verbal_feedback?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute_participants?: boolean;
                    save_caption?: boolean;
                    save_captions?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
                    stereo_audio?: boolean;
                    use_html_format_email?: boolean;
                    virtual_background?: boolean;
                    webinar_chat?: boolean;
                    webinar_live_streaming?: boolean;
                    webinar_polling?: boolean;
                    webinar_question_answer?: boolean;
                    meeting_question_answer?: boolean;
                    webinar_survey?: boolean;
                    whiteboard?: boolean;
                };
                email_notification?: {
                    alternative_host_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    cloud_recording_available_reminder?: boolean;
                    jbh_reminder?: boolean;
                    schedule_for_reminder?: boolean;
                };
                recording?: {
                    account_user_access_recording?: boolean;
                    auto_delete_cmr?: boolean;
                    auto_recording?: boolean;
                    cloud_recording?: boolean;
                    cloud_recording_download?: boolean;
                    host_delete_cloud_recording?: boolean;
                    ip_address_access_control?: boolean;
                    local_recording?: boolean;
                    recording_authentication?: boolean;
                    archive?: boolean;
                };
                telephony?: {
                    telephony_regions?: boolean;
                    third_party_audio?: boolean;
                };
                other_options?: {
                    blur_snapshot?: boolean;
                    webinar_registration_options?: boolean;
                };
                audio_conferencing?: {
                    toll_free_and_fee_based_toll_call?: boolean;
                };
                chat?: {
                    share_files?: boolean;
                    chat_emojis?: boolean;
                    record_voice_messages?: boolean;
                    record_video_messages?: boolean;
                    screen_capture?: boolean;
                    share_links_in_chat?: boolean;
                    schedule_meetings_in_chat?: boolean;
                    allow_users_to_add_contacts?: boolean;
                    allow_users_to_chat_with_others?: boolean;
                    chat_etiquette_tool?: boolean;
                    send_data_to_third_party_archiving_service?: boolean;
                    translate_messages?: boolean;
                    search_and_send_animated_gif_images?: boolean;
                };
                meeting_security?: {
                    approved_or_denied_countries_or_regions?: boolean;
                    auto_security?: boolean;
                    block_user_domain?: boolean;
                    chat_etiquette_tool?: boolean;
                    embed_password_in_join_link?: boolean;
                    encryption_type?: boolean;
                    end_to_end_encrypted_meetings?: boolean;
                    meeting_password?: boolean;
                    only_authenticated_can_join_from_webclient?: boolean;
                    phone_password?: boolean;
                    pmi_password?: boolean;
                    waiting_room?: boolean;
                    webinar_password?: boolean;
                };
                tsp?: {
                    share_files?: boolean;
                    chat_emojis?: boolean;
                    record_voice_messages?: boolean;
                    record_video_messages?: boolean;
                    screen_capture?: boolean;
                    share_links_in_chat?: boolean;
                    schedule_meetings_in_chat?: boolean;
                    allow_users_to_add_contacts?: boolean;
                    allow_users_to_chat_with_others?: boolean;
                    chat_etiquette_tool?: boolean;
                    send_data_to_third_party_archiving_service?: boolean;
                    translate_messages?: boolean;
                    search_and_send_animated_gif_images?: boolean;
                };
            };
        };
    };
};
type AccountDisassociatedEvent = Event<"account.disassociated"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operator_id?: string;
        object?: {
            id?: string;
            owner_id?: string;
            owner_email?: string;
        };
    };
};
type InformationBarriersPolicyUpdatedEvent = Event<"information_barriers.policy_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            assigned_group_id: string;
            policy_name: string;
            settings: {
                complete_phone_calls: boolean;
                file_transfer: boolean;
                im: boolean;
                in_meeting_chat: boolean;
                meeting: boolean;
                message_via_sms: boolean;
                recording: boolean;
                screen_share: boolean;
            };
            status: number;
            to_group_id: string;
            type: number;
        };
    };
};
type AccountVanityUrlApprovedEvent = Event<"account.vanity_url_approved"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        object: {
            id: string;
            vanity_url: string;
        };
    };
};
type AccountSettingsUpdatedEvent = Event<"account.settings_updated"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operator_id?: string;
        object?: {
            id?: string;
            settings?: {
                schedule_meeting?: {
                    host_video?: boolean;
                    participant_video?: boolean;
                    audio_type?: string;
                    join_before_host?: boolean;
                    enforce_login?: boolean;
                    enforce_login_with_domains?: boolean;
                    enforce_login_domains?: string;
                    not_store_meeting_topic?: boolean;
                    force_pmi_jbh_password?: boolean;
                    use_pmi_for_scheduled_meetings?: boolean;
                    pstn_password_protected?: string;
                    jbh_time?: number;
                    personal_meeting?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    mute_upon_entry?: boolean;
                    require_password_for_pmi_meetings?: string;
                    use_pmi_for_instant_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    pmi_password?: string;
                    upcoming_meeting_reminder?: boolean;
                    always_display_zoom_meeting_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_meetings?: boolean;
                    };
                    hide_meeting_description?: {
                        enable?: boolean;
                        hide_description_for_scheduled_meetings?: boolean;
                    };
                    always_display_zoom_webinar_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_webinars?: boolean;
                    };
                    hide_webinar_description?: {
                        enable?: boolean;
                        hide_description_for_scheduled_webinars?: boolean;
                    };
                };
                in_meeting?: {
                    e2e_encryption?: boolean;
                    chat?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_participants_chat_with?: number;
                    allow_users_save_chats?: number;
                    private_chat?: boolean;
                    auto_saving_chat?: boolean;
                    file_transfer?: boolean;
                    feedback?: boolean;
                    post_meeting_feedback?: boolean;
                    co_host?: boolean;
                    polling?: boolean;
                    meeting_polling?: {
                        enable?: boolean;
                        advanced_polls?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        manage_saved_polls_and_quizzes?: boolean;
                        allow_host_to_upload_image?: boolean;
                    };
                    attendee_on_hold?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    allow_show_zoom_windows?: boolean;
                    annotation?: boolean;
                    whiteboard?: boolean;
                    webinar_question_answer?: boolean;
                    meeting_question_answer?: boolean;
                    anonymous_question_answer?: boolean;
                    breakout_room?: boolean;
                    breakout_room_schedule?: boolean;
                    closed_caption?: boolean;
                    far_end_camera_control?: boolean;
                    group_hd?: boolean;
                    virtual_background?: boolean;
                    watermark?: boolean;
                    watermark_by_default?: boolean;
                    audio_watermark_by_default?: boolean;
                    attention_mode_focus_mode?: boolean;
                    allow_host_to_enable_focus_mode?: boolean;
                    alert_guest_join?: boolean;
                    auto_answer?: boolean;
                    p2p_connetion?: boolean;
                    p2p_ports?: boolean;
                    ports_range?: string;
                    sending_default_email_invites?: boolean;
                    use_html_format_email?: boolean;
                    dscp_marking?: boolean;
                    dscp_audio?: number;
                    dscp_video?: number;
                    stereo_audio?: boolean;
                    original_audio?: boolean;
                    screen_sharing?: boolean;
                    remote_control?: boolean;
                    non_verbal_feedback?: boolean;
                    remote_support?: boolean;
                    custom_data_center_regions?: boolean;
                    data_center_regions?: string[];
                    language_interpretation?: {
                        enable?: boolean;
                        enable_language_interpretation_by_default?: boolean;
                        allow_participants_to_speak_in_listening_channel?: boolean;
                        allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
                        languages?: string[];
                        custom_languages?: string[];
                    };
                    sign_language_interpretation?: {
                        enable?: boolean;
                        enable_sign_language_interpretation_by_default?: boolean;
                        languages?: string[];
                        custom_languages?: string[];
                    };
                    meeting_reactions?: boolean;
                    meeting_reactions_emojis?: string;
                    allow_host_panelists_to_use_audible_clap?: boolean;
                    webinar_reactions?: boolean;
                    show_a_join_from_your_browser_link?: boolean;
                    join_from_mobile?: boolean;
                    join_from_desktop?: boolean;
                    allow_live_streaming?: boolean;
                    live_streaming_facebook?: boolean;
                    workplace_by_facebook?: boolean;
                    live_streaming_youtube?: boolean;
                    custom_live_streaming_service?: boolean;
                    custom_service_instructions?: string;
                    webinar_live_streaming?: {
                        enable?: boolean;
                        live_streaming_service?: string[];
                        custom_service_instructions?: string;
                        live_streaming_reminder?: boolean;
                    };
                    webinar_chat?: {
                        enable?: boolean;
                        allow_panelists_chat_with?: number;
                        allow_attendees_chat_with?: number;
                        default_attendees_chat_with?: number;
                        allow_panelists_send_direct_message?: boolean;
                        allow_users_save_chats?: number;
                        allow_auto_save_local_chat_file?: boolean;
                    };
                    closed_captioning?: {
                        enable?: boolean;
                        third_party_captioning_service?: boolean;
                        auto_transcribing?: boolean;
                        view_full_transcript?: boolean;
                        save_caption?: boolean;
                    };
                    slide_control?: boolean;
                    meeting_survey?: boolean;
                    webinar_polling?: {
                        enable?: boolean;
                        advanced_polls?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        manage_saved_polls_and_quizzes?: boolean;
                        allow_host_to_upload_image?: boolean;
                    };
                    webinar_survey?: boolean;
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
                    who_can_share_screen?: string;
                    who_can_share_screen_when_someone_is_sharing?: string;
                    participants_share_simultaneously?: string;
                };
                email_notification?: {
                    cloud_recording_available_reminder?: boolean;
                    recording_available_reminder_schedulers?: boolean;
                    recording_available_reminder_alternative_hosts?: boolean;
                    jbh_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    low_host_count_reminder?: boolean;
                    alternative_host_reminder?: boolean;
                    schedule_for_reminder?: boolean;
                };
                zoom_rooms?: {
                    upcoming_meeting_alert?: boolean;
                    start_airplay_manually?: boolean;
                    weekly_system_restart?: boolean;
                    list_meetings_with_calendar?: boolean;
                    zr_post_meeting_feedback?: boolean;
                    ultrasonic?: boolean;
                    force_private_meeting?: boolean;
                    hide_host_information?: boolean;
                    cmr_for_instant_meeting?: boolean;
                    auto_start_stop_scheduled_meetings?: boolean;
                };
                security?: {
                    admin_change_name_pic?: boolean;
                    import_photos_from_devices?: boolean;
                    hide_billing_info?: boolean;
                    password_requirement?: {
                        minimum_password_length?: number;
                        have_special_character?: boolean;
                        consecutive_characters_length?: number;
                        weak_enhance_detection?: boolean;
                    };
                    signin_with_sso?: {
                        enable?: boolean;
                        require_sso_for_domains?: boolean;
                        domains?: string[];
                        sso_bypass_users?: {
                            id?: string;
                            email?: string;
                        }[];
                    };
                };
                recording?: {
                    local_recording?: boolean;
                    cloud_recording?: boolean;
                    record_speaker_view?: boolean;
                    record_gallery_view?: boolean;
                    record_audio_file?: boolean;
                    save_chat_text?: boolean;
                    show_timestamp?: boolean;
                    recording_audio_transcript?: boolean;
                    auto_recording?: string;
                    cloud_recording_download?: boolean;
                    cloud_recording_download_host?: boolean;
                    account_user_access_recording?: boolean;
                    auto_delete_cmr?: boolean;
                    auto_delete_cmr_days?: number;
                    record_files_separately?: {
                        active_speaker?: boolean;
                        gallery_view?: boolean;
                        shared_screen?: boolean;
                    };
                    display_participant_name?: boolean;
                    recording_thumbnails?: boolean;
                    optimize_recording_for_3rd_party_video_editor?: boolean;
                    recording_highlight?: boolean;
                    smart_recording?: {
                        create_recording_highlights?: boolean;
                        create_smart_chapters?: boolean;
                        create_next_steps?: boolean;
                    };
                    save_panelist_chat?: boolean;
                    save_poll_results?: boolean;
                    save_close_caption?: boolean;
                    record_audio_file_each_participant?: boolean;
                    host_pause_stop_recording?: boolean;
                    recording_disclaimer?: boolean;
                    ask_participants_to_consent_disclaimer?: boolean;
                    ask_host_to_confirm_disclaimer?: boolean;
                    recording_password_requirement?: {
                        length?: number;
                        have_letter?: boolean;
                        have_number?: boolean;
                        have_special_character?: boolean;
                        only_allow_numeric?: boolean;
                    };
                    ip_address_access_control?: {
                        enable?: boolean;
                        ip_addresses_or_ranges?: string;
                    };
                    prevent_host_access_recording?: boolean;
                    host_delete_cloud_recording?: boolean;
                    allow_recovery_deleted_cloud_recordings?: boolean;
                    archive?: {
                        enable?: boolean;
                        type?: number;
                        settings?: {
                            chat_file?: boolean;
                            chat_with_sender_email?: boolean;
                            audio_file?: boolean;
                            video_file?: boolean;
                            cc_transcript_file?: boolean;
                            chat_with_direct_message?: boolean;
                            archive_retention?: number;
                            action_when_archive_failed?: number;
                            notification_when_archiving_starts?: string;
                            play_voice_prompt_when_archiving_starts?: string;
                        };
                    };
                };
                telephony?: {
                    third_party_audio?: boolean;
                    audio_conference_info?: string;
                    telephony_regions?: {
                        allowed_values?: string[];
                        selection_values?: string;
                    };
                };
                integration?: {
                    google_calendar?: boolean;
                    google_drive?: boolean;
                    dropbox?: boolean;
                    box?: boolean;
                    microsoft_one_drive?: boolean;
                    kubi?: boolean;
                };
                feature?: {
                    meeting_capacity?: number;
                };
                other_options?: {
                    allow_auto_active_users?: boolean;
                    blur_snapshot?: boolean;
                    display_meetings_scheduled_for_others?: boolean;
                    use_cdn?: string;
                    allow_users_contact_support_via_chat?: boolean;
                    show_one_user_meeting_on_dashboard?: boolean;
                    meeting_qos_and_mos?: number;
                    allow_users_enter_and_share_pronouns?: boolean;
                    webinar_registration_options?: {
                        allow_host_to_enable_social_share_buttons?: boolean;
                    };
                };
                audio_conferencing?: {
                    toll_free_and_fee_based_toll_call?: {
                        enable?: boolean;
                        numbers?: {
                            code?: string;
                            country_code?: string;
                            country_name?: string;
                            number?: string;
                            display_number?: string;
                        }[];
                        allow_webinar_attendees_dial?: boolean;
                    };
                };
                chat?: {
                    allow_bots_chat?: boolean;
                    share_files?: {
                        enable?: boolean;
                        share_option?: string;
                        restrictions?: {
                            only_allow_specific_file_types?: boolean;
                            file_type_restrictions?: string[];
                            file_type_restrictions_for_external?: string[];
                            maximum_file_size?: boolean;
                            file_size_restrictions?: number;
                            file_size_restrictions_for_external?: number;
                        };
                    };
                    chat_emojis?: {
                        enable?: boolean;
                        emojis_option?: string;
                    };
                    record_voice_messages?: boolean;
                    record_video_messages?: boolean;
                    screen_capture?: boolean;
                    create_public_channels?: boolean;
                    create_private_channels?: boolean;
                    share_links_in_chat?: boolean;
                    schedule_meetings_in_chat?: boolean;
                    set_retention_period_in_cloud?: {
                        enable?: boolean;
                        retention_period_of_direct_messages_and_group_conversation?: string;
                        retention_period_of_channels?: string;
                    };
                    set_retention_period_in_local?: {
                        enable?: boolean;
                        retention_period_of_direct_messages_and_group_conversation?: string;
                        retention_period_of_channels?: string;
                    };
                    allow_users_to_add_contacts?: {
                        enable?: boolean;
                        selected_option?: number;
                        user_email_addresses?: string;
                    };
                    allow_users_to_chat_with_others?: {
                        enable?: boolean;
                        selected_option?: number;
                        user_email_addresses?: string;
                    };
                    chat_etiquette_tool?: {
                        enable?: boolean;
                        policies?: {
                            description?: string;
                            id?: string;
                            is_locked?: boolean;
                            keywords?: string[];
                            name?: string;
                            regular_expression?: string;
                            status?: string;
                            trigger_action?: number;
                        }[];
                        policy_max_count?: number;
                    };
                    send_data_to_third_party_archiving_service?: {
                        enable?: boolean;
                        type?: string;
                        smtp_delivery_address?: string;
                        user_name?: string;
                        passcode?: string;
                        authorized_channel_token?: string;
                    };
                    apply_local_storage_to_personal_channel?: {
                        enable?: boolean;
                        retention_period?: string;
                    };
                    translate_messages?: boolean;
                    search_and_send_animated_gif_images?: {
                        enable?: boolean;
                        giphy_content_rating?: number;
                    };
                };
                meeting_security?: {
                    auto_security?: boolean;
                    waiting_room?: boolean;
                    waiting_room_settings?: {
                        participants_to_place_in_waiting_room?: number;
                        whitelisted_domains_for_waiting_room?: string;
                        users_who_can_admit_participants_from_waiting_room?: number;
                    };
                    meeting_password?: boolean;
                    require_password_for_scheduled_meeting?: boolean;
                    pmi_password?: boolean;
                    phone_password?: boolean;
                    webinar_password?: boolean;
                    require_password_for_scheduled_webinar?: boolean;
                    meeting_password_requirement?: {
                        length?: number;
                        have_letter?: boolean;
                        have_number?: boolean;
                        have_special_character?: boolean;
                        only_allow_numeric?: boolean;
                        have_upper_and_lower_characters?: boolean;
                        consecutive_characters_length?: number;
                        weak_enhance_detection?: boolean;
                    };
                    embed_password_in_join_link?: boolean;
                    end_to_end_encrypted_meetings?: boolean;
                    encryption_type?: string;
                    block_user_domain?: boolean;
                    block_user_domain_list?: string[];
                    only_authenticated_can_join_from_webclient?: boolean;
                    chat_etiquette_tool?: {
                        enable?: boolean;
                        policies?: {
                            id?: string;
                            name?: string;
                            description?: string;
                            trigger_action?: number;
                            keywords?: string[];
                            regular_expression?: string;
                            status?: string;
                            is_locked?: boolean;
                        }[];
                    };
                };
                in_session?: {
                    custom_data_center_regions?: boolean;
                    data_center_regions?: string[];
                    p2p_connetion?: boolean;
                    p2p_ports?: boolean;
                    ports_range?: string;
                    dscp_audio?: number;
                    dscp_marking?: boolean;
                    dscp_video?: number;
                    dscp_dual?: boolean;
                    subsession?: boolean;
                };
                session_security?: {
                    approved_or_denied_countries_or_regions?: {
                        approved_list?: string[];
                        denied_list?: string[];
                        enable?: boolean;
                        method?: string;
                    };
                };
            };
        };
        time_stamp?: number;
    };
};
type AccountsEvents = AccountVanityUrlRejectedEvent | AccountCreatedEvent | InformationBarriersPolicyDeletedEvent | AccountUpdatedEvent | InformationBarriersPolicyCreatedEvent | AccountLockSettingsUpdatedEvent | AccountDisassociatedEvent | InformationBarriersPolicyUpdatedEvent | AccountVanityUrlApprovedEvent | AccountSettingsUpdatedEvent;
declare class AccountsEventProcessor extends EventManager<AccountsEndpoints, AccountsEvents> {
}

type AccountsOptions<R extends Receiver> = CommonClientOptions<OAuth, R>;
declare class AccountsOAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<OAuth, ReceiverType> = AccountsOptions<ReceiverType>> extends ProductClient<OAuth, AccountsEndpoints, AccountsEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, ...restOptions }: OptionsType): OAuth;
    protected initEndpoints(auth: OAuth, options: OptionsType): AccountsEndpoints;
    protected initEventProcessor(endpoints: AccountsEndpoints): AccountsEventProcessor;
}

type AccountsS2SAuthOptions<R extends Receiver> = CommonClientOptions<S2SAuth, R>;
declare class AccountsS2SAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<S2SAuth, ReceiverType> = AccountsS2SAuthOptions<ReceiverType>> extends ProductClient<S2SAuth, AccountsEndpoints, AccountsEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, accountId }: OptionsType): S2SAuth;
    protected initEndpoints(auth: S2SAuth, options: OptionsType): AccountsEndpoints;
    protected initEventProcessor(endpoints: AccountsEndpoints): AccountsEventProcessor;
}

export { type AccountCreatedEvent, type AccountDisassociatedEvent, type AccountLockSettingsUpdatedEvent, type AccountSettingsUpdatedEvent, type AccountUpdatedEvent, type AccountVanityUrlApprovedEvent, type AccountVanityUrlRejectedEvent, type AccountsDeleteVirtualBackgroundFilesPathParams, type AccountsDeleteVirtualBackgroundFilesQueryParams, AccountsEndpoints, AccountsEventProcessor, type AccountsGetAccountSettingsPathParams, type AccountsGetAccountSettingsQueryParams, type AccountsGetAccountSettingsResponse, type AccountsGetAccountsManagedDomainsPathParams, type AccountsGetAccountsManagedDomainsResponse, type AccountsGetAccountsTrustedDomainsPathParams, type AccountsGetAccountsTrustedDomainsResponse, type AccountsGetAccountsWebinarRegistrationSettingsPathParams, type AccountsGetAccountsWebinarRegistrationSettingsQueryParams, type AccountsGetAccountsWebinarRegistrationSettingsResponse, type AccountsGetLockedSettingsPathParams, type AccountsGetLockedSettingsQueryParams, type AccountsGetLockedSettingsResponse, AccountsOAuthClient, type AccountsOptions, AccountsS2SAuthClient, type AccountsS2SAuthOptions, type AccountsUpdateAccountOwnerPathParams, type AccountsUpdateAccountOwnerRequestBody, type AccountsUpdateAccountSettingsPathParams, type AccountsUpdateAccountSettingsQueryParams, type AccountsUpdateAccountSettingsRequestBody, type AccountsUpdateAccountsWebinarRegistrationSettingsPathParams, type AccountsUpdateAccountsWebinarRegistrationSettingsQueryParams, type AccountsUpdateAccountsWebinarRegistrationSettingsRequestBody, type AccountsUpdateLockedSettingsPathParams, type AccountsUpdateLockedSettingsRequestBody, type AccountsUploadVirtualBackgroundFilesPathParams, type AccountsUploadVirtualBackgroundFilesRequestBody, type AccountsUploadVirtualBackgroundFilesResponse, ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, type ClientCredentialsToken, CommonHttpRequestError, ConsoleLogger, type DashboardsGetCRCPortUsageQueryParams, type DashboardsGetCRCPortUsageResponse, type DashboardsGetChatMetricsQueryParams, type DashboardsGetChatMetricsResponse, type DashboardsGetIssuesOfZoomRoomsPathParams, type DashboardsGetIssuesOfZoomRoomsQueryParams, type DashboardsGetIssuesOfZoomRoomsResponse, type DashboardsGetMeetingDetailsPathParams, type DashboardsGetMeetingDetailsQueryParams, type DashboardsGetMeetingDetailsResponse, type DashboardsGetMeetingParticipantQoSPathParams, type DashboardsGetMeetingParticipantQoSQueryParams, type DashboardsGetMeetingParticipantQoSResponse, type DashboardsGetMeetingQualityScoresQueryParams, type DashboardsGetMeetingQualityScoresResponse, type DashboardsGetMeetingSharingRecordingDetailsPathParams, type DashboardsGetMeetingSharingRecordingDetailsQueryParams, type DashboardsGetMeetingSharingRecordingDetailsResponse, type DashboardsGetPostMeetingFeedbackPathParams, type DashboardsGetPostMeetingFeedbackQueryParams, type DashboardsGetPostMeetingFeedbackResponse, type DashboardsGetPostWebinarFeedbackPathParams, type DashboardsGetPostWebinarFeedbackQueryParams, type DashboardsGetPostWebinarFeedbackResponse, type DashboardsGetTopIssuesOfZoomRoomsQueryParams, type DashboardsGetTopIssuesOfZoomRoomsResponse, type DashboardsGetTopZoomRoomsWithIssuesQueryParams, type DashboardsGetTopZoomRoomsWithIssuesResponse, type DashboardsGetWebinarDetailsPathParams, type DashboardsGetWebinarDetailsQueryParams, type DashboardsGetWebinarDetailsResponse, type DashboardsGetWebinarParticipantQoSPathParams, type DashboardsGetWebinarParticipantQoSQueryParams, type DashboardsGetWebinarParticipantQoSResponse, type DashboardsGetWebinarParticipantsPathParams, type DashboardsGetWebinarParticipantsQueryParams, type DashboardsGetWebinarParticipantsResponse, type DashboardsGetWebinarSharingRecordingDetailsPathParams, type DashboardsGetWebinarSharingRecordingDetailsQueryParams, type DashboardsGetWebinarSharingRecordingDetailsResponse, type DashboardsGetZoomMeetingsClientFeedbackPathParams, type DashboardsGetZoomMeetingsClientFeedbackQueryParams, type DashboardsGetZoomMeetingsClientFeedbackResponse, type DashboardsGetZoomRoomsDetailsPathParams, type DashboardsGetZoomRoomsDetailsQueryParams, type DashboardsGetZoomRoomsDetailsResponse, type DashboardsListClientMeetingSatisfactionQueryParams, type DashboardsListClientMeetingSatisfactionResponse, type DashboardsListClientVersionsResponse, type DashboardsListMeetingParticipantsPathParams, type DashboardsListMeetingParticipantsQoSPathParams, type DashboardsListMeetingParticipantsQoSQueryParams, type DashboardsListMeetingParticipantsQoSResponse, type DashboardsListMeetingParticipantsQueryParams, type DashboardsListMeetingParticipantsResponse, type DashboardsListMeetingsQueryParams, type DashboardsListMeetingsResponse, type DashboardsListWebinarParticipantQoSPathParams, type DashboardsListWebinarParticipantQoSQueryParams, type DashboardsListWebinarParticipantQoSResponse, type DashboardsListWebinarsQueryParams, type DashboardsListWebinarsResponse, type DashboardsListZoomMeetingsClientFeedbackQueryParams, type DashboardsListZoomMeetingsClientFeedbackResponse, type DashboardsListZoomRoomsQueryParams, type DashboardsListZoomRoomsResponse, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, type HttpReceiverOptions, type InformationBarriersCreateInformationBarrierPolicyRequestBody, type InformationBarriersCreateInformationBarrierPolicyResponse, type InformationBarriersGetInformationBarrierPolicyByIDPathParams, type InformationBarriersGetInformationBarrierPolicyByIDResponse, type InformationBarriersListInformationBarrierPoliciesResponse, type InformationBarriersPolicyCreatedEvent, type InformationBarriersPolicyDeletedEvent, type InformationBarriersPolicyUpdatedEvent, type InformationBarriersRemoveInformationBarrierPolicyPathParams, type InformationBarriersUpdateInformationBarriersPolicyPathParams, type InformationBarriersUpdateInformationBarriersPolicyRequestBody, type JwtToken, LogLevel, type Logger, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, type OAuthToken, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, type Receiver, ReceiverInconsistentStateError, type ReceiverInitOptions, ReceiverOAuthFlowError, type RolesAssignRolePathParams, type RolesAssignRoleRequestBody, type RolesAssignRoleResponse, type RolesCreateRoleRequestBody, type RolesCreateRoleResponse, type RolesDeleteRolePathParams, type RolesGetRoleInformationPathParams, type RolesGetRoleInformationResponse, type RolesListMembersInRolePathParams, type RolesListMembersInRoleQueryParams, type RolesListMembersInRoleResponse, type RolesListRolesQueryParams, type RolesListRolesResponse, type RolesUnassignRolePathParams, type RolesUpdateRoleInformationPathParams, type RolesUpdateRoleInformationRequestBody, type RolesUpdateRoleInformationResponse, type S2SAuthToken, S2SRawResponseError, type StateStore, StatusCode, type TokenStore, isCoreError, isStateStore };
