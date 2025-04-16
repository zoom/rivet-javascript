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

type ContactGroupsListContactGroupsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type ContactGroupsListContactGroupsResponse = {
    groups?: {
        group_id?: string;
        group_name?: string;
        group_privacy?: number;
        description?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ContactGroupsCreateContactGroupRequestBody = {
    group_name?: string;
    group_privacy?: number;
    description?: string;
    group_members?: {
        type?: number;
        id?: string;
    }[];
};
type ContactGroupsCreateContactGroupResponse = {
    group_id?: string;
    group_name?: string;
    total_members?: number;
    group_privacy?: number;
    description?: string;
};
type ContactGroupsGetContactGroupPathParams = {
    groupId: string;
};
type ContactGroupsGetContactGroupResponse = {
    group_id?: string;
    group_name?: string;
    total_members?: number;
    group_privacy?: number;
    description?: string;
};
type ContactGroupsDeleteContactGroupPathParams = {
    groupId: string;
};
type ContactGroupsUpdateContactGroupPathParams = {
    groupId: string;
};
type ContactGroupsUpdateContactGroupRequestBody = {
    name?: string;
    privacy?: number;
    description?: string;
};
type ContactGroupsListContactGroupMembersPathParams = {
    groupId: string;
};
type ContactGroupsListContactGroupMembersQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type ContactGroupsListContactGroupMembersResponse = {
    members?: {
        type?: number;
        id?: string;
        name?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ContactGroupsAddContactGroupMembersPathParams = {
    groupId: string;
};
type ContactGroupsAddContactGroupMembersRequestBody = {
    group_members?: {
        type?: number;
        id?: string;
    }[];
};
type ContactGroupsAddContactGroupMembersResponse = {
    member_ids?: string[];
};
type ContactGroupsRemoveMembersInContactGroupPathParams = {
    groupId: string;
};
type ContactGroupsRemoveMembersInContactGroupQueryParams = {
    member_ids: string;
};
type GroupsListGroupsResponse = {
    groups?: ({
        id?: string;
    } & {
        name?: string;
        total_members?: number;
    })[];
    total_records?: number;
};
type GroupsCreateGroupRequestBody = {
    name?: string;
};
type GroupsGetGroupPathParams = {
    groupId: string;
};
type GroupsGetGroupResponse = {
    id?: string;
    name?: string;
    total_members?: number;
};
type GroupsDeleteGroupPathParams = {
    groupId: string;
};
type GroupsUpdateGroupPathParams = {
    groupId: string;
};
type GroupsUpdateGroupRequestBody = {
    name?: string;
};
type GroupsListGroupAdminsPathParams = {
    groupId: string;
};
type GroupsListGroupAdminsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type GroupsListGroupAdminsResponse = {
    admins?: {
        email?: string;
        name?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
};
type GroupsAddGroupAdminsPathParams = {
    groupId: string;
};
type GroupsAddGroupAdminsRequestBody = {
    admins?: {
        email?: string;
        id?: string;
    }[];
};
type GroupsDeleteGroupAdminPathParams = {
    groupId: string;
    userId: string;
};
type GroupsListGroupChannelsPathParams = {
    groupId: string;
};
type GroupsListGroupChannelsResponse = {
    channels: {
        channel_id: string;
        channel_name: string;
        member_count: number;
    }[];
    group_id: string;
};
type GroupsGetLockedSettingsPathParams = {
    groupId: string;
};
type GroupsGetLockedSettingsQueryParams = {
    option?: string;
};
type GroupsGetLockedSettingsResponse = {
    audio_conferencing?: {
        toll_free_and_fee_based_toll_call?: boolean;
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
        attendee_on_hold?: boolean;
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
        non_verbal_feedback?: boolean;
        original_audio?: boolean;
        polling?: boolean;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        remote_control?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        save_caption?: boolean;
        save_captions?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_browser_join_link?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        stereo_audio?: boolean;
        use_html_format_email?: boolean;
        virtual_background?: boolean;
        waiting_room?: boolean;
        webinar_chat?: boolean;
        webinar_live_streaming?: boolean;
        webinar_polling?: boolean;
        webinar_question_answer?: boolean;
        webinar_survey?: boolean;
        whiteboard?: boolean;
    };
    other_options?: {
        blur_snapshot?: boolean;
    };
    recording?: {
        account_user_access_recording?: boolean;
        auto_delete_cmr?: boolean;
        auto_recording?: boolean;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        host_delete_cloud_recording?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        prevent_host_access_recording?: boolean;
        recording_authentication?: boolean;
        archive?: boolean;
    };
    schedule_meeting?: {
        audio_type?: boolean;
        embed_password_in_join_link?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
        join_before_host?: boolean;
        meeting_authentication?: boolean;
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        pstn_password_protected?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        upcoming_meeting_reminder?: boolean;
        continuous_meeting_chat?: boolean;
    };
    telephony?: {
        telephony_regions?: boolean;
        third_party_audio?: boolean;
    };
} | {
    meeting_security?: {
        approved_or_denied_countries_or_regions?: boolean;
        auto_security?: boolean;
        block_user_domain?: boolean;
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
type GroupsUpdateLockedSettingsPathParams = {
    groupId: string;
};
type GroupsUpdateLockedSettingsQueryParams = {
    option?: string;
};
type GroupsUpdateLockedSettingsRequestBody = {
    audio_conferencing?: {
        toll_free_and_fee_based_toll_call?: boolean;
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
        attendee_on_hold?: boolean;
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
        non_verbal_feedback?: boolean;
        original_audio?: boolean;
        polling?: boolean;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        remote_control?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        save_caption?: boolean;
        save_captions?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_browser_join_link?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        stereo_audio?: boolean;
        use_html_format_email?: boolean;
        virtual_background?: boolean;
        waiting_room?: boolean;
        webinar_chat?: boolean;
        webinar_live_streaming?: boolean;
        webinar_polling?: boolean;
        webinar_question_answer?: boolean;
        webinar_survey?: boolean;
        whiteboard?: boolean;
    };
    other_options?: {
        blur_snapshot?: boolean;
    };
    recording?: {
        account_user_access_recording?: boolean;
        auto_delete_cmr?: boolean;
        auto_recording?: boolean;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        host_delete_cloud_recording?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        recording_authentication?: boolean;
        archive?: boolean;
    };
    schedule_meeting?: {
        audio_type?: boolean;
        embed_password_in_join_link?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
        join_before_host?: boolean;
        meeting_authentication?: boolean;
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        personal_meeting?: boolean;
        pstn_password_protected?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        upcoming_meeting_reminder?: boolean;
        continuous_meeting_chat?: boolean;
    };
    telephony?: {
        telephony_regions?: boolean;
        third_party_audio?: boolean;
    };
} | {
    meeting_security?: {
        approved_or_denied_countries_or_regions?: boolean;
        auto_security?: boolean;
        block_user_domain?: boolean;
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
type GroupsListGroupMembersPathParams = {
    groupId: string;
};
type GroupsListGroupMembersQueryParams = {
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type GroupsListGroupMembersResponse = {
    members?: {
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
type GroupsAddGroupMembersPathParams = {
    groupId: string;
};
type GroupsAddGroupMembersRequestBody = {
    members?: {
        email?: string;
        id?: string;
    }[];
};
type GroupsDeleteGroupMemberPathParams = {
    groupId: string;
    memberId: string;
};
type GroupsUpdateGroupMemberPathParams = {
    groupId: string;
    memberId: string;
};
type GroupsUpdateGroupMemberRequestBody = {
    action: string;
    target_group_id?: string;
};
type GroupsGetGroupsSettingsPathParams = {
    groupId: string;
};
type GroupsGetGroupsSettingsQueryParams = {
    option?: string;
    custom_query_fields?: string;
};
type GroupsGetGroupsSettingsResponse = {
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
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        recording_available_reminder_alternative_hosts?: boolean;
        recording_available_reminder_schedulers?: boolean;
        schedule_for_reminder?: boolean;
    };
    in_meeting?: {
        alert_guest_join?: boolean;
        allow_users_to_delete_messages_in_meeting_chat?: boolean;
        allow_live_streaming?: boolean;
        allow_participants_chat_with?: number;
        allow_show_zoom_windows?: boolean;
        allow_users_save_chats?: number;
        annotation?: boolean;
        attendee_on_hold?: boolean;
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
        data_center_regions?: string[];
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
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
        meeting_reactions?: boolean;
        meeting_reactions_emojis?: string;
        allow_host_panelists_to_use_audible_clap?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        non_verbal_feedback?: boolean;
        only_host_view_device_list?: boolean;
        original_audio?: boolean;
        polling?: boolean;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        record_play_own_voice?: boolean;
        remote_control?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_browser_join_link?: boolean;
        show_device_list?: boolean;
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
        waiting_room?: boolean;
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
        meeting_polling?: {
            enable?: boolean;
            advanced_polls?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            require_answers_to_be_anonymous?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            allow_host_to_upload_image?: boolean;
        };
        webinar_polling?: {
            enable?: boolean;
            advanced_polls?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            require_answers_to_be_anonymous?: boolean;
            allow_host_to_upload_image?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
        };
        webinar_question_answer?: boolean;
        webinar_survey?: boolean;
        whiteboard?: boolean;
        who_can_share_screen?: string;
        who_can_share_screen_when_someone_is_sharing?: string;
        participants_share_simultaneously?: string;
        workplace_by_facebook?: boolean;
    };
    other_options?: {
        allow_users_contact_support_via_chat?: boolean;
        blur_snapshot?: boolean;
        webinar_registration_options?: {
            allow_host_to_enable_join_info?: boolean;
            allow_host_to_enable_social_share_buttons?: boolean;
            enable_custom_questions?: boolean;
        };
    };
    profile?: {
        recording_storage_location?: {
            allowed_values?: string[];
            value?: string;
        };
    };
    recording?: {
        account_user_access_recording?: boolean;
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
        auto_recording?: string;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        cloud_recording_download_host?: boolean;
        host_delete_cloud_recording?: boolean;
        record_files_separately?: {
            active_speaker?: boolean;
            gallery_view?: boolean;
            shared_screen?: boolean;
        };
        display_participant_name?: boolean;
        recording_thumbnails?: boolean;
        optimize_recording_for_3rd_party_video_editor?: boolean;
        recording_highlight?: boolean;
        save_panelist_chat?: boolean;
        save_poll_results?: boolean;
        save_close_caption?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        prevent_host_access_recording?: boolean;
        record_audio_file?: boolean;
        record_gallery_view?: boolean;
        record_speaker_view?: boolean;
        recording_audio_transcript?: boolean;
        smart_recording?: {
            create_recording_highlights?: boolean;
            create_smart_chapters?: boolean;
            create_next_steps?: boolean;
        };
        save_chat_text?: boolean;
        show_timestamp?: boolean;
    };
    schedule_meeting?: {
        audio_type?: string;
        embed_password_in_join_link?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
        join_before_host?: boolean;
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        personal_meeting?: boolean;
        pstn_password_protected?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: string;
        require_password_for_scheduled_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        upcoming_meeting_reminder?: boolean;
        use_pmi_for_instant_meetings?: boolean;
        use_pmi_for_schedule_meetings?: boolean;
        always_display_zoom_meeting_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_meetings?: boolean;
        };
        always_display_zoom_webinar_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_webinars?: boolean;
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
    chat?: {
        share_files?: {
            enable?: boolean;
            share_option?: string;
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
        allow_users_to_search_others_options?: string;
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
        };
        send_data_to_third_party_archiving_service?: {
            enable?: boolean;
        };
        translate_messages?: boolean;
        search_and_send_animated_gif_images?: {
            enable?: boolean;
        };
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
    };
};
type GroupsUpdateGroupsSettingsPathParams = {
    groupId: string;
};
type GroupsUpdateGroupsSettingsQueryParams = {
    option?: string;
};
type GroupsUpdateGroupsSettingsRequestBody = {
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
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        recording_available_reminder_alternative_hosts?: boolean;
        recording_available_reminder_schedulers?: boolean;
        schedule_for_reminder?: boolean;
    };
    in_meeting?: {
        alert_guest_join?: boolean;
        allow_users_to_delete_messages_in_meeting_chat?: boolean;
        allow_live_streaming?: boolean;
        allow_participants_chat_with?: number;
        allow_show_zoom_windows?: boolean;
        allow_users_save_chats?: number;
        annotation?: boolean;
        attendee_on_hold?: boolean;
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
        data_center_regions?: string[];
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
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
        meeting_reactions?: boolean;
        meeting_reactions_emojis?: string;
        allow_host_panelists_to_use_audible_clap?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        non_verbal_feedback?: boolean;
        only_host_view_device_list?: boolean;
        original_audio?: boolean;
        polling?: boolean;
        post_meeting_feedback?: boolean;
        private_chat?: boolean;
        record_play_own_voice?: boolean;
        remote_control?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        screen_sharing?: boolean;
        sending_default_email_invites?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_browser_join_link?: boolean;
        show_device_list?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        stereo_audio?: boolean;
        use_html_format_email?: boolean;
        virtual_background?: boolean;
        waiting_room?: boolean;
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
        meeting_polling?: {
            enable?: boolean;
            advanced_polls?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            require_answers_to_be_anonymous?: boolean;
            allow_host_to_upload_image?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
        };
        webinar_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            manage_saved_polls_and_quizzes?: boolean;
            require_answers_to_be_anonymous?: boolean;
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
    };
    other_options?: {
        allow_users_contact_support_via_chat?: boolean;
        blur_snapshot?: boolean;
        webinar_registration_options?: {
            allow_host_to_enable_join_info?: boolean;
            allow_host_to_enable_social_share_buttons?: boolean;
            enable_custom_questions?: boolean;
        };
    };
    profile?: {
        recording_storage_location?: {
            allowed_values?: string[];
            value?: string;
        };
    };
    recording?: {
        account_user_access_recording?: boolean;
        archive?: {
            enable?: boolean;
            settings?: {
                audio_file?: boolean;
                cc_transcript_file?: boolean;
                chat_file?: boolean;
                chat_with_sender_email?: boolean;
                video_file?: boolean;
            };
            type?: number;
        };
        auto_recording?: string;
        cloud_recording?: boolean;
        cloud_recording_download?: boolean;
        cloud_recording_download_host?: boolean;
        host_delete_cloud_recording?: boolean;
        record_files_separately?: {
            active_speaker?: boolean;
            gallery_view?: boolean;
            shared_screen?: boolean;
        };
        display_participant_name?: boolean;
        recording_thumbnails?: boolean;
        optimize_recording_for_3rd_party_video_editor?: boolean;
        recording_highlight?: boolean;
        save_panelist_chat?: boolean;
        save_poll_results?: boolean;
        save_close_caption?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        prevent_host_access_recording?: boolean;
        record_audio_file?: boolean;
        record_gallery_view?: boolean;
        record_speaker_view?: boolean;
        recording_audio_transcript?: boolean;
        smart_recording?: {
            create_recording_highlights?: boolean;
            create_smart_chapters?: boolean;
            create_next_steps?: boolean;
        };
        save_chat_text?: boolean;
        show_timestamp?: boolean;
    };
    schedule_meeting?: {
        audio_type?: string;
        embed_password_in_join_link?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
        join_before_host?: boolean;
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        pstn_password_protected?: boolean;
        require_password_for_all_meetings?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: string;
        require_password_for_scheduled_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        upcoming_meeting_reminder?: boolean;
        always_display_zoom_meeting_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_meetings?: boolean;
        };
        always_display_zoom_webinar_as_topic?: {
            enable?: boolean;
            display_topic_for_scheduled_webinars?: boolean;
        };
        continuous_meeting_chat?: {
            enable?: boolean;
            can_add_external_users?: boolean;
            auto_add_invited_external_users?: boolean;
        };
    };
    telephony?: {
        audio_conference_info?: string;
        third_party_audio?: boolean;
    };
    chat?: {
        share_files?: {
            enable?: boolean;
            share_option?: string;
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
        allow_users_to_search_others_options?: string;
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
                id?: string;
                status?: string;
            }[];
        };
        send_data_to_third_party_archiving_service?: {
            enable?: boolean;
        };
        translate_messages?: boolean;
        search_and_send_animated_gif_images?: {
            enable?: boolean;
        };
    };
} | ({
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
            policies?: {
                id?: string;
                status?: string;
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
    };
};
type GroupsUpdateGroupsSettingsResponse = object;
type GroupsGetGroupsWebinarRegistrationSettingsPathParams = {
    groupId: string;
};
type GroupsGetGroupsWebinarRegistrationSettingsQueryParams = {
    type?: string;
};
type GroupsGetGroupsWebinarRegistrationSettingsResponse = {
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
type GroupsUpdateGroupsWebinarRegistrationSettingsPathParams = {
    groupId: string;
};
type GroupsUpdateGroupsWebinarRegistrationSettingsQueryParams = {
    type?: string;
};
type GroupsUpdateGroupsWebinarRegistrationSettingsRequestBody = {
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
type GroupsUploadVirtualBackgroundFilesPathParams = {
    groupId: string;
};
type GroupsUploadVirtualBackgroundFilesRequestBody = {
    file?: string;
};
type GroupsUploadVirtualBackgroundFilesResponse = {
    id?: string;
    is_default?: boolean;
    name?: string;
    size?: number;
    type?: string;
};
type GroupsDeleteVirtualBackgroundFilesPathParams = {
    groupId: string;
};
type GroupsDeleteVirtualBackgroundFilesQueryParams = {
    file_ids?: string;
};
type UsersListUsersQueryParams = {
    status?: string;
    page_size?: number;
    role_id?: string;
    page_number?: string;
    include_fields?: string;
    next_page_token?: string;
    license?: string;
};
type UsersListUsersResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
    users?: {
        user_created_at?: string;
        created_at?: string;
        custom_attributes?: {
            key?: string;
            name?: string;
            value?: string;
        }[];
        dept?: string;
        email: string;
        employee_unique_id?: string;
        first_name?: string;
        group_ids?: string[];
        host_key?: string;
        id?: string;
        im_group_ids?: string[];
        last_client_version?: string;
        last_login_time?: string;
        last_name?: string;
        plan_united_type?: string;
        pmi?: number;
        role_id?: string;
        status?: string;
        timezone?: string;
        type: number;
        verified?: number;
        display_name?: string;
    }[];
};
type UsersCreateUsersRequestBody = {
    action: string;
    user_info?: {
        email: string;
        first_name?: string;
        last_name?: string;
        display_name?: string;
        password?: string;
        type: number;
        feature?: {
            zoom_phone?: boolean;
            zoom_one_type?: number;
        };
        plan_united_type?: string;
    };
};
type UsersCreateUsersResponse = {
    email?: string;
    first_name?: string;
    id?: string;
    last_name?: string;
    type?: number;
};
type UsersCheckUserEmailQueryParams = {
    email: string;
};
type UsersCheckUserEmailResponse = {
    existed_email?: boolean;
};
type UsersBulkUpdateFeaturesForUserRequestBody = {
    feature_type: string;
    feature_value: string;
    users: {
        id?: string;
        email?: string;
    }[];
};
type UsersBulkUpdateFeaturesForUserResponse = {
    success_user_ids?: string[];
    fail_details?: {
        user_ids?: string[];
        reason?: string;
    }[];
};
type UsersGetUsersZAKResponse = {
    token?: string;
};
type UsersGetUserSummaryResponse = {
    licensed_users_count?: number;
    basic_users_count?: number;
    on_prem_users_count?: number;
    room_users_count?: number;
    pending_users_count?: number;
    join_only_users_count?: number;
    total_users_count?: number;
};
type UsersCheckUsersPMRoomQueryParams = {
    vanity_name: string;
};
type UsersCheckUsersPMRoomResponse = {
    existed?: boolean;
};
type UsersGetUserPathParams = {
    userId: string;
};
type UsersGetUserQueryParams = {
    login_type?: number;
    encrypted_email?: boolean;
    search_by_unique_id?: boolean;
};
type UsersGetUserResponse = {
    id?: string;
} & {
    created_at?: string;
    dept?: string;
    email?: string;
    first_name?: string;
    last_client_version?: string;
    last_login_time?: string;
    last_name?: string;
    pmi?: number;
    role_name?: string;
    timezone?: string;
    type: number;
    use_pmi?: boolean;
    display_name?: string;
} & {
    account_id?: string;
    account_number?: number;
    cms_user_id?: string;
    company?: string;
    created_at?: string;
    user_created_at?: string;
    custom_attributes?: {
        key?: string;
        name?: string;
        value?: string;
    }[];
    employee_unique_id?: string;
    group_ids?: string[];
    im_group_ids?: string[];
    jid?: string;
    job_title?: string;
    language?: string;
    location?: string;
    login_types?: number[];
    manager?: string;
    personal_meeting_url?: string;
    phone_country?: string;
    phone_number?: string;
    phone_numbers?: {
        code?: string;
        country?: string;
        label?: string;
        number?: string;
        verified?: boolean;
    }[];
    pic_url?: string;
    plan_united_type?: string;
    pronouns?: string;
    pronouns_option?: number;
    role_id?: string;
    status?: string;
    use_pmi?: boolean;
    vanity_url?: string;
    verified?: number;
    cluster?: string;
    zoom_one_type?: number;
};
type UsersDeleteUserPathParams = {
    userId: string;
};
type UsersDeleteUserQueryParams = {
    encrypted_email?: boolean;
    action?: string;
    transfer_email?: string;
    transfer_meeting?: boolean;
    transfer_webinar?: boolean;
    transfer_recording?: boolean;
    transfer_whiteboard?: boolean;
};
type UsersUpdateUserPathParams = {
    userId: string;
};
type UsersUpdateUserQueryParams = {
    login_type?: number;
    remove_tsp_credentials?: boolean;
};
type UsersUpdateUserRequestBody = {
    cms_user_id?: string;
    company?: string;
    custom_attributes?: {
        key?: string;
        name?: string;
        value?: string;
    }[];
    dept?: string;
    first_name?: string;
    group_id?: string;
    host_key?: string;
    job_title?: string;
    language?: string;
    last_name?: string;
    location?: string;
    manager?: string;
    phone_country?: string;
    phone_number?: string;
    phone_numbers?: {
        code?: string;
        country?: string;
        label?: string;
        number?: string;
    }[];
    pmi?: number;
    pronouns?: string;
    pronouns_option?: number;
    timezone?: string;
    type?: number;
    use_pmi?: boolean;
    vanity_name?: string;
    display_name?: string;
    zoom_one_type?: number;
    plan_united_type?: string;
    feature?: {
        zoom_phone?: boolean;
    };
    about_me?: string;
    linkedin_url?: string;
};
type UsersListUserAssistantsPathParams = {
    userId: string;
};
type UsersListUserAssistantsResponse = {
    assistants?: {
        email?: string;
        id?: string;
    }[];
};
type UsersAddAssistantsPathParams = {
    userId: string;
};
type UsersAddAssistantsRequestBody = {
    assistants?: {
        email?: string;
        id?: string;
    }[];
};
type UsersAddAssistantsResponse = {
    add_at?: string;
    ids?: string;
};
type UsersDeleteUserAssistantsPathParams = {
    userId: string;
};
type UsersDeleteUserAssistantPathParams = {
    userId: string;
    assistantId: string;
};
type UsersListUsersCollaborationDevicesPathParams = {
    userId: string;
};
type UsersListUsersCollaborationDevicesResponse = {
    total_records?: number;
    collaboration_devices?: {
        id?: string;
        device_name?: string;
        room_name?: string;
        room_user_id?: string;
        status?: string;
    }[];
};
type UsersGetCollaborationDeviceDetailPathParams = {
    userId: string;
    collaborationDeviceId: string;
};
type UsersGetCollaborationDeviceDetailResponse = {
    id?: string;
    device_name?: string;
    room_name?: string;
    room_user_id?: string;
    status?: string;
};
type UsersUpdateUsersEmailPathParams = {
    userId: string;
};
type UsersUpdateUsersEmailRequestBody = {
    email: string;
};
type UsersGetMeetingTemplateDetailPathParams = {
    userId: string;
    meetingTemplateId: string;
};
type UsersGetMeetingTemplateDetailResponse = {
    id?: string;
    name?: string;
    settings?: {
        in_meeting?: {
            entry_exit_chime?: string;
            feedback?: boolean;
            polling?: boolean;
            post_meeting_feedback?: boolean;
            screen_sharing?: boolean;
            who_can_share_screen?: string;
            who_can_share_screen_when_someone_is_sharing?: string;
            disable_screen_sharing_for_host_meetings?: boolean;
            annotation?: boolean;
            whiteboard?: boolean;
            remote_control?: boolean;
            non_verbal_feedback?: boolean;
            allow_participants_to_rename?: boolean;
            breakout_room?: boolean;
            remote_support?: boolean;
            manual_captioning?: {
                auto_generated_captions?: boolean;
                allow_to_type?: boolean;
                manual_captions?: boolean;
                save_captions?: boolean;
            };
            closed_captioning?: {
                auto_transcribing?: boolean;
                enable?: boolean;
                save_caption?: boolean;
            };
        };
        recording?: {
            auto_recording?: string;
        };
        schedule_meeting?: {
            host_video?: boolean;
            participant_video?: boolean;
            mute_upon_entry?: boolean;
        };
        meeting_security?: {
            waiting_room?: boolean;
        };
    };
};
type UsersUpdateUsersPasswordPathParams = {
    userId: string;
};
type UsersUpdateUsersPasswordRequestBody = {
    password: string;
};
type UsersGetUserPermissionsPathParams = {
    userId: string;
};
type UsersGetUserPermissionsResponse = {
    permissions?: string[];
};
type UsersUploadUsersProfilePicturePathParams = {
    userId: string;
};
type UsersUploadUsersProfilePictureRequestBody = {
    pic_file: string;
};
type UsersUploadUsersProfilePictureResponse = object;
type UsersDeleteUsersProfilePicturePathParams = {
    userId: string;
};
type UsersGetUserPresenceStatusPathParams = {
    userId: string;
};
type UsersGetUserPresenceStatusResponse = {
    status: string;
    end_time: string;
    remaining_time: number;
} | {
    status: string;
};
type UsersUpdateUsersPresenceStatusPathParams = {
    userId: string;
};
type UsersUpdateUsersPresenceStatusRequestBody = {
    status: string;
} | {
    status: string;
    duration?: number;
};
type UsersListUserSchedulersPathParams = {
    userId: string;
};
type UsersListUserSchedulersResponse = {
    schedulers?: {
        email?: string;
        id?: string;
        pmi?: number;
    }[];
};
type UsersDeleteUserSchedulersPathParams = {
    userId: string;
};
type UsersDeleteSchedulerPathParams = {
    userId: string;
    schedulerId: string;
};
type UsersGetUserSettingsPathParams = {
    userId: string;
};
type UsersGetUserSettingsQueryParams = {
    login_type?: number;
    option?: string;
    custom_query_fields?: string;
};
type UsersGetUserSettingsResponse = {
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
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        recording_available_reminder_alternative_hosts?: boolean;
        recording_available_reminder_schedulers?: boolean;
        schedule_for_reminder?: boolean;
    };
    feature?: {
        cn_meeting?: boolean;
        concurrent_meeting?: string;
        in_meeting?: boolean;
        large_meeting?: boolean;
        large_meeting_capacity?: number;
        meeting_capacity?: number;
        webinar?: boolean;
        webinar_capacity?: number;
        zoom_events?: boolean;
        zoom_events_capacity?: number;
        zoom_events_unlimited?: boolean;
        zoom_events_unlimited_capacities?: number[];
        zoom_sessions_unlimited?: boolean;
        zoom_sessions_unlimited_capacities?: number[];
        zoom_events_pay_per_attendee?: boolean;
        zoom_sessions_pay_per_attendee?: boolean;
        zoom_phone?: boolean;
        zoom_iq_for_sales?: boolean;
        zoom_revenue_accelerator?: boolean;
        zoom_whiteboard?: boolean;
        zoom_whiteboard_plus?: boolean;
        zoom_translated_captions?: boolean;
        zoom_customer_managed_key?: boolean;
        zoom_huddles?: boolean;
        zoom_quality_management?: boolean;
        zoom_workforce_management?: boolean;
        zoom_scheduler?: boolean;
        zoom_clips_plus?: boolean;
        zoom_mail_calendar?: boolean;
        zoom_compliance_management?: boolean;
    };
    in_meeting?: {
        allow_host_to_enable_focus_mode?: boolean;
        allow_users_to_delete_messages_in_meeting_chat?: boolean;
        allow_live_streaming?: boolean;
        post_meeting_feedback?: boolean;
        whiteboard?: boolean;
        allow_participants_chat_with?: number;
        allow_users_save_chats?: number;
        annotation?: boolean;
        attendee_on_hold?: boolean;
        attention_mode_focus_mode?: boolean;
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
        data_center_regions?: string[];
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
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
            enable_language_interpretation_by_default?: boolean;
            allow_participants_to_speak_in_listening_channel?: boolean;
            allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
            enable?: boolean;
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
        meeting_reactions?: boolean;
        meeting_reactions_emojis?: string;
        allow_host_panelists_to_use_audible_clap?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        non_verbal_feedback?: boolean;
        polling?: boolean;
        private_chat?: boolean;
        record_play_voice?: boolean;
        remote_control?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        screen_sharing?: boolean;
        share_dual_camera?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
        unchecked_data_center_regions?: string[];
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
        waiting_room?: boolean;
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
        meeting_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            require_answers_to_be_anonymous?: boolean;
            allow_host_to_upload_image?: boolean;
            enable?: boolean;
        };
        webinar_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            require_answers_to_be_anonymous?: boolean;
            allow_host_to_upload_image?: boolean;
            enable?: boolean;
        };
        webinar_survey?: boolean;
        who_can_share_screen?: string;
        who_can_share_screen_when_someone_is_sharing?: string;
        participants_share_simultaneously?: string;
        workplace_by_facebook?: boolean;
        transfer_meetings_between_devices?: boolean;
        allow_show_zoom_windows?: boolean;
    };
    profile?: {
        recording_storage_location?: {
            allowed_values?: string[];
            value?: string;
        };
    };
    recording?: {
        ask_host_to_confirm_disclaimer?: boolean;
        ask_participants_to_consent_disclaimer?: boolean;
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
        save_panelist_chat?: boolean;
        save_poll_results?: boolean;
        save_close_caption?: boolean;
        auto_recording?: string;
        cloud_recording?: boolean;
        host_pause_stop_recording?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        record_audio_file?: boolean;
        record_gallery_view?: boolean;
        record_speaker_view?: boolean;
        recording_audio_transcript?: boolean;
        recording_disclaimer?: boolean;
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
        save_chat_text?: boolean;
        show_timestamp?: boolean;
    };
    schedule_meeting?: {
        audio_type?: string;
        default_password_for_scheduled_meetings?: string;
        embed_password_in_join_link?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
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
        participants_video?: boolean;
        personal_meeting?: boolean;
        pmi_password?: string;
        pstn_password_protected?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: string;
        require_password_for_scheduled_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        use_pmi_for_instant_meetings?: boolean;
        use_pmi_for_scheduled_meetings?: boolean;
        continuous_meeting_chat?: {
            enable?: boolean;
            can_add_external_users?: boolean;
            auto_add_invited_external_users?: boolean;
        };
    };
    telephony?: {
        audio_conference_info?: string;
        show_international_numbers_link?: boolean;
        telephony_regions?: {
            allowed_values?: string[];
            selection_values?: string;
        };
        third_party_audio?: boolean;
    };
    tsp?: {
        call_out?: boolean;
        call_out_countries?: object[];
        show_international_numbers_link?: boolean;
    };
    whiteboard?: {
        out_meeting_advanced_whiteboard?: boolean;
        in_meeting_advanced_whiteboard?: boolean;
    };
} | {
    authentication_options?: {
        meeting_authentication?: {
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
        };
        recording_authentication?: {
            authentication_options?: {
                default_option?: boolean;
                domains?: string;
                id?: string;
                name?: string;
                type?: string;
                visible?: boolean;
            }[];
            recording_authentication?: boolean;
        };
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
    };
};
type UsersUpdateUserSettingsPathParams = {
    userId: string;
};
type UsersUpdateUserSettingsQueryParams = {
    option?: string;
};
type UsersUpdateUserSettingsRequestBody = {
    email_notification?: {
        alternative_host_reminder?: boolean;
        cancel_meeting_reminder?: boolean;
        cloud_recording_available_reminder?: boolean;
        jbh_reminder?: boolean;
        recording_available_reminder_alternative_hosts?: boolean;
        recording_available_reminder_schedulers?: boolean;
        schedule_for_reminder?: boolean;
    };
    feature?: {
        concurrent_meeting?: string;
        large_meeting?: boolean;
        large_meeting_capacity?: number;
        meeting_capacity?: number;
        webinar?: boolean;
        webinar_capacity?: number;
        zoom_events?: boolean;
        zoom_events_capacity?: number;
        zoom_events_unlimited?: boolean;
        zoom_events_unlimited_capacities?: number[];
        zoom_sessions_unlimited?: boolean;
        zoom_sessions_unlimited_capacities?: number[];
        zoom_events_pay_per_attendee?: boolean;
        zoom_sessions_pay_per_attendee?: boolean;
        zoom_phone?: boolean;
        zoom_iq_for_sales?: boolean;
        zoom_revenue_accelerator?: boolean;
        zoom_whiteboard?: boolean;
        zoom_whiteboard_plus?: boolean;
        zoom_translated_captions?: boolean;
        zoom_customer_managed_key?: boolean;
        zoom_huddles?: boolean;
        zoom_quality_management?: boolean;
        zoom_workforce_management?: boolean;
        zoom_scheduler?: boolean;
        zoom_clips_plus?: boolean;
        zoom_mail_calendar?: boolean;
        zoom_compliance_management?: boolean;
    };
    in_meeting?: {
        allow_host_to_enable_focus_mode?: boolean;
        allow_users_to_delete_messages_in_meeting_chat?: boolean;
        allow_live_streaming?: boolean;
        post_meeting_feedback?: boolean;
        whiteboard?: boolean;
        allow_participants_chat_with?: number;
        allow_users_save_chats?: number;
        annotation?: boolean;
        attendee_on_hold?: boolean;
        attention_mode_focus_mode?: boolean;
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
        data_center_regions?: string[];
        disable_screen_sharing_for_host_meetings?: boolean;
        disable_screen_sharing_for_in_meeting_guests?: boolean;
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
            enable_language_interpretation_by_default?: boolean;
            allow_participants_to_speak_in_listening_channel?: boolean;
            allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
            enable?: boolean;
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
        meeting_reactions?: boolean;
        meeting_reactions_emojis?: string;
        allow_host_panelists_to_use_audible_clap?: boolean;
        webinar_reactions?: boolean;
        meeting_survey?: boolean;
        non_verbal_feedback?: boolean;
        polling?: boolean;
        private_chat?: boolean;
        record_play_voice?: boolean;
        remote_control?: boolean;
        remote_support?: boolean;
        request_permission_to_unmute_participants?: boolean;
        screen_sharing?: boolean;
        share_dual_camera?: boolean;
        show_a_join_from_your_browser_link?: boolean;
        show_meeting_control_toolbar?: boolean;
        slide_control?: boolean;
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
        waiting_room?: boolean;
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
        meeting_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            require_answers_to_be_anonymous?: boolean;
            allow_host_to_upload_image?: boolean;
            enable?: boolean;
        };
        webinar_polling?: {
            advanced_polls?: boolean;
            allow_alternative_host_to_add_edit?: boolean;
            require_answers_to_be_anonymous?: boolean;
            allow_host_to_upload_image?: boolean;
            enable?: boolean;
        };
        webinar_survey?: boolean;
        who_can_share_screen?: string;
        who_can_share_screen_when_someone_is_sharing?: string;
        participants_share_simultaneously?: string;
        workplace_by_facebook?: boolean;
        auto_answer?: boolean;
        allow_show_zoom_windows?: boolean;
    };
    profile?: {
        recording_storage_location?: {
            allowed_values?: string[];
            value?: string;
        };
    };
    recording?: {
        ask_host_to_confirm_disclaimer?: boolean;
        ask_participants_to_consent_disclaimer?: boolean;
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
        save_panelist_chat?: boolean;
        save_poll_results?: boolean;
        save_close_caption?: boolean;
        auto_recording?: string;
        cloud_recording?: boolean;
        host_pause_stop_recording?: boolean;
        ip_address_access_control?: {
            enable?: boolean;
            ip_addresses_or_ranges?: string;
        };
        local_recording?: boolean;
        record_audio_file?: boolean;
        record_gallery_view?: boolean;
        record_speaker_view?: boolean;
        recording_audio_transcript?: boolean;
        recording_disclaimer?: boolean;
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
        save_chat_text?: boolean;
        show_timestamp?: boolean;
    };
    schedule_meeting?: {
        audio_type?: string;
        default_password_for_scheduled_meetings?: string;
        embed_password_in_join_link?: boolean;
        force_pmi_jbh_password?: boolean;
        host_video?: boolean;
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
        participants_video?: boolean;
        personal_meeting?: boolean;
        pmi_password?: string;
        pstn_password_protected?: boolean;
        require_password_for_instant_meetings?: boolean;
        require_password_for_pmi_meetings?: string;
        require_password_for_scheduled_meetings?: boolean;
        require_password_for_scheduling_new_meetings?: boolean;
        use_pmi_for_instant_meetings?: boolean;
        use_pmi_for_scheduled_meetings?: boolean;
    };
    telephony?: {
        audio_conference_info?: string;
        show_international_numbers_link?: boolean;
        telephony_regions?: {
            selection_values?: string;
        };
        third_party_audio?: boolean;
    };
    tsp?: {
        call_out?: boolean;
        call_out_countries?: object[];
        show_international_numbers_link?: boolean;
    };
} | ({
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
    };
};
type UsersUploadVirtualBackgroundFilesPathParams = {
    userId: string;
};
type UsersUploadVirtualBackgroundFilesRequestBody = {
    file?: string;
};
type UsersUploadVirtualBackgroundFilesResponse = {
    id?: string;
    is_default?: boolean;
    name?: string;
    size?: number;
    type?: string;
};
type UsersDeleteVirtualBackgroundFilesPathParams = {
    userId: string;
};
type UsersDeleteVirtualBackgroundFilesQueryParams = {
    file_ids?: string;
};
type UsersUpdateUserStatusPathParams = {
    userId: string;
};
type UsersUpdateUserStatusRequestBody = {
    action: string;
};
type UsersGetUsersTokenPathParams = {
    userId: string;
};
type UsersGetUsersTokenQueryParams = {
    type?: string;
    ttl?: number;
};
type UsersGetUsersTokenResponse = {
    token?: string;
};
type UsersRevokeUsersSSOTokenPathParams = {
    userId: string;
};
declare class UsersEndpoints extends WebEndpoints {
    readonly contactGroups: {
        listContactGroups: (_: object & {
            query?: ContactGroupsListContactGroupsQueryParams;
        }) => Promise<BaseResponse<ContactGroupsListContactGroupsResponse>>;
        createContactGroup: (_: object & {
            body?: ContactGroupsCreateContactGroupRequestBody;
        }) => Promise<BaseResponse<ContactGroupsCreateContactGroupResponse>>;
        getContactGroup: (_: {
            path: ContactGroupsGetContactGroupPathParams;
        } & object) => Promise<BaseResponse<ContactGroupsGetContactGroupResponse>>;
        deleteContactGroup: (_: {
            path: ContactGroupsDeleteContactGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateContactGroup: (_: {
            path: ContactGroupsUpdateContactGroupPathParams;
        } & {
            body?: ContactGroupsUpdateContactGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listContactGroupMembers: (_: {
            path: ContactGroupsListContactGroupMembersPathParams;
        } & object & {
            query?: ContactGroupsListContactGroupMembersQueryParams;
        }) => Promise<BaseResponse<ContactGroupsListContactGroupMembersResponse>>;
        addContactGroupMembers: (_: {
            path: ContactGroupsAddContactGroupMembersPathParams;
        } & {
            body?: ContactGroupsAddContactGroupMembersRequestBody;
        } & object) => Promise<BaseResponse<ContactGroupsAddContactGroupMembersResponse>>;
        removeMembersInContactGroup: (_: {
            path: ContactGroupsRemoveMembersInContactGroupPathParams;
        } & object & {
            query: ContactGroupsRemoveMembersInContactGroupQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly groups: {
        listGroups: (_: object) => Promise<BaseResponse<GroupsListGroupsResponse>>;
        createGroup: (_: object & {
            body?: GroupsCreateGroupRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        getGroup: (_: {
            path: GroupsGetGroupPathParams;
        } & object) => Promise<BaseResponse<GroupsGetGroupResponse>>;
        deleteGroup: (_: {
            path: GroupsDeleteGroupPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateGroup: (_: {
            path: GroupsUpdateGroupPathParams;
        } & {
            body?: GroupsUpdateGroupRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listGroupAdmins: (_: {
            path: GroupsListGroupAdminsPathParams;
        } & object & {
            query?: GroupsListGroupAdminsQueryParams;
        }) => Promise<BaseResponse<GroupsListGroupAdminsResponse>>;
        addGroupAdmins: (_: {
            path: GroupsAddGroupAdminsPathParams;
        } & {
            body?: GroupsAddGroupAdminsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteGroupAdmin: (_: {
            path: GroupsDeleteGroupAdminPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listGroupChannels: (_: {
            path: GroupsListGroupChannelsPathParams;
        } & object) => Promise<BaseResponse<GroupsListGroupChannelsResponse>>;
        getLockedSettings: (_: {
            path: GroupsGetLockedSettingsPathParams;
        } & object & {
            query?: GroupsGetLockedSettingsQueryParams;
        }) => Promise<BaseResponse<GroupsGetLockedSettingsResponse>>;
        updateLockedSettings: (_: {
            path: GroupsUpdateLockedSettingsPathParams;
        } & (({
            body?: {
                audio_conferencing?: {
                    toll_free_and_fee_based_toll_call?: boolean;
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
                    attendee_on_hold?: boolean;
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
                    non_verbal_feedback?: boolean;
                    original_audio?: boolean;
                    polling?: boolean;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    remote_control?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute_participants?: boolean;
                    save_caption?: boolean;
                    save_captions?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_a_join_from_your_browser_link?: boolean;
                    show_browser_join_link?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
                    stereo_audio?: boolean;
                    use_html_format_email?: boolean;
                    virtual_background?: boolean;
                    waiting_room?: boolean;
                    webinar_chat?: boolean;
                    webinar_live_streaming?: boolean;
                    webinar_polling?: boolean;
                    webinar_question_answer?: boolean;
                    webinar_survey?: boolean;
                    whiteboard?: boolean;
                };
                other_options?: {
                    blur_snapshot?: boolean;
                };
                recording?: {
                    account_user_access_recording?: boolean;
                    auto_delete_cmr?: boolean;
                    auto_recording?: boolean;
                    cloud_recording?: boolean;
                    cloud_recording_download?: boolean;
                    host_delete_cloud_recording?: boolean;
                    ip_address_access_control?: {
                        enable?: boolean;
                        ip_addresses_or_ranges?: string;
                    };
                    local_recording?: boolean;
                    recording_authentication?: boolean;
                    archive?: boolean;
                };
                schedule_meeting?: {
                    audio_type?: boolean;
                    embed_password_in_join_link?: boolean;
                    force_pmi_jbh_password?: boolean;
                    host_video?: boolean;
                    join_before_host?: boolean;
                    meeting_authentication?: boolean;
                    mute_upon_entry?: boolean;
                    participant_video?: boolean;
                    personal_meeting?: boolean;
                    pstn_password_protected?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    upcoming_meeting_reminder?: boolean;
                    continuous_meeting_chat?: boolean;
                };
                telephony?: {
                    telephony_regions?: boolean;
                    third_party_audio?: boolean;
                };
            };
        } | {
            body?: {
                meeting_security?: {
                    approved_or_denied_countries_or_regions?: boolean;
                    auto_security?: boolean;
                    block_user_domain?: boolean;
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
        }) & {
            query?: GroupsUpdateLockedSettingsQueryParams;
        })) => Promise<BaseResponse<unknown>>;
        listGroupMembers: (_: {
            path: GroupsListGroupMembersPathParams;
        } & object & {
            query?: GroupsListGroupMembersQueryParams;
        }) => Promise<BaseResponse<GroupsListGroupMembersResponse>>;
        addGroupMembers: (_: {
            path: GroupsAddGroupMembersPathParams;
        } & {
            body?: GroupsAddGroupMembersRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteGroupMember: (_: {
            path: GroupsDeleteGroupMemberPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateGroupMember: (_: {
            path: GroupsUpdateGroupMemberPathParams;
        } & {
            body: GroupsUpdateGroupMemberRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getGroupsSettings: (_: {
            path: GroupsGetGroupsSettingsPathParams;
        } & object & {
            query?: GroupsGetGroupsSettingsQueryParams;
        }) => Promise<BaseResponse<GroupsGetGroupsSettingsResponse>>;
        updateGroupsSettings: (_: {
            path: GroupsUpdateGroupsSettingsPathParams;
        } & (({
            body?: {
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
                email_notification?: {
                    alternative_host_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    cloud_recording_available_reminder?: boolean;
                    jbh_reminder?: boolean;
                    recording_available_reminder_alternative_hosts?: boolean;
                    recording_available_reminder_schedulers?: boolean;
                    schedule_for_reminder?: boolean;
                };
                in_meeting?: {
                    alert_guest_join?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_live_streaming?: boolean;
                    allow_participants_chat_with?: number;
                    allow_show_zoom_windows?: boolean;
                    allow_users_save_chats?: number;
                    annotation?: boolean;
                    attendee_on_hold?: boolean;
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
                    data_center_regions?: string[];
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
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
                    meeting_reactions?: boolean;
                    meeting_reactions_emojis?: string;
                    allow_host_panelists_to_use_audible_clap?: boolean;
                    webinar_reactions?: boolean;
                    meeting_survey?: boolean;
                    non_verbal_feedback?: boolean;
                    only_host_view_device_list?: boolean;
                    original_audio?: boolean;
                    polling?: boolean;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    record_play_own_voice?: boolean;
                    remote_control?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute_participants?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_a_join_from_your_browser_link?: boolean;
                    show_browser_join_link?: boolean;
                    show_device_list?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
                    stereo_audio?: boolean;
                    use_html_format_email?: boolean;
                    virtual_background?: boolean;
                    waiting_room?: boolean;
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
                    meeting_polling?: {
                        enable?: boolean;
                        advanced_polls?: boolean;
                        manage_saved_polls_and_quizzes?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        allow_host_to_upload_image?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                    };
                    webinar_polling?: {
                        advanced_polls?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        manage_saved_polls_and_quizzes?: boolean;
                        require_answers_to_be_anonymous?: boolean;
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
                };
                other_options?: {
                    allow_users_contact_support_via_chat?: boolean;
                    blur_snapshot?: boolean;
                    webinar_registration_options?: {
                        allow_host_to_enable_join_info?: boolean;
                        allow_host_to_enable_social_share_buttons?: boolean;
                        enable_custom_questions?: boolean;
                    };
                };
                profile?: {
                    recording_storage_location?: {
                        allowed_values?: string[];
                        value?: string;
                    };
                };
                recording?: {
                    account_user_access_recording?: boolean;
                    archive?: {
                        enable?: boolean;
                        settings?: {
                            audio_file?: boolean;
                            cc_transcript_file?: boolean;
                            chat_file?: boolean;
                            chat_with_sender_email?: boolean;
                            video_file?: boolean;
                        };
                        type?: number;
                    };
                    auto_recording?: string;
                    cloud_recording?: boolean;
                    cloud_recording_download?: boolean;
                    cloud_recording_download_host?: boolean;
                    host_delete_cloud_recording?: boolean;
                    record_files_separately?: {
                        active_speaker?: boolean;
                        gallery_view?: boolean;
                        shared_screen?: boolean;
                    };
                    display_participant_name?: boolean;
                    recording_thumbnails?: boolean;
                    optimize_recording_for_3rd_party_video_editor?: boolean;
                    recording_highlight?: boolean;
                    save_panelist_chat?: boolean;
                    save_poll_results?: boolean;
                    save_close_caption?: boolean;
                    ip_address_access_control?: {
                        enable?: boolean;
                        ip_addresses_or_ranges?: string;
                    };
                    local_recording?: boolean;
                    prevent_host_access_recording?: boolean;
                    record_audio_file?: boolean;
                    record_gallery_view?: boolean;
                    record_speaker_view?: boolean;
                    recording_audio_transcript?: boolean;
                    smart_recording?: {
                        create_recording_highlights?: boolean;
                        create_smart_chapters?: boolean;
                        create_next_steps?: boolean;
                    };
                    save_chat_text?: boolean;
                    show_timestamp?: boolean;
                };
                schedule_meeting?: {
                    audio_type?: string;
                    embed_password_in_join_link?: boolean;
                    force_pmi_jbh_password?: boolean;
                    host_video?: boolean;
                    join_before_host?: boolean;
                    mute_upon_entry?: boolean;
                    participant_video?: boolean;
                    pstn_password_protected?: boolean;
                    require_password_for_all_meetings?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: string;
                    require_password_for_scheduled_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    upcoming_meeting_reminder?: boolean;
                    always_display_zoom_meeting_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_meetings?: boolean;
                    };
                    always_display_zoom_webinar_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_webinars?: boolean;
                    };
                    continuous_meeting_chat?: {
                        enable?: boolean;
                        can_add_external_users?: boolean;
                        auto_add_invited_external_users?: boolean;
                    };
                };
                telephony?: {
                    audio_conference_info?: string;
                    third_party_audio?: boolean;
                };
                chat?: {
                    share_files?: {
                        enable?: boolean;
                        share_option?: string;
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
                    allow_users_to_search_others_options?: string;
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
                            id?: string;
                            status?: string;
                        }[];
                    };
                    send_data_to_third_party_archiving_service?: {
                        enable?: boolean;
                    };
                    translate_messages?: boolean;
                    search_and_send_animated_gif_images?: {
                        enable?: boolean;
                    };
                };
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
                        policies?: {
                            id?: string;
                            status?: string;
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
                };
            };
        }) & {
            query?: GroupsUpdateGroupsSettingsQueryParams;
        })) => Promise<BaseResponse<object>>;
        getGroupsWebinarRegistrationSettings: (_: {
            path: GroupsGetGroupsWebinarRegistrationSettingsPathParams;
        } & object & {
            query?: GroupsGetGroupsWebinarRegistrationSettingsQueryParams;
        }) => Promise<BaseResponse<GroupsGetGroupsWebinarRegistrationSettingsResponse>>;
        updateGroupsWebinarRegistrationSettings: (_: {
            path: GroupsUpdateGroupsWebinarRegistrationSettingsPathParams;
        } & {
            body?: GroupsUpdateGroupsWebinarRegistrationSettingsRequestBody;
        } & {
            query?: GroupsUpdateGroupsWebinarRegistrationSettingsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        uploadVirtualBackgroundFiles: (_: {
            path: GroupsUploadVirtualBackgroundFilesPathParams;
        } & {
            body?: GroupsUploadVirtualBackgroundFilesRequestBody;
        } & object) => Promise<BaseResponse<GroupsUploadVirtualBackgroundFilesResponse>>;
        deleteVirtualBackgroundFiles: (_: {
            path: GroupsDeleteVirtualBackgroundFilesPathParams;
        } & object & {
            query?: GroupsDeleteVirtualBackgroundFilesQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly users: {
        listUsers: (_: object & {
            query?: UsersListUsersQueryParams;
        }) => Promise<BaseResponse<UsersListUsersResponse>>;
        createUsers: (_: object & {
            body: UsersCreateUsersRequestBody;
        }) => Promise<BaseResponse<UsersCreateUsersResponse>>;
        checkUserEmail: (_: object & {
            query: UsersCheckUserEmailQueryParams;
        }) => Promise<BaseResponse<UsersCheckUserEmailResponse>>;
        bulkUpdateFeaturesForUser: (_: object & {
            body: UsersBulkUpdateFeaturesForUserRequestBody;
        }) => Promise<BaseResponse<UsersBulkUpdateFeaturesForUserResponse>>;
        getUsersZAK: (_: object) => Promise<BaseResponse<UsersGetUsersZAKResponse>>;
        getUserSummary: (_: object) => Promise<BaseResponse<UsersGetUserSummaryResponse>>;
        checkUsersPMRoom: (_: object & {
            query: UsersCheckUsersPMRoomQueryParams;
        }) => Promise<BaseResponse<UsersCheckUsersPMRoomResponse>>;
        getUser: (_: {
            path: UsersGetUserPathParams;
        } & object & {
            query?: UsersGetUserQueryParams;
        }) => Promise<BaseResponse<UsersGetUserResponse>>;
        deleteUser: (_: {
            path: UsersDeleteUserPathParams;
        } & object & {
            query?: UsersDeleteUserQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateUser: (_: {
            path: UsersUpdateUserPathParams;
        } & {
            body?: UsersUpdateUserRequestBody;
        } & {
            query?: UsersUpdateUserQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        listUserAssistants: (_: {
            path: UsersListUserAssistantsPathParams;
        } & object) => Promise<BaseResponse<UsersListUserAssistantsResponse>>;
        addAssistants: (_: {
            path: UsersAddAssistantsPathParams;
        } & {
            body?: UsersAddAssistantsRequestBody;
        } & object) => Promise<BaseResponse<UsersAddAssistantsResponse>>;
        deleteUserAssistants: (_: {
            path: UsersDeleteUserAssistantsPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteUserAssistant: (_: {
            path: UsersDeleteUserAssistantPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listUsersCollaborationDevices: (_: {
            path: UsersListUsersCollaborationDevicesPathParams;
        } & object) => Promise<BaseResponse<UsersListUsersCollaborationDevicesResponse>>;
        getCollaborationDeviceDetail: (_: {
            path: UsersGetCollaborationDeviceDetailPathParams;
        } & object) => Promise<BaseResponse<UsersGetCollaborationDeviceDetailResponse>>;
        updateUsersEmail: (_: {
            path: UsersUpdateUsersEmailPathParams;
        } & {
            body: UsersUpdateUsersEmailRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getMeetingTemplateDetail: (_: {
            path: UsersGetMeetingTemplateDetailPathParams;
        } & object) => Promise<BaseResponse<UsersGetMeetingTemplateDetailResponse>>;
        updateUsersPassword: (_: {
            path: UsersUpdateUsersPasswordPathParams;
        } & {
            body: UsersUpdateUsersPasswordRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUserPermissions: (_: {
            path: UsersGetUserPermissionsPathParams;
        } & object) => Promise<BaseResponse<UsersGetUserPermissionsResponse>>;
        uploadUsersProfilePicture: (_: {
            path: UsersUploadUsersProfilePicturePathParams;
        } & {
            body: UsersUploadUsersProfilePictureRequestBody;
        } & object) => Promise<BaseResponse<object>>;
        deleteUsersProfilePicture: (_: {
            path: UsersDeleteUsersProfilePicturePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getUserPresenceStatus: (_: {
            path: UsersGetUserPresenceStatusPathParams;
        } & object) => Promise<BaseResponse<UsersGetUserPresenceStatusResponse>>;
        updateUsersPresenceStatus: (_: {
            path: UsersUpdateUsersPresenceStatusPathParams;
        } & (({
            body: {
                status: string;
            };
        } | {
            body: {
                status: string;
                duration?: number;
            };
        }) & object)) => Promise<BaseResponse<unknown>>;
        listUserSchedulers: (_: {
            path: UsersListUserSchedulersPathParams;
        } & object) => Promise<BaseResponse<UsersListUserSchedulersResponse>>;
        deleteUserSchedulers: (_: {
            path: UsersDeleteUserSchedulersPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteScheduler: (_: {
            path: UsersDeleteSchedulerPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getUserSettings: (_: {
            path: UsersGetUserSettingsPathParams;
        } & object & {
            query?: UsersGetUserSettingsQueryParams;
        }) => Promise<BaseResponse<UsersGetUserSettingsResponse>>;
        updateUserSettings: (_: {
            path: UsersUpdateUserSettingsPathParams;
        } & (({
            body?: {
                email_notification?: {
                    alternative_host_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    cloud_recording_available_reminder?: boolean;
                    jbh_reminder?: boolean;
                    recording_available_reminder_alternative_hosts?: boolean;
                    recording_available_reminder_schedulers?: boolean;
                    schedule_for_reminder?: boolean;
                };
                feature?: {
                    concurrent_meeting?: string;
                    large_meeting?: boolean;
                    large_meeting_capacity?: number;
                    meeting_capacity?: number;
                    webinar?: boolean;
                    webinar_capacity?: number;
                    zoom_events?: boolean;
                    zoom_events_capacity?: number;
                    zoom_events_unlimited?: boolean;
                    zoom_events_unlimited_capacities?: number[];
                    zoom_sessions_unlimited?: boolean;
                    zoom_sessions_unlimited_capacities?: number[];
                    zoom_events_pay_per_attendee?: boolean;
                    zoom_sessions_pay_per_attendee?: boolean;
                    zoom_phone?: boolean;
                    zoom_iq_for_sales?: boolean;
                    zoom_revenue_accelerator?: boolean;
                    zoom_whiteboard?: boolean;
                    zoom_whiteboard_plus?: boolean;
                    zoom_translated_captions?: boolean;
                    zoom_customer_managed_key?: boolean;
                    zoom_huddles?: boolean;
                    zoom_quality_management?: boolean;
                    zoom_workforce_management?: boolean;
                    zoom_scheduler?: boolean;
                    zoom_clips_plus?: boolean;
                    zoom_mail_calendar?: boolean;
                    zoom_compliance_management?: boolean;
                };
                in_meeting?: {
                    allow_host_to_enable_focus_mode?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_live_streaming?: boolean;
                    post_meeting_feedback?: boolean;
                    whiteboard?: boolean;
                    allow_participants_chat_with?: number;
                    allow_users_save_chats?: number;
                    annotation?: boolean;
                    attendee_on_hold?: boolean;
                    attention_mode_focus_mode?: boolean;
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
                    data_center_regions?: string[];
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
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
                        enable_language_interpretation_by_default?: boolean;
                        allow_participants_to_speak_in_listening_channel?: boolean;
                        allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
                        enable?: boolean;
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
                    meeting_reactions?: boolean;
                    meeting_reactions_emojis?: string;
                    allow_host_panelists_to_use_audible_clap?: boolean;
                    webinar_reactions?: boolean;
                    meeting_survey?: boolean;
                    non_verbal_feedback?: boolean;
                    polling?: boolean;
                    private_chat?: boolean;
                    record_play_voice?: boolean;
                    remote_control?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute_participants?: boolean;
                    screen_sharing?: boolean;
                    share_dual_camera?: boolean;
                    show_a_join_from_your_browser_link?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
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
                    waiting_room?: boolean;
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
                    meeting_polling?: {
                        advanced_polls?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        allow_host_to_upload_image?: boolean;
                        enable?: boolean;
                    };
                    webinar_polling?: {
                        advanced_polls?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        allow_host_to_upload_image?: boolean;
                        enable?: boolean;
                    };
                    webinar_survey?: boolean;
                    who_can_share_screen?: string;
                    who_can_share_screen_when_someone_is_sharing?: string;
                    participants_share_simultaneously?: string;
                    workplace_by_facebook?: boolean;
                    auto_answer?: boolean;
                    allow_show_zoom_windows?: boolean;
                };
                profile?: {
                    recording_storage_location?: {
                        allowed_values?: string[];
                        value?: string;
                    };
                };
                recording?: {
                    ask_host_to_confirm_disclaimer?: boolean;
                    ask_participants_to_consent_disclaimer?: boolean;
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
                    save_panelist_chat?: boolean;
                    save_poll_results?: boolean;
                    save_close_caption?: boolean;
                    auto_recording?: string;
                    cloud_recording?: boolean;
                    host_pause_stop_recording?: boolean;
                    ip_address_access_control?: {
                        enable?: boolean;
                        ip_addresses_or_ranges?: string;
                    };
                    local_recording?: boolean;
                    record_audio_file?: boolean;
                    record_gallery_view?: boolean;
                    record_speaker_view?: boolean;
                    recording_audio_transcript?: boolean;
                    recording_disclaimer?: boolean;
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
                    save_chat_text?: boolean;
                    show_timestamp?: boolean;
                };
                schedule_meeting?: {
                    audio_type?: string;
                    default_password_for_scheduled_meetings?: string;
                    embed_password_in_join_link?: boolean;
                    force_pmi_jbh_password?: boolean;
                    host_video?: boolean;
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
                    participants_video?: boolean;
                    personal_meeting?: boolean;
                    pmi_password?: string;
                    pstn_password_protected?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: string;
                    require_password_for_scheduled_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    use_pmi_for_instant_meetings?: boolean;
                    use_pmi_for_scheduled_meetings?: boolean;
                };
                telephony?: {
                    audio_conference_info?: string;
                    show_international_numbers_link?: boolean;
                    telephony_regions?: {
                        selection_values?: string;
                    };
                    third_party_audio?: boolean;
                };
                tsp?: {
                    call_out?: boolean;
                    call_out_countries?: object[];
                    show_international_numbers_link?: boolean;
                };
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
                };
            };
        }) & {
            query?: UsersUpdateUserSettingsQueryParams;
        })) => Promise<BaseResponse<unknown>>;
        uploadVirtualBackgroundFiles: (_: {
            path: UsersUploadVirtualBackgroundFilesPathParams;
        } & {
            body?: UsersUploadVirtualBackgroundFilesRequestBody;
        } & object) => Promise<BaseResponse<UsersUploadVirtualBackgroundFilesResponse>>;
        deleteVirtualBackgroundFiles: (_: {
            path: UsersDeleteVirtualBackgroundFilesPathParams;
        } & object & {
            query?: UsersDeleteVirtualBackgroundFilesQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateUserStatus: (_: {
            path: UsersUpdateUserStatusPathParams;
        } & {
            body: UsersUpdateUserStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUsersToken: (_: {
            path: UsersGetUsersTokenPathParams;
        } & object & {
            query?: UsersGetUsersTokenQueryParams;
        }) => Promise<BaseResponse<UsersGetUsersTokenResponse>>;
        revokeUsersSSOToken: (_: {
            path: UsersRevokeUsersSSOTokenPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
}

type GroupAdminAddedEvent = Event<"group.admin_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            admins: {
                id?: string;
                email?: string;
            }[];
        };
    };
};
type GroupLockSettingsUpdatedEvent = Event<"group.lock_settings_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: string;
            settings: {
                audio_conferencing?: {
                    toll_free_and_fee_based_toll_call?: boolean;
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
                    e2e_encryption?: boolean;
                    entry_exit_chime?: boolean;
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
                    non_verbal_feedback?: boolean;
                    original_audio?: boolean;
                    polling?: boolean;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    remote_control?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute?: boolean;
                    save_caption?: boolean;
                    save_captions?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_a_join_from_your_browser_link?: boolean;
                    show_browser_join_link?: boolean;
                    show_meeting_control_toolbar?: boolean;
                    slide_control?: boolean;
                    stereo_audio?: boolean;
                    use_html_format_email?: boolean;
                    virtual_background?: boolean;
                    waiting_room?: boolean;
                    webinar_chat?: boolean;
                    webinar_live_streaming?: boolean;
                    webinar_polling?: boolean;
                    webinar_question_answer?: boolean;
                    meeting_question_answer?: boolean;
                    webinar_survey?: boolean;
                    whiteboard?: boolean;
                };
                other_options?: {
                    blur_snapshot?: boolean;
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
                    force_pmi_jbh_password?: boolean;
                    host_video?: boolean;
                    join_before_host?: boolean;
                    meeting_authentication?: boolean;
                    mute_upon_entry?: boolean;
                    participant_video?: boolean;
                    pstn_password_protected?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    upcoming_meeting_reminder?: boolean;
                };
                telephony?: {
                    telephony_regions?: boolean;
                    third_party_audio?: boolean;
                };
                meeting_security?: {
                    approved_or_denied_countries_or_regions?: boolean;
                    auto_security?: boolean;
                    block_user_domain?: boolean;
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
        };
        time_stamp?: number;
    };
};
type GroupAdminDeletedEvent = Event<"group.admin_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            admins: {
                id?: string;
                email?: string;
            }[];
        };
    };
};
type GroupMemberDeletedEvent = Event<"group.member_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            members: {
                id?: string;
                email?: string;
            }[];
        };
    };
};
type UserDeletedEvent = Event<"user.deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: string;
            first_name?: string;
            last_name?: string;
            email: string;
            type: number;
        };
    };
};
type UserDeactivatedEvent = Event<"user.deactivated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: string;
            first_name: string;
            last_name: string;
            email: string;
            type: number;
        };
    };
};
type UserSettingsUpdatedEvent = Event<"user.settings_updated"> & {
    event: string;
    event_ts: number;
    operator?: string;
    operator_id?: string;
    time_stamp?: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            settings: {
                schedule_meeting?: {
                    host_video?: boolean;
                    participants_video?: boolean;
                    audio_type?: string;
                    join_before_host?: boolean;
                    force_pmi_jbh_password?: string;
                    use_pmi_for_scheduled_meetings?: boolean;
                    pstn_password_protected?: string;
                    jbh_time?: number;
                    personal_meeting?: boolean;
                    default_password_for_scheduled_meetings?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    mute_upon_entry?: boolean;
                    require_password_for_pmi_meetings?: string;
                    use_pmi_for_instant_meetings?: boolean;
                    require_password_for_scheduled_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    pmi_password?: string;
                    upcoming_meeting_reminder?: boolean;
                };
                in_meeting?: {
                    e2e_encryption?: boolean;
                    chat?: boolean;
                    post_meeting_feedback?: boolean;
                    whiteboard?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_participants_chat_with?: number;
                    allow_users_save_chats?: number;
                    private_chat?: boolean;
                    attention_mode_focus_mode?: boolean;
                    allow_host_to_enable_focus_mode?: boolean;
                    auto_saving_chat?: boolean;
                    entry_exit_chime?: string;
                    record_play_voice?: boolean;
                    file_transfer?: boolean;
                    feedback?: boolean;
                    co_host?: boolean;
                    polling?: boolean;
                    meeting_polling?: {
                        enable?: boolean;
                        advanced_polls?: boolean;
                        require_answers_to_be_anonymous?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        allow_host_to_upload_image?: boolean;
                    };
                    attendee_on_hold?: boolean;
                    annotation?: boolean;
                    remote_control?: boolean;
                    non_verbal_feedback?: boolean;
                    breakout_room?: boolean;
                    breakout_room_schedule?: boolean;
                    remote_support?: boolean;
                    screen_sharing?: boolean;
                    who_can_share_screen?: string;
                    who_can_share_screen_when_someone_is_sharing?: string;
                    participants_share_simultaneously?: string;
                    closed_caption?: boolean;
                    group_hd?: boolean;
                    far_end_camera_control?: boolean;
                    share_dual_camera?: boolean;
                    waiting_room?: boolean;
                    virtual_background?: boolean;
                    virtual_background_settings?: {
                        enable?: boolean;
                        allow_videos?: boolean;
                        allow_upload_custom?: boolean;
                        files?: {
                            id?: string;
                            name?: string;
                            type?: string;
                            is_default?: boolean;
                            size?: number;
                        }[];
                    };
                    custom_data_center_regions?: boolean;
                    data_center_regions?: string[];
                    language_interpretation?: {
                        enable?: boolean;
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
                    sign_language_interpretation?: {
                        enable?: boolean;
                        enable_sign_language_interpretation_by_default?: boolean;
                        languages?: string[];
                        custom_languages?: string[];
                    };
                    meeting_question_answer?: boolean;
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
                        allow_host_to_upload_image?: boolean;
                    };
                    webinar_survey?: boolean;
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
                    auto_answer?: boolean;
                    allow_show_zoom_windows?: boolean;
                };
                email_notification?: {
                    cloud_recording_available_reminder?: boolean;
                    recording_available_reminder_schedulers?: boolean;
                    recording_available_reminder_alternative_hosts?: boolean;
                    jbh_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    alternative_host_reminder?: boolean;
                    schedule_for_reminder?: boolean;
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
                };
                telephony?: {
                    third_party_audio?: boolean;
                    audio_conference_info?: string;
                    show_international_numbers_link?: boolean;
                    telephony_regions?: {
                        allowed_values?: string[];
                        selection_values?: string;
                    };
                };
                feature?: {
                    meeting_capacity?: number;
                    large_meeting?: boolean;
                    large_meeting_capacity?: number;
                    webinar?: boolean;
                    webinar_capacity?: number;
                    zoom_events?: boolean;
                    zoom_events_capacity?: number;
                    cn_meeting?: boolean;
                    in_meeting?: boolean;
                    zoom_phone?: boolean;
                    concurrent_meeting?: string;
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
                    only_authenticated_can_join_from_webclient?: boolean;
                    block_user_domain_list?: string[];
                };
                tsp?: {
                    call_out?: boolean;
                    call_out_countries?: string[];
                    show_international_numbers_link?: boolean;
                    display_toll_free_numbers?: boolean;
                };
            };
        };
    };
};
type UserInvitationAcceptedEvent = Event<"user.invitation_accepted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            first_name?: string;
            last_name?: string;
            email: string;
            type: number;
        };
    };
};
type GroupCreatedEvent = Event<"group.created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            name: string;
        };
    };
};
type GroupSettingsUpdatedEvent = Event<"group.settings_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: string;
            settings: {
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
                email_notification?: {
                    alternative_host_reminder?: boolean;
                    cancel_meeting_reminder?: boolean;
                    cloud_recording_available_reminder?: boolean;
                    jbh_reminder?: boolean;
                    recording_available_reminder_alternative_hosts?: boolean;
                    recording_available_reminder_schedulers?: boolean;
                    schedule_for_reminder?: boolean;
                };
                in_meeting?: {
                    alert_guest_join?: boolean;
                    allow_users_to_delete_messages_in_meeting_chat?: boolean;
                    allow_live_streaming?: boolean;
                    allow_participants_chat_with?: number;
                    allow_show_zoom_windows?: boolean;
                    allow_users_save_chats?: number;
                    annotation?: boolean;
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
                    data_center_regions?: string[];
                    disable_screen_sharing_for_host_meetings?: boolean;
                    disable_screen_sharing_for_in_meeting_guests?: boolean;
                    e2e_encryption?: boolean;
                    entry_exit_chime?: boolean;
                    far_end_camera_control?: boolean;
                    feedback?: boolean;
                    file_transfer?: boolean;
                    group_hd?: boolean;
                    join_from_desktop?: boolean;
                    join_from_mobile?: boolean;
                    language_interpretation?: {
                        custom_languages?: string[];
                        enable_language_interpretation_by_default?: boolean;
                        allow_participants_to_speak_in_listening_channel?: boolean;
                        allow_up_to_25_custom_languages_when_scheduling_meetings?: boolean;
                        enable?: boolean;
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
                        require_answers_to_be_anonymous?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
                        manage_saved_polls_and_quizzes?: boolean;
                        allow_host_to_upload_image?: boolean;
                        enable?: boolean;
                    };
                    meeting_reactions?: boolean;
                    meeting_reactions_emojis?: string;
                    allow_host_panelists_to_use_audible_clap?: boolean;
                    webinar_reactions?: boolean;
                    meeting_survey?: boolean;
                    non_verbal_feedback?: boolean;
                    only_host_view_device_list?: boolean;
                    original_audio?: boolean;
                    polling?: boolean;
                    post_meeting_feedback?: boolean;
                    private_chat?: boolean;
                    record_play_own_voice?: boolean;
                    remote_control?: boolean;
                    remote_support?: boolean;
                    request_permission_to_unmute?: boolean;
                    screen_sharing?: boolean;
                    sending_default_email_invites?: boolean;
                    show_a_join_from_your_browser_link?: boolean;
                    show_device_list?: boolean;
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
                    waiting_room?: boolean;
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
                        require_answers_to_be_anonymous?: boolean;
                        allow_alternative_host_to_add_edit?: boolean;
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
                };
                other_options?: {
                    allow_users_contact_support_via_chat?: boolean;
                    blur_snapshot?: boolean;
                    webinar_registration_options?: {
                        allow_host_to_enable_social_share_buttons?: boolean;
                    };
                };
                profile?: {
                    recording_storage_location?: {
                        allowed_values?: string[];
                        value?: string;
                    };
                };
                recording?: {
                    account_user_access_recording?: boolean;
                    archive?: {
                        enable?: boolean;
                        settings?: {
                            audio_file?: boolean;
                            cc_transcript_file?: boolean;
                            chat_file?: boolean;
                            chat_with_sender_email?: boolean;
                            video_file?: boolean;
                        };
                        type?: number;
                    };
                    auto_recording?: boolean;
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
                    recording_highlight?: boolean;
                    smart_recording?: {
                        create_recording_highlights?: boolean;
                        create_smart_chapters?: boolean;
                        create_next_steps?: boolean;
                    };
                    recording_thumbnails?: boolean;
                    save_chat_text?: boolean;
                    save_close_caption?: boolean;
                    save_panelist_chat?: boolean;
                    save_poll_results?: boolean;
                    show_timestamp?: boolean;
                };
                schedule_meeting?: {
                    audio_type?: boolean;
                    embed_password_in_join_link?: boolean;
                    force_pmi_jbh_password?: boolean;
                    host_video?: boolean;
                    join_before_host?: boolean;
                    mute_upon_entry?: boolean;
                    participant_video?: boolean;
                    personal_meeting?: boolean;
                    pstn_password_protected?: boolean;
                    require_password_for_instant_meetings?: boolean;
                    require_password_for_pmi_meetings?: string;
                    require_password_for_scheduled_meetings?: boolean;
                    require_password_for_scheduling_new_meetings?: boolean;
                    upcoming_meeting_reminder?: boolean;
                    use_pmi_for_instant_meetings?: boolean;
                    use_pmi_for_schedule_meetings?: boolean;
                    always_display_zoom_meeting_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_meetings?: boolean;
                    };
                    always_display_zoom_webinar_as_topic?: {
                        enable?: boolean;
                        display_topic_for_scheduled_webinars?: boolean;
                    };
                };
                telephony?: {
                    audio_conference_info?: string;
                    telephony_regions?: {
                        selection_values?: string;
                    };
                    third_party_audio?: boolean;
                };
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
                };
                chat?: {
                    share_files?: {
                        enable?: boolean;
                        share_option?: string;
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
                    allow_users_to_search_others_options?: string;
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
                            id?: string;
                            status?: string;
                        }[];
                    };
                    send_data_to_third_party_archiving_service?: {
                        enable?: boolean;
                    };
                };
            };
        };
        time_stamp?: number;
    };
};
type UserDisassociatedEvent = Event<"user.disassociated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: string;
            first_name: string;
            last_name: string;
            email: string;
            type: number;
        };
    };
};
type GroupUpdatedEvent = Event<"group.updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            name: string;
        };
    };
};
type UserPresenceStatusUpdatedEvent = Event<"user.presence_status_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            date_time: string;
            email: string;
            id: string;
            presence_status: string;
            app?: {
                type: string;
                presence_status: string;
            };
        };
    };
};
type UserActivatedEvent = Event<"user.activated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: string;
            first_name: string;
            last_name: string;
            email: string;
            type: number;
        };
    };
};
type UserSignedInEvent = Event<"user.signed_in"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            client_type: string;
            date_time: string;
            email: string;
            version: string;
            login_type: number;
        };
    };
};
type UserSignedOutEvent = Event<"user.signed_out"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            client_type: string;
            date_time: string;
            email: string;
            version: string;
            login_type: number;
        };
    };
};
type UserPersonalNotesUpdatedEvent = Event<"user.personal_notes_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            date_time: string;
            email: string;
            id: string;
            personal_notes: string;
        };
        old_object: {
            personal_notes: string;
        };
    };
};
type GroupMemberAddedEvent = Event<"group.member_added"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            members: {
                id?: string;
                email?: string;
            }[];
        };
    };
};
type UserUpdatedEvent = Event<"user.updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator?: string;
        operator_id?: string;
        operation?: string;
        object: {
            id: string;
            first_name?: string;
            last_name?: string;
            display_name?: string;
            email?: string;
            type?: number;
            phone_number?: string;
            phone_country?: string;
            company?: string;
            pmi?: number;
            use_pmi?: boolean;
            timezone?: string;
            pic_url?: string;
            vanity_name?: string;
            host_key?: string;
            role?: string;
            dept?: string;
            language?: string;
            settings?: {
                feature?: {
                    large_meeting_capacity?: number;
                    webinar?: boolean;
                    webinar_capacity?: number;
                };
                meeting_capacity?: number;
                large_meeting?: string;
            };
            custom_attributes?: {
                key: string;
                name: string;
                value: number;
            }[];
            primary_group_id?: string;
        };
        time_stamp?: number;
    };
};
type GroupDeletedEvent = Event<"group.deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp?: number;
        object: {
            id: string;
            name: string;
        };
    };
};
type UserCreatedEvent = Event<"user.created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        creation_type: string;
        object: {
            id: string;
            first_name?: string;
            last_name?: string;
            display_name?: string;
            email: string;
            type: number;
        };
    };
};
type UsersEvents = GroupAdminAddedEvent | GroupLockSettingsUpdatedEvent | GroupAdminDeletedEvent | GroupMemberDeletedEvent | UserDeletedEvent | UserDeactivatedEvent | UserSettingsUpdatedEvent | UserInvitationAcceptedEvent | GroupCreatedEvent | GroupSettingsUpdatedEvent | UserDisassociatedEvent | GroupUpdatedEvent | UserPresenceStatusUpdatedEvent | UserActivatedEvent | UserSignedInEvent | UserSignedOutEvent | UserPersonalNotesUpdatedEvent | GroupMemberAddedEvent | UserUpdatedEvent | GroupDeletedEvent | UserCreatedEvent;
declare class UsersEventProcessor extends EventManager<UsersEndpoints, UsersEvents> {
}

type UsersOAuthOptions<R extends Receiver> = CommonClientOptions<OAuth, R>;
declare class UsersOAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<OAuth, ReceiverType> = UsersOAuthOptions<ReceiverType>> extends ProductClient<OAuth, UsersEndpoints, UsersEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, ...restOptions }: OptionsType): OAuth;
    protected initEndpoints(auth: OAuth, options: OptionsType): UsersEndpoints;
    protected initEventProcessor(endpoints: UsersEndpoints): UsersEventProcessor;
}

type UsersS2SAuthOptions<R extends Receiver> = CommonClientOptions<S2SAuth, R>;
declare class UsersS2SAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<S2SAuth, ReceiverType> = UsersS2SAuthOptions<ReceiverType>> extends ProductClient<S2SAuth, UsersEndpoints, UsersEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, accountId }: OptionsType): S2SAuth;
    protected initEndpoints(auth: S2SAuth, options: OptionsType): UsersEndpoints;
    protected initEventProcessor(endpoints: UsersEndpoints): UsersEventProcessor;
}

export { ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, type ClientCredentialsToken, CommonHttpRequestError, ConsoleLogger, type ContactGroupsAddContactGroupMembersPathParams, type ContactGroupsAddContactGroupMembersRequestBody, type ContactGroupsAddContactGroupMembersResponse, type ContactGroupsCreateContactGroupRequestBody, type ContactGroupsCreateContactGroupResponse, type ContactGroupsDeleteContactGroupPathParams, type ContactGroupsGetContactGroupPathParams, type ContactGroupsGetContactGroupResponse, type ContactGroupsListContactGroupMembersPathParams, type ContactGroupsListContactGroupMembersQueryParams, type ContactGroupsListContactGroupMembersResponse, type ContactGroupsListContactGroupsQueryParams, type ContactGroupsListContactGroupsResponse, type ContactGroupsRemoveMembersInContactGroupPathParams, type ContactGroupsRemoveMembersInContactGroupQueryParams, type ContactGroupsUpdateContactGroupPathParams, type ContactGroupsUpdateContactGroupRequestBody, type GroupAdminAddedEvent, type GroupAdminDeletedEvent, type GroupCreatedEvent, type GroupDeletedEvent, type GroupLockSettingsUpdatedEvent, type GroupMemberAddedEvent, type GroupMemberDeletedEvent, type GroupSettingsUpdatedEvent, type GroupUpdatedEvent, type GroupsAddGroupAdminsPathParams, type GroupsAddGroupAdminsRequestBody, type GroupsAddGroupMembersPathParams, type GroupsAddGroupMembersRequestBody, type GroupsCreateGroupRequestBody, type GroupsDeleteGroupAdminPathParams, type GroupsDeleteGroupMemberPathParams, type GroupsDeleteGroupPathParams, type GroupsDeleteVirtualBackgroundFilesPathParams, type GroupsDeleteVirtualBackgroundFilesQueryParams, type GroupsGetGroupPathParams, type GroupsGetGroupResponse, type GroupsGetGroupsSettingsPathParams, type GroupsGetGroupsSettingsQueryParams, type GroupsGetGroupsSettingsResponse, type GroupsGetGroupsWebinarRegistrationSettingsPathParams, type GroupsGetGroupsWebinarRegistrationSettingsQueryParams, type GroupsGetGroupsWebinarRegistrationSettingsResponse, type GroupsGetLockedSettingsPathParams, type GroupsGetLockedSettingsQueryParams, type GroupsGetLockedSettingsResponse, type GroupsListGroupAdminsPathParams, type GroupsListGroupAdminsQueryParams, type GroupsListGroupAdminsResponse, type GroupsListGroupChannelsPathParams, type GroupsListGroupChannelsResponse, type GroupsListGroupMembersPathParams, type GroupsListGroupMembersQueryParams, type GroupsListGroupMembersResponse, type GroupsListGroupsResponse, type GroupsUpdateGroupMemberPathParams, type GroupsUpdateGroupMemberRequestBody, type GroupsUpdateGroupPathParams, type GroupsUpdateGroupRequestBody, type GroupsUpdateGroupsSettingsPathParams, type GroupsUpdateGroupsSettingsQueryParams, type GroupsUpdateGroupsSettingsRequestBody, type GroupsUpdateGroupsSettingsResponse, type GroupsUpdateGroupsWebinarRegistrationSettingsPathParams, type GroupsUpdateGroupsWebinarRegistrationSettingsQueryParams, type GroupsUpdateGroupsWebinarRegistrationSettingsRequestBody, type GroupsUpdateLockedSettingsPathParams, type GroupsUpdateLockedSettingsQueryParams, type GroupsUpdateLockedSettingsRequestBody, type GroupsUploadVirtualBackgroundFilesPathParams, type GroupsUploadVirtualBackgroundFilesRequestBody, type GroupsUploadVirtualBackgroundFilesResponse, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, type HttpReceiverOptions, type JwtToken, LogLevel, type Logger, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, type OAuthToken, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, type Receiver, ReceiverInconsistentStateError, type ReceiverInitOptions, ReceiverOAuthFlowError, type S2SAuthToken, S2SRawResponseError, type StateStore, StatusCode, type TokenStore, type UserActivatedEvent, type UserCreatedEvent, type UserDeactivatedEvent, type UserDeletedEvent, type UserDisassociatedEvent, type UserInvitationAcceptedEvent, type UserPersonalNotesUpdatedEvent, type UserPresenceStatusUpdatedEvent, type UserSettingsUpdatedEvent, type UserSignedInEvent, type UserSignedOutEvent, type UserUpdatedEvent, type UsersAddAssistantsPathParams, type UsersAddAssistantsRequestBody, type UsersAddAssistantsResponse, type UsersBulkUpdateFeaturesForUserRequestBody, type UsersBulkUpdateFeaturesForUserResponse, type UsersCheckUserEmailQueryParams, type UsersCheckUserEmailResponse, type UsersCheckUsersPMRoomQueryParams, type UsersCheckUsersPMRoomResponse, type UsersCreateUsersRequestBody, type UsersCreateUsersResponse, type UsersDeleteSchedulerPathParams, type UsersDeleteUserAssistantPathParams, type UsersDeleteUserAssistantsPathParams, type UsersDeleteUserPathParams, type UsersDeleteUserQueryParams, type UsersDeleteUserSchedulersPathParams, type UsersDeleteUsersProfilePicturePathParams, type UsersDeleteVirtualBackgroundFilesPathParams, type UsersDeleteVirtualBackgroundFilesQueryParams, UsersEndpoints, UsersEventProcessor, type UsersGetCollaborationDeviceDetailPathParams, type UsersGetCollaborationDeviceDetailResponse, type UsersGetMeetingTemplateDetailPathParams, type UsersGetMeetingTemplateDetailResponse, type UsersGetUserPathParams, type UsersGetUserPermissionsPathParams, type UsersGetUserPermissionsResponse, type UsersGetUserPresenceStatusPathParams, type UsersGetUserPresenceStatusResponse, type UsersGetUserQueryParams, type UsersGetUserResponse, type UsersGetUserSettingsPathParams, type UsersGetUserSettingsQueryParams, type UsersGetUserSettingsResponse, type UsersGetUserSummaryResponse, type UsersGetUsersTokenPathParams, type UsersGetUsersTokenQueryParams, type UsersGetUsersTokenResponse, type UsersGetUsersZAKResponse, type UsersListUserAssistantsPathParams, type UsersListUserAssistantsResponse, type UsersListUserSchedulersPathParams, type UsersListUserSchedulersResponse, type UsersListUsersCollaborationDevicesPathParams, type UsersListUsersCollaborationDevicesResponse, type UsersListUsersQueryParams, type UsersListUsersResponse, UsersOAuthClient, type UsersOAuthOptions, type UsersRevokeUsersSSOTokenPathParams, UsersS2SAuthClient, type UsersS2SAuthOptions, type UsersUpdateUserPathParams, type UsersUpdateUserQueryParams, type UsersUpdateUserRequestBody, type UsersUpdateUserSettingsPathParams, type UsersUpdateUserSettingsQueryParams, type UsersUpdateUserSettingsRequestBody, type UsersUpdateUserStatusPathParams, type UsersUpdateUserStatusRequestBody, type UsersUpdateUsersEmailPathParams, type UsersUpdateUsersEmailRequestBody, type UsersUpdateUsersPasswordPathParams, type UsersUpdateUsersPasswordRequestBody, type UsersUpdateUsersPresenceStatusPathParams, type UsersUpdateUsersPresenceStatusRequestBody, type UsersUploadUsersProfilePicturePathParams, type UsersUploadUsersProfilePictureRequestBody, type UsersUploadUsersProfilePictureResponse, type UsersUploadVirtualBackgroundFilesPathParams, type UsersUploadVirtualBackgroundFilesRequestBody, type UsersUploadVirtualBackgroundFilesResponse, isCoreError, isStateStore };
