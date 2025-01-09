import { LambdaFunctionURLResult, LambdaFunctionURLHandler } from 'aws-lambda';
import { AxiosResponse } from 'axios';
import { Server } from 'node:http';
import { ServerOptions } from 'node:https';
import { ReadStream } from 'node:fs';

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
type ProhibitKeys<K extends keyof any> = {
    [P in K]?: never;
};
type StringIndexed<V = any> = Record<string, V>;

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

interface TokenStore<Token> {
    getLatestToken(): MaybePromise<Token | null | undefined>;
    storeToken(token: Token): MaybePromise<void>;
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

interface HttpReceiverOptions extends Partial<SecureServerOptions> {
    endpoints?: MaybeArray<string> | undefined;
    port?: number | string | undefined;
    webhooksSecretToken: string;
    logger?: Logger;
    logLevel?: LogLevel;
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
    private getServerCreator;
    private hasEndpoint;
    private hasSecureOptions;
    init({ eventEmitter, interactiveAuth }: ReceiverInitOptions): void;
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
type ClientConstructorOptions<A extends Auth, O extends CommonClientOptions<A, R>, R extends Receiver> = IsReceiverDisabled<O> extends true ? O : O & (ClientReceiverOptions<R> | HttpReceiverOptions);
type ExtractInstallerOptions<A extends Auth, R extends Receiver> = A extends InteractiveAuth ? [
    ReturnType<R["canInstall"]>
] extends [true] ? WideInstallerOptions : object : object;
type ExtractAuthTokenType<A> = A extends Auth<infer T> ? T : never;
type GenericClientOptions = CommonClientOptions<any, any>;
type GetAuthOptions<A extends Auth> = AuthOptions<ExtractAuthTokenType<A>> & (A extends S2SAuth ? S2SAuthOptions : object);
type IsReceiverDisabled<O extends Pick<GenericClientOptions, "disableReceiver">> = [
    O["disableReceiver"]
] extends [true] ? true : false;
type WideInstallerOptions = {
    installerOptions: InstallerOptions;
};
declare abstract class ProductClient<AuthType extends Auth, EndpointsType extends WebEndpoints, EventProcessorType extends GenericEventManager, OptionsType extends CommonClientOptions<AuthType, ReceiverType>, ReceiverType extends Receiver> {
    private readonly auth;
    readonly endpoints: EndpointsType;
    readonly webEventConsumer: EventProcessorType;
    private readonly receiver?;
    constructor(options: ClientConstructorOptions<AuthType, OptionsType, ReceiverType>);
    protected abstract initAuth(options: OptionsType): AuthType;
    protected abstract initEndpoints(auth: AuthType, options: OptionsType): EndpointsType;
    protected abstract initEventProcessor(endpoints: EndpointsType, options: OptionsType): EventProcessorType;
    private initDefaultReceiver;
    start(this: IsReceiverDisabled<OptionsType> extends true ? never : this): Promise<ReturnType<ReceiverType["start"]>>;
}

interface InstallerOptions {
    directInstall?: boolean | undefined;
    installPath?: string | undefined;
    redirectUri: string;
    redirectUriPath?: string | undefined;
    stateStore: StateStore | string;
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
    getAuthorizationUrl(): Promise<string>;
    getFullRedirectUri(): string;
    setInstallerOptions({ directInstall, installPath, redirectUri, redirectUriPath, stateStore }: InstallerOptions): {
        directInstall: boolean;
        installPath: string;
        redirectUri: string;
        redirectUriPath: string;
        stateStore: StateStore;
    };
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
    eventEmitter: GenericEventManager;
    interactiveAuth?: InteractiveAuth | undefined;
}
interface Receiver {
    canInstall(): true | false;
    init(options: ReceiverInitOptions): void;
    start(...args: any[]): MaybePromise<unknown>;
    stop(...args: any[]): MaybePromise<unknown>;
}

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

type ArchivingListArchivedFilesQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    query_date_type?: string;
    group_id?: string;
    group_ids?: string;
};
type ArchivingListArchivedFilesResponse = {
    from?: string;
    meetings?: {
        account_name: string;
        archive_files: {
            download_url: string;
            file_extension: string;
            file_path?: string;
            file_size: number;
            file_type: string;
            id: string;
            individual: boolean;
            participant_email?: string;
            participant_join_time: string;
            participant_leave_time: string;
            recording_type: string;
            status: string;
            encryption_fingerprint: string;
            number_of_messages?: number;
            storage_location?: string;
            auto_delete?: boolean;
        }[];
        complete_time: string;
        duration: number;
        duration_in_second: number;
        host_id: string;
        id: number;
        is_breakout_room: boolean;
        meeting_type: string;
        parent_meeting_id?: string;
        recording_count: number;
        start_time: string;
        timezone: string;
        topic: string;
        total_size: number;
        type: number;
        uuid: string;
        status: string;
        group_id?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
    to?: string;
    total_records?: number;
};
type ArchivingGetArchivedFileStatisticsQueryParams = {
    from?: string;
    to?: string;
};
type ArchivingGetArchivedFileStatisticsResponse = {
    from?: string;
    to?: string;
    total_records?: number;
    statistic_by_file_extension?: {
        mp4_file_count?: number;
        m4a_file_count?: number;
        txt_file_count?: number;
        json_file_count?: number;
        vtt_file_count?: number;
    };
    statistic_by_file_status?: {
        processing_file_count?: number;
        completed_file_count?: number;
        failed_file_count?: number;
    };
};
type ArchivingUpdateArchivedFilesAutoDeleteStatusPathParams = {
    fileId: string;
};
type ArchivingUpdateArchivedFilesAutoDeleteStatusRequestBody = {
    auto_delete: boolean;
};
type ArchivingGetMeetingsArchivedFilesPathParams = {
    meetingUUID: string;
};
type ArchivingGetMeetingsArchivedFilesResponse = {
    account_name: string;
    archive_files: {
        download_url: string;
        file_extension: string;
        file_path?: string;
        file_size: number;
        file_type: string;
        id: string;
        individual: boolean;
        participant_email?: string;
        participant_join_time: string;
        participant_leave_time: string;
        recording_type: string;
        status: string;
        encryption_fingerprint: string;
        number_of_messages?: number;
        storage_location?: string;
        auto_delete?: boolean;
    }[];
    complete_time: string;
    duration: number;
    duration_in_second: number;
    host_id: string;
    id: number;
    is_breakout_room: boolean;
    meeting_type: string;
    parent_meeting_id?: string;
    recording_count: number;
    start_time: string;
    timezone: string;
    topic: string;
    total_size: number;
    type: number;
    uuid: string;
    status: string;
    group_id?: string;
};
type ArchivingDeleteMeetingsArchivedFilesPathParams = {
    meetingUUID: string;
};
type CloudRecordingGetMeetingRecordingsPathParams = {
    meetingId: string;
};
type CloudRecordingGetMeetingRecordingsQueryParams = {
    include_fields?: string;
    ttl?: number;
};
type CloudRecordingGetMeetingRecordingsResponse = ({
    account_id?: string;
    duration?: number;
    host_id?: string;
    id?: number;
    recording_count?: number;
    start_time?: string;
    topic?: string;
    total_size?: number;
    type?: string;
    uuid?: string;
    recording_play_passcode?: string;
    auto_delete?: boolean;
    auto_delete_date?: string;
} & {
    recording_files?: {
        deleted_time?: string;
        download_url?: string;
        file_path?: string;
        file_size?: number;
        file_type?: string;
        file_extension?: string;
        id?: string;
        meeting_id?: string;
        play_url?: string;
        recording_end?: string;
        recording_start?: string;
        recording_type?: string;
        status?: string;
    }[];
}) & {
    download_access_token?: string;
    password?: string;
    recording_play_passcode?: string;
} & {
    participant_audio_files?: {
        download_url?: string;
        file_name?: string;
        file_path?: string;
        file_size?: number;
        file_type?: string;
        id?: string;
        play_url?: string;
        recording_end?: string;
        recording_start?: string;
        status?: string;
    }[];
};
type CloudRecordingDeleteMeetingOrWebinarRecordingsPathParams = {
    meetingId: string;
};
type CloudRecordingDeleteMeetingOrWebinarRecordingsQueryParams = {
    action?: string;
};
type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsPathParams = {
    meetingId: string;
};
type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    type?: string;
};
type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsResponse = {
    from?: string;
    to?: string;
    next_page_token?: string;
    page_size?: number;
    total_records?: number;
    analytics_details?: {
        date_time?: string;
        name?: string;
        email?: string;
        duration?: number;
    }[];
};
type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryPathParams = {
    meetingId: string;
};
type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryQueryParams = {
    from?: string;
    to?: string;
};
type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryResponse = {
    from?: string;
    to?: string;
    analytics_summary?: {
        date?: string;
        views_total_count?: number;
        downloads_total_count?: number;
    }[];
};
type CloudRecordingListRecordingRegistrantsPathParams = {
    meetingId: number;
};
type CloudRecordingListRecordingRegistrantsQueryParams = {
    status?: string;
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type CloudRecordingListRecordingRegistrantsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    registrants?: ({
        id?: string;
    } & {
        address?: string;
        city?: string;
        comments?: string;
        country?: string;
        custom_questions?: {
            title?: string;
            value?: string;
        }[];
        email: string;
        first_name: string;
        industry?: string;
        job_title?: string;
        last_name?: string;
        no_of_employees?: string;
        org?: string;
        phone?: string;
        purchasing_time_frame?: string;
        role_in_purchase_process?: string;
        state?: string;
        status?: string;
        zip?: string;
    })[];
};
type CloudRecordingCreateRecordingRegistrantPathParams = {
    meetingId: number;
};
type CloudRecordingCreateRecordingRegistrantRequestBody = {
    address?: string;
    city?: string;
    comments?: string;
    country?: string;
    custom_questions?: {
        title?: string;
        value?: string;
    }[];
    email: string;
    first_name: string;
    industry?: string;
    job_title?: string;
    last_name?: string;
    no_of_employees?: string;
    org?: string;
    phone?: string;
    purchasing_time_frame?: string;
    role_in_purchase_process?: string;
    state?: string;
    status?: string;
    zip?: string;
};
type CloudRecordingCreateRecordingRegistrantResponse = {
    id?: number;
    registrant_id?: string;
    share_url?: string;
    topic?: string;
};
type CloudRecordingGetRegistrationQuestionsPathParams = {
    meetingId: string;
};
type CloudRecordingGetRegistrationQuestionsResponse = {
    custom_questions?: {
        answers?: string[];
        required?: boolean;
        title?: string;
        type?: string;
    }[];
    questions?: {
        field_name?: string;
        required?: boolean;
    }[];
};
type CloudRecordingUpdateRegistrationQuestionsPathParams = {
    meetingId: string;
};
type CloudRecordingUpdateRegistrationQuestionsRequestBody = {
    custom_questions?: {
        answers?: string[];
        required?: boolean;
        title?: string;
        type?: string;
    }[];
    questions?: {
        field_name?: string;
        required?: boolean;
    }[];
};
type CloudRecordingUpdateRegistrantsStatusPathParams = {
    meetingId: number;
};
type CloudRecordingUpdateRegistrantsStatusRequestBody = {
    action: string;
    registrants?: {
        id?: string;
    }[];
};
type CloudRecordingGetMeetingRecordingSettingsPathParams = {
    meetingId: string;
};
type CloudRecordingGetMeetingRecordingSettingsResponse = {
    approval_type?: number;
    authentication_domains?: string;
    authentication_option?: string;
    on_demand?: boolean;
    password?: string;
    recording_authentication?: boolean;
    send_email_to_host?: boolean;
    share_recording?: string;
    show_social_share_buttons?: boolean;
    topic?: string;
    viewer_download?: boolean;
    auto_delete?: boolean;
    auto_delete_date?: string;
};
type CloudRecordingUpdateMeetingRecordingSettingsPathParams = {
    meetingId: string;
};
type CloudRecordingUpdateMeetingRecordingSettingsRequestBody = {
    approval_type?: number;
    authentication_domains?: string;
    authentication_option?: string;
    on_demand?: boolean;
    password?: string;
    recording_authentication?: boolean;
    send_email_to_host?: boolean;
    share_recording?: string;
    show_social_share_buttons?: boolean;
    topic?: string;
    viewer_download?: boolean;
    auto_delete?: boolean;
};
type CloudRecordingDeleteRecordingFileForMeetingOrWebinarPathParams = {
    meetingId: string;
    recordingId: string;
};
type CloudRecordingDeleteRecordingFileForMeetingOrWebinarQueryParams = {
    action?: string;
};
type CloudRecordingRecoverSingleRecordingPathParams = {
    meetingId: string;
    recordingId: string;
};
type CloudRecordingRecoverSingleRecordingRequestBody = {
    action?: string;
};
type CloudRecordingRecoverMeetingRecordingsPathParams = {
    meetingUUID: string;
};
type CloudRecordingRecoverMeetingRecordingsRequestBody = {
    action?: string;
};
type CloudRecordingListAllRecordingsPathParams = {
    userId: string;
};
type CloudRecordingListAllRecordingsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    mc?: string;
    trash?: boolean;
    from?: string;
    to?: string;
    trash_type?: string;
    meeting_id?: number;
};
type CloudRecordingListAllRecordingsResponse = {
    from?: string;
    to?: string;
} & {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    meetings?: ({
        account_id?: string;
        duration?: number;
        host_id?: string;
        id?: number;
        recording_count?: number;
        start_time?: string;
        topic?: string;
        total_size?: number;
        type?: string;
        uuid?: string;
        recording_play_passcode?: string;
        auto_delete?: boolean;
        auto_delete_date?: string;
    } & {
        recording_files?: {
            deleted_time?: string;
            download_url?: string;
            file_path?: string;
            file_size?: number;
            file_type?: string;
            file_extension?: string;
            id?: string;
            meeting_id?: string;
            play_url?: string;
            recording_end?: string;
            recording_start?: string;
            recording_type?: string;
            status?: string;
        }[];
    })[];
};
type DevicesListDevicesQueryParams = {
    search_text?: string;
    platform_os?: string;
    is_enrolled_in_zdm?: boolean;
    device_type?: number;
    device_vendor?: string;
    device_model?: string;
    device_status?: number;
    page_size?: number;
    next_page_token?: string;
};
type DevicesListDevicesResponse = {
    next_page_token?: string;
    page_size?: number;
    devices?: {
        device_id?: string;
        device_name?: string;
        mac_address?: string;
        serial_number?: string;
        vendor?: string;
        model?: string;
        platform_os?: string;
        app_version?: string;
        tag?: string;
        enrolled_in_zdm?: boolean;
        connected_to_zdm?: boolean;
        room_id?: string;
        room_name?: string;
        device_type?: number;
        skd_version?: string;
        device_status?: number;
        last_online?: string;
        user_email?: string;
    }[];
};
type DevicesAddNewDeviceRequestBody = {
    device_name: string;
    mac_address: string;
    serial_number: string;
    vendor: string;
    model: string;
    room_id?: string;
    user_email?: string;
    device_type: number;
    tag?: string;
    zdm_group_id?: string;
    extension_number?: string;
};
type DevicesGetZDMGroupInfoQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type DevicesGetZDMGroupInfoResponse = {
    groups?: {
        zdm_group_id?: string;
        name?: string;
        description?: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type DevicesAssignDeviceToUserOrCommonareaRequestBody = {
    extension_number?: string;
    mac_address: string;
    vendor: string;
};
type DevicesUpgradeZpaOsAppRequestBody = {
    zdm_group_id: string;
    data: {
        firmware_versions?: {
            vendor?: string;
            version?: string;
            model?: string;
        }[];
        upgrade_type: string;
    } | {
        app_version?: string;
        upgrade_type: string;
    };
};
type DevicesDeleteZPADeviceByVendorAndMacAddressPathParams = {
    vendor: string;
    macAddress: string;
};
type DevicesGetZPAVersionInfoPathParams = {
    zdmGroupId: string;
};
type DevicesGetZPAVersionInfoResponse = {
    firmware_versions?: {
        vendor?: string;
        model?: string;
        version?: string;
        warn_info?: string;
    }[];
    app_versions?: string[];
};
type DevicesGetDeviceDetailPathParams = {
    deviceId: string;
};
type DevicesGetDeviceDetailResponse = {
    device_id?: string;
    device_name?: string;
    mac_address?: string;
    serial_number?: string;
    vendor?: string;
    model?: string;
    platform_os?: string;
    app_version?: string;
    tag?: string;
    enrolled_in_zdm?: boolean;
    connected_to_zdm?: boolean;
    room_id?: string;
    room_name?: string;
    device_type?: number;
    sdk_version?: string;
    device_status?: number;
    last_online?: string;
    user_email?: string;
};
type DevicesDeleteDevicePathParams = {
    deviceId: string;
};
type DevicesChangeDevicePathParams = {
    deviceId: string;
};
type DevicesChangeDeviceRequestBody = {
    device_name: string;
    tag?: string;
    room_id?: string;
    device_type?: number;
};
type DevicesChangeDeviceAssociationPathParams = {
    deviceId: string;
};
type DevicesChangeDeviceAssociationRequestBody = {
    room_id?: string;
    app_type?: string;
};
type H323DevicesListHSIPDevicesQueryParams = {
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type H323DevicesListHSIPDevicesResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    devices?: ({
        id?: string;
    } & {
        encryption: string;
        ip: string;
        name: string;
        protocol: string;
    })[];
};
type H323DevicesCreateHSIPDeviceRequestBody = {
    encryption: string;
    ip: string;
    name: string;
    protocol: string;
};
type H323DevicesCreateHSIPDeviceResponse = {
    id?: string;
} & {
    encryption: string;
    ip: string;
    name: string;
    protocol: string;
};
type H323DevicesDeleteHSIPDevicePathParams = {
    deviceId: string;
};
type H323DevicesUpdateHSIPDevicePathParams = {
    deviceId: string;
};
type H323DevicesUpdateHSIPDeviceRequestBody = {
    encryption: string;
    ip: string;
    name: string;
    protocol: string;
};
type MeetingsDeleteLiveMeetingMessagePathParams = {
    meetingId: number;
    messageId: string;
};
type MeetingsDeleteLiveMeetingMessageQueryParams = {
    file_ids?: string;
};
type MeetingsUpdateLiveMeetingMessagePathParams = {
    meetingId: number;
    messageId: string;
};
type MeetingsUpdateLiveMeetingMessageRequestBody = {
    message_content: string;
};
type MeetingsUseInMeetingControlsPathParams = {
    meetingId: string;
};
type MeetingsUseInMeetingControlsRequestBody = {
    method?: string;
    params?: {
        contacts?: {
            email?: string;
            id?: string;
        }[];
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
    };
};
type MeetingsListMeetingSummariesOfAccountQueryParams = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
};
type MeetingsListMeetingSummariesOfAccountResponse = {
    page_size?: number;
    next_page_token?: string;
    from?: string;
    to?: string;
    summaries?: {
        meeting_host_id?: string;
        meeting_host_email?: string;
        meeting_uuid?: string;
        meeting_id?: number;
        meeting_topic?: string;
        meeting_start_time?: string;
        meeting_end_time?: string;
        summary_start_time?: string;
        summary_end_time?: string;
        summary_created_time?: string;
        summary_last_modified_time?: string;
    }[];
};
type MeetingsGetMeetingPathParams = {
    meetingId: number;
};
type MeetingsGetMeetingQueryParams = {
    occurrence_id?: string;
    show_previous_occurrences?: boolean;
};
type MeetingsGetMeetingResponse = {
    assistant_id?: string;
    host_email?: string;
    host_id?: string;
    id?: number;
    uuid?: string;
    agenda?: string;
    created_at?: string;
    duration?: number;
    encrypted_password?: string;
    pstn_password?: string;
    h323_password?: string;
    join_url?: string;
    chat_join_url?: string;
    occurrences?: {
        duration?: number;
        occurrence_id?: string;
        start_time?: string;
        status?: string;
    }[];
    password?: string;
    pmi?: string;
    pre_schedule?: boolean;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    settings?: {
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_hosts_email_notification?: boolean;
        alternative_host_update_polls?: boolean;
        approval_type?: number;
        approved_or_denied_countries_or_regions?: {
            approved_list?: string[];
            denied_list?: string[];
            enable?: boolean;
            method?: string;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_exception?: {
            email?: string;
            name?: string;
            join_url?: string;
        }[];
        authentication_name?: string;
        authentication_option?: string;
        auto_recording?: string;
        breakout_room?: {
            enable?: boolean;
            rooms?: {
                name?: string;
                participants?: string[];
            }[];
        };
        calendar_type?: number;
        close_registration?: boolean;
        cn_meeting?: boolean;
        contact_email?: string;
        contact_name?: string;
        custom_keys?: {
            key?: string;
            value?: string;
        }[];
        email_notification?: boolean;
        encryption_type?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        focus_mode?: boolean;
        global_dial_in_countries?: string[];
        global_dial_in_numbers?: {
            city?: string;
            country?: string;
            country_name?: string;
            number?: string;
            type?: string;
        }[];
        host_video?: boolean;
        in_meeting?: boolean;
        jbh_time?: number;
        join_before_host?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        meeting_authentication?: boolean;
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        private_meeting?: boolean;
        registrants_confirmation_email?: boolean;
        registrants_email_notification?: boolean;
        registration_type?: number;
        show_share_button?: boolean;
        use_pmi?: boolean;
        waiting_room?: boolean;
        watermark?: boolean;
        host_save_video_order?: boolean;
        internal_meeting?: boolean;
        meeting_invitees?: {
            email?: string;
            internal_user?: boolean;
        }[];
        continuous_meeting_chat?: {
            enable?: boolean;
            auto_add_invited_external_users?: boolean;
            auto_add_meeting_participants?: boolean;
            channel_id?: string;
        };
        participant_focused_meeting?: boolean;
        push_change_to_calendar?: boolean;
        resources?: {
            resource_type?: string;
            resource_id?: string;
            permission_level?: string;
        }[];
        auto_start_meeting_summary?: boolean;
        auto_start_ai_companion_questions?: boolean;
        device_testing?: boolean;
    };
    start_time?: string;
    start_url?: string;
    status?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field?: string;
        value?: string;
        visible?: boolean;
    }[];
    type?: number;
    dynamic_host_key?: string;
};
type MeetingsDeleteMeetingPathParams = {
    meetingId: number;
};
type MeetingsDeleteMeetingQueryParams = {
    occurrence_id?: string;
    schedule_for_reminder?: boolean;
    cancel_meeting_reminder?: boolean;
};
type MeetingsUpdateMeetingPathParams = {
    meetingId: number;
};
type MeetingsUpdateMeetingQueryParams = {
    occurrence_id?: string;
};
type MeetingsUpdateMeetingRequestBody = {
    agenda?: string;
    duration?: number;
    password?: string;
    pre_schedule?: boolean;
    schedule_for?: string;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    settings?: {
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_hosts_email_notification?: boolean;
        alternative_host_update_polls?: boolean;
        approval_type?: number;
        approved_or_denied_countries_or_regions?: {
            approved_list?: string[];
            denied_list?: string[];
            enable?: boolean;
            method?: string;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_exception?: {
            email?: string;
            name?: string;
            join_url?: string;
        }[];
        authentication_name?: string;
        authentication_option?: string;
        auto_recording?: string;
        breakout_room?: {
            enable?: boolean;
            rooms?: {
                name?: string;
                participants?: string[];
            }[];
        };
        calendar_type?: number;
        close_registration?: boolean;
        cn_meeting?: boolean;
        contact_email?: string;
        contact_name?: string;
        custom_keys?: {
            key?: string;
            value?: string;
        }[];
        email_notification?: boolean;
        encryption_type?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        focus_mode?: boolean;
        global_dial_in_countries?: string[];
        global_dial_in_numbers?: {
            city?: string;
            country?: string;
            country_name?: string;
            number?: string;
            type?: string;
        }[];
        host_video?: boolean;
        in_meeting?: boolean;
        jbh_time?: number;
        join_before_host?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        meeting_authentication?: boolean;
        meeting_invitees?: {
            email?: string;
        }[];
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        private_meeting?: boolean;
        registrants_confirmation_email?: boolean;
        registrants_email_notification?: boolean;
        registration_type?: number;
        show_share_button?: boolean;
        use_pmi?: boolean;
        waiting_room?: boolean;
        watermark?: boolean;
        host_save_video_order?: boolean;
        internal_meeting?: boolean;
        continuous_meeting_chat?: {
            enable?: boolean;
            auto_add_invited_external_users?: boolean;
            auto_add_meeting_participants?: boolean;
        };
        participant_focused_meeting?: boolean;
        resources?: {
            resource_type?: string;
            resource_id?: string;
            permission_level?: string;
        }[];
        auto_start_meeting_summary?: boolean;
        auto_start_ai_companion_questions?: boolean;
        device_testing?: boolean;
    };
    start_time?: string;
    template_id?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field?: string;
        value?: string;
    }[];
    type?: number;
};
type MeetingsPerformBatchPollCreationPathParams = {
    meetingId: string;
};
type MeetingsPerformBatchPollCreationRequestBody = {
    polls?: {
        anonymous?: boolean;
        poll_type?: number;
        questions?: {
            answer_max_character?: number;
            answer_min_character?: number;
            answer_required?: boolean;
            answers?: string[];
            case_sensitive?: boolean;
            name?: string;
            prompts?: {
                prompt_question?: string;
                prompt_right_answers?: string[];
            }[];
            rating_max_label?: string;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_min_value?: number;
            right_answers?: string[];
            show_as_dropdown?: boolean;
            type?: string;
        }[];
        title?: string;
    }[];
};
type MeetingsPerformBatchPollCreationResponse = {
    polls?: {
        anonymous?: boolean;
        id?: string;
        poll_type?: number;
        questions?: {
            answer_max_character?: number;
            answer_min_character?: number;
            answer_required?: boolean;
            answers?: string[];
            case_sensitive?: boolean;
            name?: string;
            prompts?: {
                prompt_question?: string;
                prompt_right_answers?: string[];
            }[];
            rating_max_label?: string;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_min_value?: number;
            right_answers?: string[];
            show_as_dropdown?: boolean;
            type?: string;
        }[];
        status?: string;
        title?: string;
    }[];
};
type MeetingsPerformBatchRegistrationPathParams = {
    meetingId: string;
};
type MeetingsPerformBatchRegistrationRequestBody = {
    auto_approve?: boolean;
    registrants_confirmation_email?: boolean;
    registrants?: {
        email: string;
        first_name: string;
        last_name?: string;
    }[];
};
type MeetingsPerformBatchRegistrationResponse = {
    registrants?: {
        email?: string;
        join_url?: string;
        registrant_id?: string;
        participant_pin_code?: number;
    }[];
};
type MeetingsGetMeetingInvitationPathParams = {
    meetingId: number;
};
type MeetingsGetMeetingInvitationResponse = {
    invitation?: string;
    sip_links?: string[];
};
type MeetingsCreateMeetingsInviteLinksPathParams = {
    meetingId: number;
};
type MeetingsCreateMeetingsInviteLinksRequestBody = {
    attendees?: {
        name: string;
    }[];
    ttl?: number;
};
type MeetingsCreateMeetingsInviteLinksResponse = {
    attendees?: {
        join_url?: string;
        name?: string;
    }[];
};
type MeetingsGetMeetingsJoinTokenForLiveStreamingPathParams = {
    meetingId: number;
};
type MeetingsGetMeetingsJoinTokenForLiveStreamingResponse = {
    expire_in?: number;
    token?: string;
};
type MeetingsGetMeetingsArchiveTokenForLocalArchivingPathParams = {
    meetingId: number;
};
type MeetingsGetMeetingsArchiveTokenForLocalArchivingResponse = {
    expire_in?: number;
    token?: string;
};
type MeetingsGetMeetingsJoinTokenForLocalRecordingPathParams = {
    meetingId: number;
};
type MeetingsGetMeetingsJoinTokenForLocalRecordingQueryParams = {
    bypass_waiting_room?: boolean;
};
type MeetingsGetMeetingsJoinTokenForLocalRecordingResponse = {
    expire_in?: number;
    token?: string;
};
type MeetingsGetLivestreamDetailsPathParams = {
    meetingId: string;
};
type MeetingsGetLivestreamDetailsResponse = {
    page_url?: string;
    stream_key?: string;
    stream_url?: string;
    resolution?: string;
};
type MeetingsUpdateLivestreamPathParams = {
    meetingId: number;
};
type MeetingsUpdateLivestreamRequestBody = {
    page_url: string;
    stream_key: string;
    stream_url: string;
    resolution?: string;
};
type MeetingsUpdateLivestreamStatusPathParams = {
    meetingId: number;
};
type MeetingsUpdateLivestreamStatusRequestBody = {
    action?: string;
    settings?: {
        active_speaker_name?: boolean;
        display_name?: string;
        layout?: string;
        close_caption?: string;
    };
};
type MeetingsGetMeetingSummaryPathParams = {
    meetingId: string;
};
type MeetingsGetMeetingSummaryResponse = {
    meeting_host_id?: string;
    meeting_host_email?: string;
    meeting_uuid?: string;
    meeting_id?: number;
    meeting_topic?: string;
    meeting_start_time?: string;
    meeting_end_time?: string;
    summary_start_time?: string;
    summary_end_time?: string;
    summary_created_time?: string;
    summary_last_modified_time?: string;
    summary_title?: string;
    summary_overview?: string;
    summary_details?: {
        label?: string;
        summary?: string;
    }[];
    next_steps?: string[];
    edited_summary?: {
        summary_details?: string;
        next_steps?: string[];
    };
};
type MeetingsAddMeetingAppPathParams = {
    meetingId: number;
};
type MeetingsAddMeetingAppResponse = {
    id?: number;
    start_time?: string;
    app_id?: string;
};
type MeetingsDeleteMeetingAppPathParams = {
    meetingId: number;
};
type MeetingsListMeetingPollsPathParams = {
    meetingId: number;
};
type MeetingsListMeetingPollsQueryParams = {
    anonymous?: boolean;
};
type MeetingsListMeetingPollsResponse = {
    polls?: ({
        id?: string;
        status?: string;
    } & {
        anonymous?: boolean;
        poll_type?: number;
        questions?: {
            answer_max_character?: number;
            answer_min_character?: number;
            answer_required?: boolean;
            answers?: string[];
            case_sensitive?: boolean;
            name?: string;
            prompts?: {
                prompt_question?: string;
                prompt_right_answers?: string[];
            }[];
            rating_max_label?: string;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_min_value?: number;
            right_answers?: string[];
            show_as_dropdown?: boolean;
            type?: string;
        }[];
        title?: string;
    })[];
    total_records?: number;
};
type MeetingsCreateMeetingPollPathParams = {
    meetingId: number;
};
type MeetingsCreateMeetingPollRequestBody = {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type MeetingsCreateMeetingPollResponse = {
    id?: string;
    status?: string;
} & {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type MeetingsGetMeetingPollPathParams = {
    meetingId: number;
    pollId: string;
};
type MeetingsGetMeetingPollResponse = {
    id?: string;
    status?: string;
} & {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type MeetingsUpdateMeetingPollPathParams = {
    meetingId: number;
    pollId: string;
};
type MeetingsUpdateMeetingPollRequestBody = {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type MeetingsDeleteMeetingPollPathParams = {
    meetingId: number;
    pollId: string;
};
type MeetingsListMeetingRegistrantsPathParams = {
    meetingId: number;
};
type MeetingsListMeetingRegistrantsQueryParams = {
    occurrence_id?: string;
    status?: string;
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type MeetingsListMeetingRegistrantsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    registrants?: ({
        id?: string;
    } & {
        address?: string;
        city?: string;
        comments?: string;
        country?: string;
        custom_questions?: {
            title?: string;
            value?: string;
        }[];
        email: string;
        first_name: string;
        industry?: string;
        job_title?: string;
        last_name?: string;
        no_of_employees?: string;
        org?: string;
        phone?: string;
        purchasing_time_frame?: string;
        role_in_purchase_process?: string;
        state?: string;
        status?: string;
        zip?: string;
    } & {
        create_time?: string;
        join_url?: string;
        status?: string;
        participant_pin_code?: number;
    })[];
};
type MeetingsAddMeetingRegistrantPathParams = {
    meetingId: number;
};
type MeetingsAddMeetingRegistrantQueryParams = {
    occurrence_ids?: string;
};
type MeetingsAddMeetingRegistrantRequestBody = {
    first_name: string;
    last_name?: string;
    email: string;
    address?: string;
    city?: string;
    state?: string;
    zip?: string;
    country?: string;
    phone?: string;
    comments?: string;
    custom_questions?: {
        title?: string;
        value?: string;
    }[];
    industry?: string;
    job_title?: string;
    no_of_employees?: string;
    org?: string;
    purchasing_time_frame?: string;
    role_in_purchase_process?: string;
} & {
    language?: string;
} & {
    auto_approve?: boolean;
};
type MeetingsAddMeetingRegistrantResponse = {
    id?: number;
    join_url?: string;
    registrant_id?: string;
    start_time?: string;
    topic?: string;
    occurrences?: {
        duration?: number;
        occurrence_id?: string;
        start_time?: string;
        status?: string;
    }[];
    participant_pin_code?: number;
};
type MeetingsListRegistrationQuestionsPathParams = {
    meetingId: number;
};
type MeetingsListRegistrationQuestionsResponse = {
    custom_questions?: {
        answers?: string[];
        required?: boolean;
        title?: string;
        type?: string;
    }[];
    questions?: {
        field_name?: string;
        required?: boolean;
    }[];
};
type MeetingsUpdateRegistrationQuestionsPathParams = {
    meetingId: number;
};
type MeetingsUpdateRegistrationQuestionsRequestBody = {
    custom_questions?: {
        answers?: string[];
        required?: boolean;
        title?: string;
        type?: string;
    }[];
    questions?: {
        field_name?: string;
        required?: boolean;
    }[];
};
type MeetingsUpdateRegistrantsStatusPathParams = {
    meetingId: number;
};
type MeetingsUpdateRegistrantsStatusQueryParams = {
    occurrence_id?: string;
};
type MeetingsUpdateRegistrantsStatusRequestBody = {
    action: string;
    registrants?: {
        email?: string;
        id?: string;
    }[];
};
type MeetingsGetMeetingRegistrantPathParams = {
    meetingId: number;
    registrantId: string;
};
type MeetingsGetMeetingRegistrantResponse = {
    id?: string;
} & {
    address?: string;
    city?: string;
    comments?: string;
    country?: string;
    custom_questions?: {
        title?: string;
        value?: string;
    }[];
    email: string;
    first_name: string;
    industry?: string;
    job_title?: string;
    last_name?: string;
    no_of_employees?: string;
    org?: string;
    phone?: string;
    purchasing_time_frame?: string;
    role_in_purchase_process?: string;
    state?: string;
    status?: string;
    zip?: string;
} & {
    create_time?: string;
    join_url?: string;
    status?: string;
    participant_pin_code?: number;
};
type MeetingsDeleteMeetingRegistrantPathParams = {
    meetingId: number;
    registrantId: string;
};
type MeetingsDeleteMeetingRegistrantQueryParams = {
    occurrence_id?: string;
};
type MeetingsGetMeetingSIPURIWithPasscodePathParams = {
    meetingId: number;
};
type MeetingsGetMeetingSIPURIWithPasscodeRequestBody = {
    passcode?: string;
};
type MeetingsGetMeetingSIPURIWithPasscodeResponse = {
    sip_dialing?: string;
    paid_crc_plan_participant?: boolean;
    participant_identifier_code?: string;
    expire_in?: number;
};
type MeetingsUpdateMeetingStatusPathParams = {
    meetingId: number;
};
type MeetingsUpdateMeetingStatusRequestBody = {
    action?: string;
};
type MeetingsGetMeetingSurveyPathParams = {
    meetingId: number;
};
type MeetingsGetMeetingSurveyResponse = {
    custom_survey?: {
        title?: string;
        anonymous?: boolean;
        numbered_questions?: boolean;
        show_question_type?: boolean;
        feedback?: string;
        questions?: {
            name?: string;
            type?: string;
            answer_required?: boolean;
            show_as_dropdown?: boolean;
            answers?: string[];
            prompts?: {
                prompt_question?: string;
            }[];
            answer_min_character?: number;
            answer_max_character?: number;
            rating_min_value?: number;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_max_label?: string;
        }[];
    };
    show_in_the_browser?: boolean;
    third_party_survey?: string;
};
type MeetingsDeleteMeetingSurveyPathParams = {
    meetingId: number;
};
type MeetingsUpdateMeetingSurveyPathParams = {
    meetingId: number;
};
type MeetingsUpdateMeetingSurveyRequestBody = {
    custom_survey?: {
        title?: string;
        anonymous?: boolean;
        numbered_questions?: boolean;
        show_question_type?: boolean;
        feedback?: string;
        questions?: {
            name?: string;
            type?: string;
            answer_required?: boolean;
            show_as_dropdown?: boolean;
            answers?: string[];
            prompts?: {
                prompt_question?: string;
            }[];
            answer_min_character?: number;
            answer_max_character?: number;
            rating_min_value?: number;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_max_label?: string;
        }[];
    };
    show_in_the_browser?: boolean;
    third_party_survey?: string;
};
type MeetingsGetMeetingsTokenPathParams = {
    meetingId: number;
};
type MeetingsGetMeetingsTokenQueryParams = {
    type?: string;
};
type MeetingsGetMeetingsTokenResponse = {
    token?: string;
};
type MeetingsGetPastMeetingDetailsPathParams = {
    meetingId: number | string;
};
type MeetingsGetPastMeetingDetailsResponse = {
    id?: number;
    uuid?: string;
    duration?: number;
    start_time?: string;
    end_time?: string;
    host_id?: string;
    dept?: string;
    participants_count?: number;
    source?: string;
    topic?: string;
    total_minutes?: number;
    type?: number;
    user_email?: string;
    user_name?: string;
};
type MeetingsListPastMeetingInstancesPathParams = {
    meetingId: number;
};
type MeetingsListPastMeetingInstancesResponse = {
    meetings?: {
        start_time?: string;
        uuid?: string;
    }[];
};
type MeetingsGetPastMeetingParticipantsPathParams = {
    meetingId: string;
};
type MeetingsGetPastMeetingParticipantsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type MeetingsGetPastMeetingParticipantsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        id?: string;
        name?: string;
        user_id?: string;
        registrant_id?: string;
        user_email?: string;
        join_time?: string;
        leave_time?: string;
        duration?: number;
        failover?: boolean;
        status?: string;
        internal_user?: boolean;
    }[];
};
type MeetingsListPastMeetingsPollResultsPathParams = {
    meetingId: string;
};
type MeetingsListPastMeetingsPollResultsResponse = {
    id?: number;
    questions?: {
        email?: string;
        name?: string;
        question_details?: {
            answer?: string;
            date_time?: string;
            polling_id?: string;
            question?: string;
        }[];
    }[];
    start_time?: string;
    uuid?: string;
};
type MeetingsListPastMeetingsQAPathParams = {
    meetingId: string;
};
type MeetingsListPastMeetingsQAResponse = {
    id?: number;
    questions?: {
        email?: string;
        name?: string;
        question_details?: {
            answer?: string;
            question?: string;
        }[];
    }[];
    start_time?: string;
    uuid?: string;
};
type MeetingsListMeetingTemplatesPathParams = {
    userId: string;
};
type MeetingsListMeetingTemplatesResponse = {
    templates?: {
        id?: string;
        name?: string;
        type?: number;
    }[];
    total_records?: number;
};
type MeetingsCreateMeetingTemplateFromExistingMeetingPathParams = {
    userId: string;
};
type MeetingsCreateMeetingTemplateFromExistingMeetingRequestBody = {
    meeting_id?: number;
    name?: string;
    save_recurrence?: boolean;
    overwrite?: boolean;
};
type MeetingsCreateMeetingTemplateFromExistingMeetingResponse = {
    id?: string;
    name?: string;
};
type MeetingsListMeetingsPathParams = {
    userId: string;
};
type MeetingsListMeetingsQueryParams = {
    type?: string;
    page_size?: number;
    next_page_token?: string;
    page_number?: number;
    from?: string;
    to?: string;
    timezone?: string;
};
type MeetingsListMeetingsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    meetings?: {
        agenda?: string;
        created_at?: string;
        duration?: number;
        host_id?: string;
        id?: number;
        join_url?: string;
        pmi?: string;
        start_time?: string;
        timezone?: string;
        topic?: string;
        type?: number;
        uuid?: string;
    }[];
};
type MeetingsCreateMeetingPathParams = {
    userId: string;
};
type MeetingsCreateMeetingRequestBody = {
    agenda?: string;
    default_password?: boolean;
    duration?: number;
    password?: string;
    pre_schedule?: boolean;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    schedule_for?: string;
    settings?: {
        additional_data_center_regions?: string[];
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_hosts_email_notification?: boolean;
        approval_type?: number;
        approved_or_denied_countries_or_regions?: {
            approved_list?: string[];
            denied_list?: string[];
            enable?: boolean;
            method?: string;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_exception?: {
            email?: string;
            name?: string;
        }[];
        authentication_option?: string;
        auto_recording?: string;
        breakout_room?: {
            enable?: boolean;
            rooms?: {
                name?: string;
                participants?: string[];
            }[];
        };
        calendar_type?: number;
        close_registration?: boolean;
        cn_meeting?: boolean;
        contact_email?: string;
        contact_name?: string;
        email_notification?: boolean;
        encryption_type?: string;
        focus_mode?: boolean;
        global_dial_in_countries?: string[];
        host_video?: boolean;
        in_meeting?: boolean;
        jbh_time?: number;
        join_before_host?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        meeting_authentication?: boolean;
        meeting_invitees?: {
            email?: string;
        }[];
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        private_meeting?: boolean;
        registrants_confirmation_email?: boolean;
        registrants_email_notification?: boolean;
        registration_type?: number;
        show_share_button?: boolean;
        use_pmi?: boolean;
        waiting_room?: boolean;
        watermark?: boolean;
        host_save_video_order?: boolean;
        alternative_host_update_polls?: boolean;
        internal_meeting?: boolean;
        continuous_meeting_chat?: {
            enable?: boolean;
            auto_add_invited_external_users?: boolean;
            auto_add_meeting_participants?: boolean;
        };
        participant_focused_meeting?: boolean;
        push_change_to_calendar?: boolean;
        resources?: {
            resource_type?: string;
            resource_id?: string;
            permission_level?: string;
        }[];
        auto_start_meeting_summary?: boolean;
        auto_start_ai_companion_questions?: boolean;
        device_testing?: boolean;
    };
    start_time?: string;
    template_id?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field: string;
        value?: string;
    }[];
    type?: number;
};
type MeetingsCreateMeetingResponse = {
    assistant_id?: string;
    host_email?: string;
    id?: number;
    registration_url?: string;
    agenda?: string;
    created_at?: string;
    duration?: number;
    encrypted_password?: string;
    pstn_password?: string;
    h323_password?: string;
    join_url?: string;
    chat_join_url?: string;
    occurrences?: {
        duration?: number;
        occurrence_id?: string;
        start_time?: string;
        status?: string;
    }[];
    password?: string;
    pmi?: string;
    pre_schedule?: boolean;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    settings?: {
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_hosts_email_notification?: boolean;
        alternative_host_update_polls?: boolean;
        approval_type?: number;
        approved_or_denied_countries_or_regions?: {
            approved_list?: string[];
            denied_list?: string[];
            enable?: boolean;
            method?: string;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_exception?: {
            email?: string;
            name?: string;
            join_url?: string;
        }[];
        authentication_name?: string;
        authentication_option?: string;
        auto_recording?: string;
        breakout_room?: {
            enable?: boolean;
            rooms?: {
                name?: string;
                participants?: string[];
            }[];
        };
        calendar_type?: number;
        close_registration?: boolean;
        cn_meeting?: boolean;
        contact_email?: string;
        contact_name?: string;
        custom_keys?: {
            key?: string;
            value?: string;
        }[];
        email_notification?: boolean;
        encryption_type?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        focus_mode?: boolean;
        global_dial_in_countries?: string[];
        global_dial_in_numbers?: {
            city?: string;
            country?: string;
            country_name?: string;
            number?: string;
            type?: string;
        }[];
        host_video?: boolean;
        in_meeting?: boolean;
        jbh_time?: number;
        join_before_host?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        meeting_authentication?: boolean;
        mute_upon_entry?: boolean;
        participant_video?: boolean;
        private_meeting?: boolean;
        registrants_confirmation_email?: boolean;
        registrants_email_notification?: boolean;
        registration_type?: number;
        show_share_button?: boolean;
        use_pmi?: boolean;
        waiting_room?: boolean;
        watermark?: boolean;
        host_save_video_order?: boolean;
        internal_meeting?: boolean;
        meeting_invitees?: {
            email?: string;
        }[];
        continuous_meeting_chat?: {
            enable?: boolean;
            auto_add_invited_external_users?: boolean;
            auto_add_meeting_participants?: boolean;
            channel_id?: string;
        };
        participant_focused_meeting?: boolean;
        push_change_to_calendar?: boolean;
        resources?: {
            resource_type?: string;
            resource_id?: string;
            permission_level?: string;
        }[];
        auto_start_meeting_summary?: boolean;
        auto_start_ai_companion_questions?: boolean;
        device_testing?: boolean;
    };
    start_time?: string;
    start_url?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field?: string;
        value?: string;
        visible?: boolean;
    }[];
    type?: number;
    dynamic_host_key?: string;
    creation_source?: string;
};
type MeetingsListUpcomingMeetingsPathParams = {
    userId: string;
};
type MeetingsListUpcomingMeetingsResponse = {
    total_records?: number;
    meetings?: {
        id?: number;
        topic?: string;
        type?: number;
        start_time?: string;
        duration?: number;
        timezone?: string;
        created_at?: string;
        join_url?: string;
    }[];
};
type PACListUsersPACAccountsPathParams = {
    userId: string;
};
type PACListUsersPACAccountsResponse = {
    pac_accounts?: {
        conference_id?: number;
        dedicated_dial_in_number?: {
            country?: string;
            number?: string;
        }[];
        global_dial_in_numbers?: {
            country?: string;
            number?: string;
        }[];
        listen_only_password?: string;
        participant_password?: string;
    }[];
};
type ReportsGetSignInSignOutActivityReportQueryParams = {
    from?: string;
    to?: string;
    page_size?: number;
    next_page_token?: string;
};
type ReportsGetSignInSignOutActivityReportResponse = {
    activity_logs?: {
        client_type?: string;
        email?: string;
        ip_address?: string;
        time?: string;
        type?: string;
        version?: string;
    }[];
    from?: string;
    next_page_token?: string;
    page_size?: number;
    to?: string;
};
type ReportsGetBillingReportsResponse = {
    billing_reports?: {
        end_date?: string;
        id?: string;
        start_date?: string;
        tax_amount?: string;
        total_amount?: string;
        type?: number;
    }[];
    currency?: string;
};
type ReportsGetBillingInvoiceReportsQueryParams = {
    billing_id: string;
};
type ReportsGetBillingInvoiceReportsResponse = {
    currency?: string;
    invoices?: {
        end_date?: string;
        invoice_charge_name?: string;
        invoice_number?: string;
        quantity?: number;
        start_date?: string;
        tax_amount?: string;
        total_amount?: string;
    }[];
};
type ReportsGetCloudRecordingUsageReportQueryParams = {
    from: string;
    to: string;
    group_id?: string;
};
type ReportsGetCloudRecordingUsageReportResponse = {
    from?: string;
    to?: string;
} & {
    cloud_recording_storage?: {
        date?: string;
        free_usage?: string;
        plan_usage?: string;
        usage?: string;
    }[];
};
type ReportsGetDailyUsageReportQueryParams = {
    year?: number;
    month?: number;
    group_id?: string;
};
type ReportsGetDailyUsageReportResponse = {
    dates?: {
        date?: string;
        meeting_minutes?: number;
        meetings?: number;
        new_users?: number;
        participants?: number;
    }[];
    month?: number;
    year?: number;
};
type ReportsGetMeetingActivitiesReportQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    meeting_number?: string;
    search_key?: string;
    activity_type: string;
};
type ReportsGetMeetingActivitiesReportResponse = {
    meeting_activity_logs?: {
        meeting_number: string;
        activity_time: string;
        operator: string;
        operator_email: string;
        activity_category: string;
        activity_detail: string;
    }[];
    next_page_token?: string;
    page_size?: number;
};
type ReportsGetMeetingDetailReportsPathParams = {
    meetingId: number | string;
};
type ReportsGetMeetingDetailReportsResponse = {
    custom_keys?: {
        key?: string;
        value?: string;
    }[];
    dept?: string;
    duration?: number;
    end_time?: string;
    id?: number;
    participants_count?: number;
    start_time?: string;
    topic?: string;
    total_minutes?: number;
    tracking_fields?: {
        field?: string;
        value?: string;
    }[];
    type?: number;
    user_email?: string;
    user_name?: string;
    uuid?: string;
};
type ReportsGetMeetingParticipantReportsPathParams = {
    meetingId: string;
};
type ReportsGetMeetingParticipantReportsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    include_fields?: string;
};
type ReportsGetMeetingParticipantReportsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        customer_key?: string;
        duration?: number;
        failover?: boolean;
        id?: string;
        join_time?: string;
        leave_time?: string;
        name?: string;
        registrant_id?: string;
        status?: string;
        user_email?: string;
        user_id?: string;
        bo_mtg_id?: string;
        participant_user_id?: string;
    }[];
};
type ReportsGetMeetingPollReportsPathParams = {
    meetingId: number | string;
};
type ReportsGetMeetingPollReportsResponse = {
    id?: number;
    uuid?: string;
    start_time?: string;
    questions?: {
        email?: string;
        name?: string;
        first_name?: string;
        last_name?: string;
        question_details?: {
            answer?: string;
            date_time?: string;
            polling_id?: string;
            question?: string;
        }[];
    }[];
};
type ReportsGetMeetingQAReportPathParams = {
    meetingId: string;
};
type ReportsGetMeetingQAReportResponse = {
    id?: number;
    questions?: {
        user_id?: string;
        email?: string;
        name?: string;
        question_details?: {
            answer?: string;
            question?: string;
            question_id?: string;
            create_time?: string;
            question_status?: string;
            answer_details?: {
                user_id?: string;
                name?: string;
                email?: string;
                content?: string;
                create_time?: string;
                type?: string;
            }[];
        }[];
    }[];
    start_time?: string;
    uuid?: string;
};
type ReportsGetMeetingSurveyReportPathParams = {
    meetingId: string;
};
type ReportsGetMeetingSurveyReportResponse = {
    meeting_id?: number;
    meeting_uuid?: string;
    start_time?: string;
    survey_id?: string;
    survey_name?: string;
    survey_answers?: {
        email?: string;
        name?: string;
        first_name?: string;
        last_name?: string;
        answer_details?: {
            question?: string;
            question_id?: string;
            answer?: string;
            date_time?: string;
        }[];
    }[];
};
type ReportsGetOperationLogsReportQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    category_type?: string;
};
type ReportsGetOperationLogsReportResponse = {
    next_page_token?: string;
    page_size?: number;
} & {
    operation_logs?: {
        action?: string;
        category_type?: string;
        operation_detail?: string;
        operator?: string;
        time?: string;
    }[];
};
type ReportsGetTelephoneReportsQueryParams = {
    type?: string;
    query_date_type?: string;
    from: string;
    to: string;
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type ReportsGetTelephoneReportsResponse = {
    from?: string;
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    to?: string;
    total_records?: number;
} & {
    telephony_usage?: {
        call_in_number?: string;
        country_name?: string;
        dept?: string;
        duration?: number;
        end_time?: string;
        host_email?: string;
        host_id?: string;
        host_name?: string;
        meeting_id?: number;
        meeting_type?: string;
        phone_number?: string;
        rate?: number;
        signaled_number?: string;
        start_time?: string;
        total?: number;
        type?: string;
        uuid?: string;
    }[];
};
type ReportsGetUpcomingEventsReportQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    type?: string;
    group_id?: string;
};
type ReportsGetUpcomingEventsReportResponse = {
    from?: string;
    next_page_token?: string;
    page_size?: number;
    to?: string;
    upcoming_events?: {
        dept?: string;
        host_id?: string;
        host_name?: string;
        id?: string;
        start_time?: string;
        topic?: string;
    }[];
};
type ReportsGetActiveOrInactiveHostReportsQueryParams = {
    type?: string;
    from: string;
    to: string;
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
    group_id?: string;
};
type ReportsGetActiveOrInactiveHostReportsResponse = {
    from?: string;
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    to?: string;
    total_records?: number;
} & {
    total_meeting_minutes?: number;
    total_meetings?: number;
    total_participants?: number;
    users?: {
        custom_attributes?: {
            key?: string;
            name?: string;
            value?: string;
        }[];
        dept?: string;
        email?: string;
        id?: string;
        meeting_minutes?: number;
        meetings?: number;
        participants?: number;
        type?: number;
        user_name?: string;
    }[];
};
type ReportsGetMeetingReportsPathParams = {
    userId: string | string | string;
};
type ReportsGetMeetingReportsQueryParams = {
    from: string;
    to: string;
    page_size?: number;
    next_page_token?: string;
    type?: string;
};
type ReportsGetMeetingReportsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    from?: string;
    meetings?: {
        custom_keys?: {
            key?: string;
            value?: string;
        }[];
        duration?: number;
        end_time?: string;
        id?: number;
        participants_count?: number;
        session_key?: string;
        source?: string;
        start_time?: string;
        topic?: string;
        total_minutes?: number;
        type?: number;
        user_email?: string;
        user_name?: string;
        uuid?: string;
        schedule_time?: string;
        join_waiting_room_time?: string;
        join_time?: string;
        leave_time?: string;
        host_organization?: string;
        host_name?: string;
        has_screen_share?: boolean;
        has_recording?: boolean;
        has_chat?: boolean;
        meeting_encryption_status?: number;
        participants_count_my_account?: number;
    }[];
    next_page_token?: string;
    to?: string;
};
type ReportsGetWebinarDetailReportsPathParams = {
    webinarId: string;
};
type ReportsGetWebinarDetailReportsResponse = {
    custom_keys?: {
        key?: string;
        value?: string;
    }[];
    dept?: string;
    duration?: number;
    end_time?: string;
    id?: number;
    participants_count?: number;
    start_time?: string;
    topic?: string;
    total_minutes?: number;
    tracking_fields?: {
        field?: string;
        value?: string;
    }[];
    type?: number;
    user_email?: string;
    user_name?: string;
    uuid?: string;
};
type ReportsGetWebinarParticipantReportsPathParams = {
    webinarId: string;
};
type ReportsGetWebinarParticipantReportsQueryParams = {
    page_size?: number;
    next_page_token?: string;
    include_fields?: string;
};
type ReportsGetWebinarParticipantReportsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    total_records?: number;
} & {
    participants?: {
        customer_key?: string;
        duration?: number;
        failover?: boolean;
        id?: string;
        join_time?: string;
        leave_time?: string;
        name?: string;
        registrant_id?: string;
        status?: string;
        user_email?: string;
        user_id?: string;
        participant_user_id?: string;
        bo_mtg_id?: string;
    }[];
};
type ReportsGetWebinarPollReportsPathParams = {
    webinarId: string;
};
type ReportsGetWebinarPollReportsResponse = {
    id?: number;
    questions?: {
        email?: string;
        name?: string;
        first_name?: string;
        last_name?: string;
        question_details?: {
            answer?: string;
            date_time?: string;
            polling_id?: string;
            question?: string;
        }[];
    }[];
    start_time?: string;
    uuid?: string;
};
type ReportsGetWebinarQAReportPathParams = {
    webinarId: string;
};
type ReportsGetWebinarQAReportResponse = {
    id?: number;
    questions?: {
        user_id?: string;
        email?: string;
        name?: string;
        question_details?: {
            answer?: string;
            question?: string;
            question_id?: string;
            create_time?: string;
            question_status?: string;
            answer_details?: {
                user_id?: string;
                name?: string;
                email?: string;
                content?: string;
                create_time?: string;
                type?: string;
            }[];
        }[];
    }[];
    start_time?: string;
    uuid?: string;
};
type ReportsGetWebinarSurveyReportPathParams = {
    webinarId: string;
};
type ReportsGetWebinarSurveyReportResponse = {
    webinar_id?: number;
    webinar_uuid?: string;
    start_time?: string;
    survey_id?: string;
    survey_name?: string;
    survey_answers?: {
        email?: string;
        name?: string;
        first_name?: string;
        last_name?: string;
        answer_details?: {
            question?: string;
            question_id?: string;
            answer?: string;
            date_time?: string;
        }[];
    }[];
};
type SIPPhoneListSIPPhonesQueryParams = {
    page_number?: number;
    search_key?: string;
    page_size?: number;
    next_page_token?: string;
};
type SIPPhoneListSIPPhonesResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    phones?: {
        authorization_name?: string;
        domain?: string;
        id?: string;
        password?: string;
        proxy_server?: string;
        proxy_server2?: string;
        proxy_server3?: string;
        register_server?: string;
        register_server2?: string;
        register_server3?: string;
        registration_expire_time?: number;
        transport_protocol?: string;
        transport_protocol2?: string;
        transport_protocol3?: string;
        user_email?: string;
        user_name?: string;
        voice_mail?: string;
    }[];
    total_records?: number;
};
type SIPPhoneEnableSIPPhoneRequestBody = {
    authorization_name: string;
    domain: string;
    password: string;
    proxy_server: string;
    proxy_server2?: string;
    proxy_server3?: string;
    register_server: string;
    register_server2?: string;
    register_server3?: string;
    registration_expire_time?: number;
    transport_protocol?: string;
    transport_protocol2?: string;
    transport_protocol3?: string;
    user_email: string;
    user_name: string;
    voice_mail: string;
};
type SIPPhoneEnableSIPPhoneResponse = {
    id?: string;
    authorization_name?: string;
    domain?: string;
    password?: string;
    proxy_server?: string;
    proxy_server2?: string;
    proxy_server3?: string;
    register_server?: string;
    register_server2?: string;
    register_server3?: string;
    registration_expire_time?: number;
    transport_protocol?: string;
    transport_protocol2?: string;
    transport_protocol3?: string;
    user_email?: string;
    user_name?: string;
    voice_mail?: string;
};
type SIPPhoneDeleteSIPPhonePathParams = {
    phoneId: string;
};
type SIPPhoneUpdateSIPPhonePathParams = {
    phoneId: string;
};
type SIPPhoneUpdateSIPPhoneRequestBody = {
    authorization_name: string;
    domain: string;
    password: string;
    proxy_server: string;
    proxy_server2: string;
    proxy_server3: string;
    register_server: string;
    register_server2: string;
    register_server3: string;
    registration_expire_time?: number;
    transport_protocol?: string;
    transport_protocol2?: string;
    transport_protocol3?: string;
    user_name: string;
    voice_mail: string;
};
type TSPGetAccountsTSPInformationResponse = {
    dial_in_number_unrestricted?: boolean;
    dial_in_numbers?: {
        code?: string;
        number?: string;
        type?: string;
    }[];
    enable?: boolean;
    master_account_setting_extended?: boolean;
    modify_credential_forbidden?: boolean;
    tsp_bridge?: string;
    tsp_enabled?: boolean;
    tsp_provider?: string;
};
type TSPUpdateAccountsTSPInformationRequestBody = {
    dial_in_number_unrestricted?: boolean;
    enable?: boolean;
    master_account_setting_extended?: boolean;
    modify_credential_forbidden?: boolean;
    tsp_bridge?: string;
    tsp_enabled?: boolean;
    tsp_provider?: string;
};
type TSPListUsersTSPAccountsPathParams = {
    userId: string;
};
type TSPListUsersTSPAccountsResponse = {
    tsp_accounts?: {
        conference_code: string;
        dial_in_numbers?: {
            code?: string;
            country_label?: string;
            number?: string;
            type?: string;
        }[];
        id?: string;
        leader_pin: string;
        tsp_bridge?: string;
    }[];
};
type TSPAddUsersTSPAccountPathParams = {
    userId: string;
};
type TSPAddUsersTSPAccountRequestBody = {
    conference_code: string;
    dial_in_numbers?: {
        code?: string;
        country_label?: string;
        number?: string;
        type?: string;
    }[];
    leader_pin: string;
    tsp_bridge?: string;
};
type TSPAddUsersTSPAccountResponse = {
    id?: string;
} & {
    conference_code: string;
    dial_in_numbers?: {
        code?: string;
        country_label?: string;
        number?: string;
        type?: string;
    }[];
    leader_pin: string;
    tsp_bridge?: string;
};
type TSPSetGlobalDialInURLForTSPUserPathParams = {
    userId: string;
};
type TSPSetGlobalDialInURLForTSPUserRequestBody = {
    audio_url?: string;
};
type TSPGetUsersTSPAccountPathParams = {
    userId: string;
    tspId: string;
};
type TSPGetUsersTSPAccountResponse = {
    conference_code: string;
    dial_in_numbers?: {
        code?: string;
        country_label?: string;
        number?: string;
        type?: string;
    }[];
    id?: string;
    leader_pin: string;
    tsp_bridge?: string;
};
type TSPDeleteUsersTSPAccountPathParams = {
    userId: string;
    tspId: string;
};
type TSPUpdateTSPAccountPathParams = {
    userId: string;
    tspId: string;
};
type TSPUpdateTSPAccountRequestBody = {
    conference_code: string;
    dial_in_numbers?: {
        code?: string;
        country_label?: string;
        number?: string;
        type?: string;
    }[];
    leader_pin: string;
    tsp_bridge?: string;
};
type TrackingFieldListTrackingFieldsResponse = {
    total_records?: number;
    tracking_fields?: ({
        id?: string;
    } & {
        field?: string;
        recommended_values?: string[];
        required?: boolean;
        visible?: boolean;
    })[];
};
type TrackingFieldCreateTrackingFieldRequestBody = {
    field?: string;
    recommended_values?: string[];
    required?: boolean;
    visible?: boolean;
};
type TrackingFieldCreateTrackingFieldResponse = {
    id?: string;
} & {
    field?: string;
    recommended_values?: string[];
    required?: boolean;
    visible?: boolean;
};
type TrackingFieldGetTrackingFieldPathParams = {
    fieldId: string;
};
type TrackingFieldGetTrackingFieldResponse = {
    id?: string;
} & {
    field?: string;
    recommended_values?: string[];
    required?: boolean;
    visible?: boolean;
};
type TrackingFieldDeleteTrackingFieldPathParams = {
    fieldId: string;
};
type TrackingFieldUpdateTrackingFieldPathParams = {
    fieldId: string;
};
type TrackingFieldUpdateTrackingFieldRequestBody = {
    field?: string;
    recommended_values?: string[];
    required?: boolean;
    visible?: boolean;
};
type WebinarsDeleteLiveWebinarMessagePathParams = {
    webinarId: number;
    messageId: string;
};
type WebinarsDeleteLiveWebinarMessageQueryParams = {
    file_ids?: string;
};
type WebinarsGetWebinarAbsenteesPathParams = {
    webinarId: string;
};
type WebinarsGetWebinarAbsenteesQueryParams = {
    occurrence_id?: string;
    page_size?: number;
    next_page_token?: string;
};
type WebinarsGetWebinarAbsenteesResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    registrants?: ({
        id?: string;
    } & {
        address?: string;
        city?: string;
        comments?: string;
        country?: string;
        custom_questions?: {
            title?: string;
            value?: string;
        }[];
        email: string;
        first_name: string;
        industry?: string;
        job_title?: string;
        last_name?: string;
        no_of_employees?: string;
        org?: string;
        phone?: string;
        purchasing_time_frame?: string;
        role_in_purchase_process?: string;
        state?: string;
        status?: string;
        zip?: string;
    } & {
        create_time?: string;
        join_url?: string;
        status?: string;
    })[];
};
type WebinarsListPastWebinarInstancesPathParams = {
    webinarId: number;
};
type WebinarsListPastWebinarInstancesResponse = {
    webinars?: {
        start_time?: string;
        uuid?: string;
    }[];
};
type WebinarsListWebinarParticipantsPathParams = {
    webinarId: string;
};
type WebinarsListWebinarParticipantsQueryParams = {
    page_size?: number;
    next_page_token?: string;
};
type WebinarsListWebinarParticipantsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_size?: number;
    participants?: {
        id?: string;
        name?: string;
        user_id?: string;
        registrant_id?: string;
        user_email?: string;
        join_time?: string;
        leave_time?: string;
        duration?: number;
        failover?: boolean;
        status?: string;
        internal_user?: boolean;
    }[];
    total_records?: number;
};
type WebinarsListPastWebinarPollResultsPathParams = {
    webinarId: string;
};
type WebinarsListPastWebinarPollResultsResponse = {
    id?: number;
    questions?: {
        email?: string;
        name?: string;
        question_details?: {
            answer?: string;
            date_time?: string;
            polling_id?: string;
            question?: string;
        }[];
    }[];
    start_time?: string;
    uuid?: string;
};
type WebinarsListQAsOfPastWebinarPathParams = {
    webinarId: string;
};
type WebinarsListQAsOfPastWebinarResponse = {
    id?: number;
    questions?: {
        email?: string;
        name?: string;
        question_details?: {
            answer?: string;
            question?: string;
        }[];
    }[];
    start_time?: string;
    uuid?: string;
};
type WebinarsListWebinarTemplatesPathParams = {
    userId: string;
};
type WebinarsListWebinarTemplatesResponse = {
    templates?: {
        id?: string;
        name?: string;
        type?: number;
    }[];
    total_records?: number;
};
type WebinarsCreateWebinarTemplatePathParams = {
    userId: string;
};
type WebinarsCreateWebinarTemplateRequestBody = {
    webinar_id?: number;
    name?: string;
    save_recurrence?: boolean;
    overwrite?: boolean;
};
type WebinarsCreateWebinarTemplateResponse = {
    id?: string;
    name?: string;
};
type WebinarsListWebinarsPathParams = {
    userId: string;
};
type WebinarsListWebinarsQueryParams = {
    type?: string;
    page_size?: number;
    page_number?: number;
};
type WebinarsListWebinarsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    webinars?: {
        agenda?: string;
        created_at?: string;
        duration?: number;
        host_id?: string;
        id?: number;
        join_url?: string;
        start_time?: string;
        timezone?: string;
        topic?: string;
        type?: number;
        uuid?: string;
        is_simulive?: boolean;
    }[];
};
type WebinarsCreateWebinarPathParams = {
    userId: string;
};
type WebinarsCreateWebinarRequestBody = {
    agenda?: string;
    duration?: number;
    password?: string;
    default_passcode?: boolean;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    schedule_for?: string;
    settings?: {
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_host_update_polls?: boolean;
        approval_type?: number;
        attendees_and_panelists_reminder_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_option?: string;
        auto_recording?: string;
        close_registration?: boolean;
        contact_email?: string;
        contact_name?: string;
        email_language?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        follow_up_absentees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        follow_up_attendees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        global_dial_in_countries?: string[];
        hd_video?: boolean;
        hd_video_for_attendees?: boolean;
        host_video?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        panelist_authentication?: boolean;
        meeting_authentication?: boolean;
        add_watermark?: boolean;
        add_audio_watermark?: boolean;
        on_demand?: boolean;
        panelists_invitation_email_notification?: boolean;
        panelists_video?: boolean;
        post_webinar_survey?: boolean;
        practice_session?: boolean;
        question_and_answer?: {
            allow_submit_questions?: boolean;
            allow_anonymous_questions?: boolean;
            answer_questions?: string;
            attendees_can_comment?: boolean;
            attendees_can_upvote?: boolean;
            allow_auto_reply?: boolean;
            auto_reply_text?: string;
            enable?: boolean;
        };
        registrants_email_notification?: boolean;
        registrants_restrict_number?: number;
        registration_type?: number;
        send_1080p_video_to_attendees?: boolean;
        show_share_button?: boolean;
        survey_url?: string;
        enable_session_branding?: boolean;
    };
    start_time?: string;
    template_id?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field: string;
        value?: string;
    }[];
    type?: number;
    is_simulive?: boolean;
    record_file_id?: string;
};
type WebinarsCreateWebinarResponse = {
    host_email?: string;
    host_id?: string;
    id?: number;
    registrants_confirmation_email?: boolean;
    template_id?: string;
    uuid?: string;
    agenda?: string;
    created_at?: string;
    duration?: number;
    join_url?: string;
    occurrences?: {
        duration?: number;
        occurrence_id?: string;
        start_time?: string;
        status?: string;
    }[];
    password?: string;
    encrypted_passcode?: string;
    h323_passcode?: string;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    settings?: {
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_host_update_polls?: boolean;
        approval_type?: number;
        attendees_and_panelists_reminder_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_name?: string;
        authentication_option?: string;
        auto_recording?: string;
        close_registration?: boolean;
        contact_email?: string;
        contact_name?: string;
        email_language?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        follow_up_absentees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        follow_up_attendees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        global_dial_in_countries?: string[];
        hd_video?: boolean;
        hd_video_for_attendees?: boolean;
        host_video?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        panelist_authentication?: boolean;
        meeting_authentication?: boolean;
        add_watermark?: boolean;
        add_audio_watermark?: boolean;
        notify_registrants?: boolean;
        on_demand?: boolean;
        panelists_invitation_email_notification?: boolean;
        panelists_video?: boolean;
        post_webinar_survey?: boolean;
        practice_session?: boolean;
        question_and_answer?: {
            allow_submit_questions?: boolean;
            allow_anonymous_questions?: boolean;
            answer_questions?: string;
            attendees_can_comment?: boolean;
            attendees_can_upvote?: boolean;
            allow_auto_reply?: boolean;
            auto_reply_text?: string;
            enable?: boolean;
        };
        registrants_confirmation_email?: boolean;
        registrants_email_notification?: boolean;
        registrants_restrict_number?: number;
        registration_type?: number;
        send_1080p_video_to_attendees?: boolean;
        show_share_button?: boolean;
        survey_url?: string;
        enable_session_branding?: boolean;
    };
    start_time?: string;
    start_url?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field?: string;
        value?: string;
    }[];
    type?: number;
    is_simulive?: boolean;
    record_file_id?: string;
    creation_source?: string;
};
type WebinarsGetWebinarPathParams = {
    webinarId: string;
};
type WebinarsGetWebinarQueryParams = {
    occurrence_id?: string;
    show_previous_occurrences?: boolean;
};
type WebinarsGetWebinarResponse = {
    host_email?: string;
    host_id?: string;
    id?: number;
    uuid?: string;
    agenda?: string;
    created_at?: string;
    duration?: number;
    join_url?: string;
    occurrences?: {
        duration?: number;
        occurrence_id?: string;
        start_time?: string;
        status?: string;
    }[];
    password?: string;
    encrypted_passcode?: string;
    h323_passcode?: string;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    settings?: {
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_host_update_polls?: boolean;
        approval_type?: number;
        attendees_and_panelists_reminder_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_name?: string;
        authentication_option?: string;
        auto_recording?: string;
        close_registration?: boolean;
        contact_email?: string;
        contact_name?: string;
        email_language?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        follow_up_absentees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        follow_up_attendees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        global_dial_in_countries?: string[];
        hd_video?: boolean;
        hd_video_for_attendees?: boolean;
        host_video?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        panelist_authentication?: boolean;
        meeting_authentication?: boolean;
        add_watermark?: boolean;
        add_audio_watermark?: boolean;
        notify_registrants?: boolean;
        on_demand?: boolean;
        panelists_invitation_email_notification?: boolean;
        panelists_video?: boolean;
        post_webinar_survey?: boolean;
        practice_session?: boolean;
        question_and_answer?: {
            allow_submit_questions?: boolean;
            allow_anonymous_questions?: boolean;
            answer_questions?: string;
            attendees_can_comment?: boolean;
            attendees_can_upvote?: boolean;
            allow_auto_reply?: boolean;
            auto_reply_text?: string;
            enable?: boolean;
        };
        registrants_confirmation_email?: boolean;
        registrants_email_notification?: boolean;
        registrants_restrict_number?: number;
        registration_type?: number;
        send_1080p_video_to_attendees?: boolean;
        show_share_button?: boolean;
        survey_url?: string;
        enable_session_branding?: boolean;
    };
    start_time?: string;
    start_url?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field?: string;
        value?: string;
    }[];
    type?: number;
    is_simulive?: boolean;
    record_file_id?: string;
    creation_source?: string;
};
type WebinarsDeleteWebinarPathParams = {
    webinarId: number;
};
type WebinarsDeleteWebinarQueryParams = {
    occurrence_id?: string;
    cancel_webinar_reminder?: boolean;
};
type WebinarsUpdateWebinarPathParams = {
    webinarId: number;
};
type WebinarsUpdateWebinarQueryParams = {
    occurrence_id?: string;
};
type WebinarsUpdateWebinarRequestBody = {
    agenda?: string;
    duration?: number;
    password?: string;
    schedule_for?: string;
    recurrence?: {
        end_date_time?: string;
        end_times?: number;
        monthly_day?: number;
        monthly_week?: number;
        monthly_week_day?: number;
        repeat_interval?: number;
        type: number;
        weekly_days?: string;
    };
    settings?: {
        allow_multiple_devices?: boolean;
        alternative_hosts?: string;
        alternative_host_update_polls?: boolean;
        approval_type?: number;
        attendees_and_panelists_reminder_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        audio?: string;
        audio_conference_info?: string;
        authentication_domains?: string;
        authentication_name?: string;
        authentication_option?: string;
        auto_recording?: string;
        close_registration?: boolean;
        contact_email?: string;
        contact_name?: string;
        email_language?: string;
        enforce_login?: boolean;
        enforce_login_domains?: string;
        follow_up_absentees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        follow_up_attendees_email_notification?: {
            enable?: boolean;
            type?: number;
        };
        global_dial_in_countries?: string[];
        hd_video?: boolean;
        hd_video_for_attendees?: boolean;
        host_video?: boolean;
        language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                languages?: string;
            }[];
        };
        sign_language_interpretation?: {
            enable?: boolean;
            interpreters?: {
                email?: string;
                sign_language?: string;
            }[];
        };
        panelist_authentication?: boolean;
        meeting_authentication?: boolean;
        add_watermark?: boolean;
        add_audio_watermark?: boolean;
        notify_registrants?: boolean;
        on_demand?: boolean;
        panelists_invitation_email_notification?: boolean;
        panelists_video?: boolean;
        post_webinar_survey?: boolean;
        practice_session?: boolean;
        question_and_answer?: {
            allow_submit_questions?: boolean;
            allow_anonymous_questions?: boolean;
            answer_questions?: string;
            attendees_can_comment?: boolean;
            attendees_can_upvote?: boolean;
            allow_auto_reply?: boolean;
            auto_reply_text?: string;
            enable?: boolean;
        };
        registrants_confirmation_email?: boolean;
        registrants_email_notification?: boolean;
        registrants_restrict_number?: number;
        registration_type?: number;
        send_1080p_video_to_attendees?: boolean;
        show_share_button?: boolean;
        survey_url?: string;
        enable_session_branding?: boolean;
    };
    start_time?: string;
    timezone?: string;
    topic?: string;
    tracking_fields?: {
        field?: string;
        value?: string;
    }[];
    type?: number;
    is_simulive?: boolean;
    record_file_id?: string;
};
type WebinarsPerformBatchRegistrationPathParams = {
    webinarId: string;
};
type WebinarsPerformBatchRegistrationRequestBody = {
    auto_approve?: boolean;
    registrants?: {
        email: string;
        first_name: string;
        last_name?: string;
    }[];
};
type WebinarsPerformBatchRegistrationResponse = {
    registrants?: {
        email?: string;
        join_url?: string;
        registrant_id?: string;
    }[];
};
type WebinarsGetWebinarsSessionBrandingPathParams = {
    webinarId: number;
};
type WebinarsGetWebinarsSessionBrandingResponse = {
    wallpaper?: {
        id?: string;
    };
    virtual_backgrounds?: {
        id?: string;
        name?: string;
        is_default?: boolean;
    }[];
    name_tags?: {
        id?: string;
        name?: string;
        text_color?: string;
        accent_color?: string;
        background_color?: string;
        is_default?: boolean;
    }[];
};
type WebinarsCreateWebinarsBrandingNameTagPathParams = {
    webinarId: number;
};
type WebinarsCreateWebinarsBrandingNameTagRequestBody = {
    name: string;
    text_color: string;
    accent_color: string;
    background_color: string;
    is_default?: boolean;
    set_default_for_all_panelists?: boolean;
};
type WebinarsCreateWebinarsBrandingNameTagResponse = {
    id?: string;
    name?: string;
    text_color?: string;
    accent_color?: string;
    background_color?: string;
    is_default?: boolean;
};
type WebinarsDeleteWebinarsBrandingNameTagPathParams = {
    webinarId: number;
};
type WebinarsDeleteWebinarsBrandingNameTagQueryParams = {
    name_tag_ids?: string;
};
type WebinarsUpdateWebinarsBrandingNameTagPathParams = {
    webinarId: number;
    nameTagId: string;
};
type WebinarsUpdateWebinarsBrandingNameTagRequestBody = {
    name?: string;
    text_color?: string;
    accent_color?: string;
    background_color?: string;
    is_default?: boolean;
    set_default_for_all_panelists?: boolean;
};
type WebinarsUploadWebinarsBrandingVirtualBackgroundPathParams = {
    webinarId: number;
};
type WebinarsUploadWebinarsBrandingVirtualBackgroundRequestBody = {
    file: Blob | Buffer | ReadStream;
    default?: boolean;
    set_default_for_all_panelists?: boolean;
};
type WebinarsUploadWebinarsBrandingVirtualBackgroundResponse = {
    id?: string;
    name?: string;
    is_default?: boolean;
    size?: number;
    type?: string;
};
type WebinarsDeleteWebinarsBrandingVirtualBackgroundsPathParams = {
    webinarId: number;
};
type WebinarsDeleteWebinarsBrandingVirtualBackgroundsQueryParams = {
    ids?: string;
};
type WebinarsSetWebinarsDefaultBrandingVirtualBackgroundPathParams = {
    webinarId: number;
};
type WebinarsSetWebinarsDefaultBrandingVirtualBackgroundQueryParams = {
    id?: string;
    set_default_for_all_panelists?: boolean;
};
type WebinarsUploadWebinarsBrandingWallpaperPathParams = {
    webinarId: number;
};
type WebinarsUploadWebinarsBrandingWallpaperRequestBody = {
    file: Blob | Buffer | ReadStream;
};
type WebinarsUploadWebinarsBrandingWallpaperResponse = {
    id?: string;
    name?: string;
    size?: number;
    type?: string;
};
type WebinarsDeleteWebinarsBrandingWallpaperPathParams = {
    webinarId: number;
};
type WebinarsCreateWebinarsInviteLinksPathParams = {
    webinarId: number;
};
type WebinarsCreateWebinarsInviteLinksRequestBody = {
    attendees?: {
        name: string;
    }[];
    ttl?: number;
};
type WebinarsCreateWebinarsInviteLinksResponse = {
    attendees?: {
        join_url?: string;
        name?: string;
    }[];
};
type WebinarsGetWebinarsJoinTokenForLiveStreamingPathParams = {
    webinarId: number;
};
type WebinarsGetWebinarsJoinTokenForLiveStreamingResponse = {
    expire_in?: number;
    token?: string;
};
type WebinarsGetWebinarsArchiveTokenForLocalArchivingPathParams = {
    webinarId: number;
};
type WebinarsGetWebinarsArchiveTokenForLocalArchivingResponse = {
    expire_in?: number;
    token?: string;
};
type WebinarsGetWebinarsJoinTokenForLocalRecordingPathParams = {
    webinarId: number;
};
type WebinarsGetWebinarsJoinTokenForLocalRecordingResponse = {
    expire_in?: number;
    token?: string;
};
type WebinarsGetLiveStreamDetailsPathParams = {
    webinarId: string;
};
type WebinarsGetLiveStreamDetailsResponse = {
    page_url?: string;
    stream_key?: string;
    stream_url?: string;
    resolution?: string;
};
type WebinarsUpdateLiveStreamPathParams = {
    webinarId: number;
};
type WebinarsUpdateLiveStreamRequestBody = {
    page_url: string;
    stream_key: string;
    stream_url: string;
    resolution?: string;
};
type WebinarsUpdateLiveStreamStatusPathParams = {
    webinarId: number;
};
type WebinarsUpdateLiveStreamStatusRequestBody = {
    action?: string;
    settings?: {
        active_speaker_name?: boolean;
        display_name?: string;
    };
};
type WebinarsListPanelistsPathParams = {
    webinarId: number;
};
type WebinarsListPanelistsResponse = {
    panelists?: ({
        id?: string;
    } & {
        email?: string;
        name?: string;
    } & {
        join_url?: string;
    } & {
        virtual_background_id?: string;
        name_tag_id?: string;
        name_tag_name?: string;
        name_tag_pronouns?: string;
        name_tag_description?: string;
    })[];
    total_records?: number;
};
type WebinarsAddPanelistsPathParams = {
    webinarId: number;
};
type WebinarsAddPanelistsRequestBody = {
    panelists?: ({
        email?: string;
        name?: string;
    } & {
        virtual_background_id?: string;
        name_tag_id?: string;
        name_tag_name?: string;
        name_tag_pronouns?: string;
        name_tag_description?: string;
    })[];
};
type WebinarsAddPanelistsResponse = {
    id?: string;
    updated_at?: string;
};
type WebinarsRemoveAllPanelistsPathParams = {
    webinarId: number;
};
type WebinarsRemovePanelistPathParams = {
    webinarId: number;
    panelistId: string;
};
type WebinarsListWebinarsPollsPathParams = {
    webinarId: number;
};
type WebinarsListWebinarsPollsQueryParams = {
    anonymous?: boolean;
};
type WebinarsListWebinarsPollsResponse = {
    polls?: ({
        id?: string;
        status?: string;
    } & {
        anonymous?: boolean;
        poll_type?: number;
        questions?: {
            answer_max_character?: number;
            answer_min_character?: number;
            answer_required?: boolean;
            answers?: string[];
            case_sensitive?: boolean;
            name?: string;
            prompts?: {
                prompt_question?: string;
                prompt_right_answers?: string[];
            }[];
            rating_max_label?: string;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_min_value?: number;
            right_answers?: string[];
            show_as_dropdown?: boolean;
            type?: string;
        }[];
        title?: string;
    })[];
    total_records?: number;
};
type WebinarsCreateWebinarsPollPathParams = {
    webinarId: number;
};
type WebinarsCreateWebinarsPollRequestBody = {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type WebinarsCreateWebinarsPollResponse = {
    id?: string;
    status?: string;
} & {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type WebinarsGetWebinarPollPathParams = {
    webinarId: number;
    pollId: string;
};
type WebinarsGetWebinarPollResponse = {
    id?: string;
    status?: string;
} & {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type WebinarsUpdateWebinarPollPathParams = {
    webinarId: number;
    pollId: string;
};
type WebinarsUpdateWebinarPollRequestBody = {
    anonymous?: boolean;
    poll_type?: number;
    questions?: {
        answer_max_character?: number;
        answer_min_character?: number;
        answer_required?: boolean;
        answers?: string[];
        case_sensitive?: boolean;
        name?: string;
        prompts?: {
            prompt_question?: string;
            prompt_right_answers?: string[];
        }[];
        rating_max_label?: string;
        rating_max_value?: number;
        rating_min_label?: string;
        rating_min_value?: number;
        right_answers?: string[];
        show_as_dropdown?: boolean;
        type?: string;
    }[];
    title?: string;
};
type WebinarsDeleteWebinarPollPathParams = {
    webinarId: number;
    pollId: string;
};
type WebinarsListWebinarRegistrantsPathParams = {
    webinarId: number;
};
type WebinarsListWebinarRegistrantsQueryParams = {
    occurrence_id?: string;
    status?: string;
    tracking_source_id?: string;
    page_size?: number;
    page_number?: number;
    next_page_token?: string;
};
type WebinarsListWebinarRegistrantsResponse = {
    next_page_token?: string;
    page_count?: number;
    page_number?: number;
    page_size?: number;
    total_records?: number;
} & {
    registrants?: ({
        id?: string;
    } & {
        address?: string;
        city?: string;
        comments?: string;
        country?: string;
        custom_questions?: {
            title?: string;
            value?: string;
        }[];
        email: string;
        first_name: string;
        industry?: string;
        job_title?: string;
        last_name?: string;
        no_of_employees?: string;
        org?: string;
        phone?: string;
        purchasing_time_frame?: string;
        role_in_purchase_process?: string;
        state?: string;
        status?: string;
        zip?: string;
    } & {
        create_time?: string;
        join_url?: string;
        status?: string;
    })[];
};
type WebinarsAddWebinarRegistrantPathParams = {
    webinarId: number;
};
type WebinarsAddWebinarRegistrantQueryParams = {
    occurrence_ids?: string;
};
type WebinarsAddWebinarRegistrantRequestBody = {
    first_name: string;
    last_name?: string;
    email: string;
    address?: string;
    city?: string;
    state?: string;
    zip?: string;
    country?: string;
    phone?: string;
    comments?: string;
    custom_questions?: {
        title?: string;
        value?: string;
    }[];
    industry?: string;
    job_title?: string;
    no_of_employees?: string;
    org?: string;
    purchasing_time_frame?: string;
    role_in_purchase_process?: string;
} & {
    language?: string;
    source_id?: string;
};
type WebinarsAddWebinarRegistrantResponse = {
    id?: number;
    join_url?: string;
    registrant_id?: string;
    start_time?: string;
    topic?: string;
    occurrences?: {
        duration?: number;
        occurrence_id?: string;
        start_time?: string;
        status?: string;
    }[];
};
type WebinarsListRegistrationQuestionsPathParams = {
    webinarId: number;
};
type WebinarsListRegistrationQuestionsResponse = {
    custom_questions?: {
        answers?: string[];
        required?: boolean;
        title?: string;
        type?: string;
    }[];
    questions?: {
        field_name?: string;
        required?: boolean;
    }[];
};
type WebinarsUpdateRegistrationQuestionsPathParams = {
    webinarId: number;
};
type WebinarsUpdateRegistrationQuestionsRequestBody = {
    custom_questions?: {
        answers?: string[];
        required?: boolean;
        title?: string;
        type?: string;
    }[];
    questions?: {
        field_name?: string;
        required?: boolean;
    }[];
};
type WebinarsUpdateRegistrantsStatusPathParams = {
    webinarId: number;
};
type WebinarsUpdateRegistrantsStatusQueryParams = {
    occurrence_id?: string;
};
type WebinarsUpdateRegistrantsStatusRequestBody = {
    action: string;
    registrants?: {
        email?: string;
        id?: string;
    }[];
};
type WebinarsGetWebinarRegistrantPathParams = {
    webinarId: number;
    registrantId: string;
};
type WebinarsGetWebinarRegistrantQueryParams = {
    occurrence_id?: string;
};
type WebinarsGetWebinarRegistrantResponse = {
    id?: string;
} & ({
    address?: string;
    city?: string;
    comments?: string;
    country?: string;
    custom_questions?: {
        title?: string;
        value?: string;
    }[];
    email: string;
    first_name: string;
    industry?: string;
    job_title?: string;
    last_name?: string;
    no_of_employees?: string;
    org?: string;
    phone?: string;
    purchasing_time_frame?: string;
    role_in_purchase_process?: string;
    state?: string;
    status?: string;
    zip?: string;
} & {
    language?: string;
}) & {
    create_time?: string;
    join_url?: string;
    status?: string;
};
type WebinarsDeleteWebinarRegistrantPathParams = {
    webinarId: number;
    registrantId: string;
};
type WebinarsDeleteWebinarRegistrantQueryParams = {
    occurrence_id?: string;
};
type WebinarsGetWebinarSIPURIWithPasscodePathParams = {
    webinarId: number;
};
type WebinarsGetWebinarSIPURIWithPasscodeRequestBody = {
    passcode?: string;
};
type WebinarsGetWebinarSIPURIWithPasscodeResponse = {
    sip_dialing?: string;
    paid_crc_plan_participant?: boolean;
    participant_identifier_code?: string;
    expire_in?: number;
};
type WebinarsUpdateWebinarStatusPathParams = {
    webinarId: number;
};
type WebinarsUpdateWebinarStatusRequestBody = {
    action?: string;
};
type WebinarsGetWebinarSurveyPathParams = {
    webinarId: number;
};
type WebinarsGetWebinarSurveyResponse = {
    custom_survey?: {
        title?: string;
        anonymous?: boolean;
        numbered_questions?: boolean;
        show_question_type?: boolean;
        feedback?: string;
        questions?: {
            name?: string;
            type?: string;
            answer_required?: boolean;
            show_as_dropdown?: boolean;
            answers?: string[];
            prompts?: {
                prompt_question?: string;
            }[];
            answer_min_character?: number;
            answer_max_character?: number;
            rating_min_value?: number;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_max_label?: string;
        }[];
    };
    show_in_the_browser?: boolean;
    show_in_the_follow_up_email?: boolean;
    third_party_survey?: string;
};
type WebinarsDeleteWebinarSurveyPathParams = {
    webinarId: number;
};
type WebinarsUpdateWebinarSurveyPathParams = {
    webinarId: number;
};
type WebinarsUpdateWebinarSurveyRequestBody = {
    custom_survey?: {
        title?: string;
        anonymous?: boolean;
        numbered_questions?: boolean;
        show_question_type?: boolean;
        feedback?: string;
        questions?: {
            name?: string;
            type?: string;
            answer_required?: boolean;
            show_as_dropdown?: boolean;
            answers?: string[];
            prompts?: {
                prompt_question?: string;
            }[];
            answer_min_character?: number;
            answer_max_character?: number;
            rating_min_value?: number;
            rating_max_value?: number;
            rating_min_label?: string;
            rating_max_label?: string;
        }[];
    };
    show_in_the_browser?: boolean;
    show_in_the_follow_up_email?: boolean;
    third_party_survey?: string;
};
type WebinarsGetWebinarsTokenPathParams = {
    webinarId: number;
};
type WebinarsGetWebinarsTokenQueryParams = {
    type?: string;
};
type WebinarsGetWebinarsTokenResponse = {
    token?: string;
};
type WebinarsGetWebinarTrackingSourcesPathParams = {
    webinarId: number;
};
type WebinarsGetWebinarTrackingSourcesResponse = {
    total_records?: number;
    tracking_sources?: {
        id?: string;
        registration_count?: number;
        source_name?: string;
        tracking_url?: string;
        visitor_count?: number;
    }[];
};
declare class MeetingsEndpoints extends WebEndpoints {
    readonly archiving: {
        listArchivedFiles: (_: object & {
            query?: ArchivingListArchivedFilesQueryParams;
        }) => Promise<BaseResponse<ArchivingListArchivedFilesResponse>>;
        getArchivedFileStatistics: (_: object & {
            query?: ArchivingGetArchivedFileStatisticsQueryParams;
        }) => Promise<BaseResponse<ArchivingGetArchivedFileStatisticsResponse>>;
        updateArchivedFilesAutoDeleteStatus: (_: {
            path: ArchivingUpdateArchivedFilesAutoDeleteStatusPathParams;
        } & {
            body: ArchivingUpdateArchivedFilesAutoDeleteStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getMeetingsArchivedFiles: (_: {
            path: ArchivingGetMeetingsArchivedFilesPathParams;
        } & object) => Promise<BaseResponse<ArchivingGetMeetingsArchivedFilesResponse>>;
        deleteMeetingsArchivedFiles: (_: {
            path: ArchivingDeleteMeetingsArchivedFilesPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly cloudRecording: {
        getMeetingRecordings: (_: {
            path: CloudRecordingGetMeetingRecordingsPathParams;
        } & object & {
            query?: CloudRecordingGetMeetingRecordingsQueryParams;
        }) => Promise<BaseResponse<CloudRecordingGetMeetingRecordingsResponse>>;
        deleteMeetingOrWebinarRecordings: (_: {
            path: CloudRecordingDeleteMeetingOrWebinarRecordingsPathParams;
        } & object & {
            query?: CloudRecordingDeleteMeetingOrWebinarRecordingsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getMeetingOrWebinarRecordingsAnalyticsDetails: (_: {
            path: CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsPathParams;
        } & object & {
            query?: CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsQueryParams;
        }) => Promise<BaseResponse<CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsResponse>>;
        getMeetingOrWebinarRecordingsAnalyticsSummary: (_: {
            path: CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryPathParams;
        } & object & {
            query?: CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryQueryParams;
        }) => Promise<BaseResponse<CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryResponse>>;
        listRecordingRegistrants: (_: {
            path: CloudRecordingListRecordingRegistrantsPathParams;
        } & object & {
            query?: CloudRecordingListRecordingRegistrantsQueryParams;
        }) => Promise<BaseResponse<CloudRecordingListRecordingRegistrantsResponse>>;
        createRecordingRegistrant: (_: {
            path: CloudRecordingCreateRecordingRegistrantPathParams;
        } & {
            body: CloudRecordingCreateRecordingRegistrantRequestBody;
        } & object) => Promise<BaseResponse<CloudRecordingCreateRecordingRegistrantResponse>>;
        getRegistrationQuestions: (_: {
            path: CloudRecordingGetRegistrationQuestionsPathParams;
        } & object) => Promise<BaseResponse<CloudRecordingGetRegistrationQuestionsResponse>>;
        updateRegistrationQuestions: (_: {
            path: CloudRecordingUpdateRegistrationQuestionsPathParams;
        } & {
            body?: CloudRecordingUpdateRegistrationQuestionsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateRegistrantsStatus: (_: {
            path: CloudRecordingUpdateRegistrantsStatusPathParams;
        } & {
            body: CloudRecordingUpdateRegistrantsStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getMeetingRecordingSettings: (_: {
            path: CloudRecordingGetMeetingRecordingSettingsPathParams;
        } & object) => Promise<BaseResponse<CloudRecordingGetMeetingRecordingSettingsResponse>>;
        updateMeetingRecordingSettings: (_: {
            path: CloudRecordingUpdateMeetingRecordingSettingsPathParams;
        } & {
            body?: CloudRecordingUpdateMeetingRecordingSettingsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteRecordingFileForMeetingOrWebinar: (_: {
            path: CloudRecordingDeleteRecordingFileForMeetingOrWebinarPathParams;
        } & object & {
            query?: CloudRecordingDeleteRecordingFileForMeetingOrWebinarQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        recoverSingleRecording: (_: {
            path: CloudRecordingRecoverSingleRecordingPathParams;
        } & {
            body?: CloudRecordingRecoverSingleRecordingRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        recoverMeetingRecordings: (_: {
            path: CloudRecordingRecoverMeetingRecordingsPathParams;
        } & {
            body?: CloudRecordingRecoverMeetingRecordingsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listAllRecordings: (_: {
            path: CloudRecordingListAllRecordingsPathParams;
        } & object & {
            query?: CloudRecordingListAllRecordingsQueryParams;
        }) => Promise<BaseResponse<CloudRecordingListAllRecordingsResponse>>;
    };
    readonly devices: {
        listDevices: (_: object & {
            query?: DevicesListDevicesQueryParams;
        }) => Promise<BaseResponse<DevicesListDevicesResponse>>;
        addNewDevice: (_: object & {
            body: DevicesAddNewDeviceRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        getZDMGroupInfo: (_: object & {
            query?: DevicesGetZDMGroupInfoQueryParams;
        }) => Promise<BaseResponse<DevicesGetZDMGroupInfoResponse>>;
        assignDeviceToUserOrCommonarea: (_: object & {
            body: DevicesAssignDeviceToUserOrCommonareaRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        upgradeZpaOsApp: (_: object & {
            body: DevicesUpgradeZpaOsAppRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        deleteZPADeviceByVendorAndMacAddress: (_: {
            path: DevicesDeleteZPADeviceByVendorAndMacAddressPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getZPAVersionInfo: (_: {
            path: DevicesGetZPAVersionInfoPathParams;
        } & object) => Promise<BaseResponse<DevicesGetZPAVersionInfoResponse>>;
        getDeviceDetail: (_: {
            path: DevicesGetDeviceDetailPathParams;
        } & object) => Promise<BaseResponse<DevicesGetDeviceDetailResponse>>;
        deleteDevice: (_: {
            path: DevicesDeleteDevicePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        changeDevice: (_: {
            path: DevicesChangeDevicePathParams;
        } & {
            body: DevicesChangeDeviceRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        changeDeviceAssociation: (_: {
            path: DevicesChangeDeviceAssociationPathParams;
        } & {
            body?: DevicesChangeDeviceAssociationRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly h323Devices: {
        listHSIPDevices: (_: object & {
            query?: H323DevicesListHSIPDevicesQueryParams;
        }) => Promise<BaseResponse<H323DevicesListHSIPDevicesResponse>>;
        createHSIPDevice: (_: object & {
            body: H323DevicesCreateHSIPDeviceRequestBody;
        }) => Promise<BaseResponse<H323DevicesCreateHSIPDeviceResponse>>;
        deleteHSIPDevice: (_: {
            path: H323DevicesDeleteHSIPDevicePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateHSIPDevice: (_: {
            path: H323DevicesUpdateHSIPDevicePathParams;
        } & {
            body: H323DevicesUpdateHSIPDeviceRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly meetings: {
        deleteLiveMeetingMessage: (_: {
            path: MeetingsDeleteLiveMeetingMessagePathParams;
        } & object & {
            query?: MeetingsDeleteLiveMeetingMessageQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateLiveMeetingMessage: (_: {
            path: MeetingsUpdateLiveMeetingMessagePathParams;
        } & {
            body: MeetingsUpdateLiveMeetingMessageRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        useInMeetingControls: (_: {
            path: MeetingsUseInMeetingControlsPathParams;
        } & {
            body?: MeetingsUseInMeetingControlsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listMeetingSummariesOfAccount: (_: object & {
            query?: MeetingsListMeetingSummariesOfAccountQueryParams;
        }) => Promise<BaseResponse<MeetingsListMeetingSummariesOfAccountResponse>>;
        getMeeting: (_: {
            path: MeetingsGetMeetingPathParams;
        } & object & {
            query?: MeetingsGetMeetingQueryParams;
        }) => Promise<BaseResponse<MeetingsGetMeetingResponse>>;
        deleteMeeting: (_: {
            path: MeetingsDeleteMeetingPathParams;
        } & object & {
            query?: MeetingsDeleteMeetingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateMeeting: (_: {
            path: MeetingsUpdateMeetingPathParams;
        } & {
            body?: MeetingsUpdateMeetingRequestBody;
        } & {
            query?: MeetingsUpdateMeetingQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        performBatchPollCreation: (_: {
            path: MeetingsPerformBatchPollCreationPathParams;
        } & {
            body?: MeetingsPerformBatchPollCreationRequestBody;
        } & object) => Promise<BaseResponse<MeetingsPerformBatchPollCreationResponse>>;
        performBatchRegistration: (_: {
            path: MeetingsPerformBatchRegistrationPathParams;
        } & {
            body?: MeetingsPerformBatchRegistrationRequestBody;
        } & object) => Promise<BaseResponse<MeetingsPerformBatchRegistrationResponse>>;
        getMeetingInvitation: (_: {
            path: MeetingsGetMeetingInvitationPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingInvitationResponse>>;
        createMeetingsInviteLinks: (_: {
            path: MeetingsCreateMeetingsInviteLinksPathParams;
        } & {
            body?: MeetingsCreateMeetingsInviteLinksRequestBody;
        } & object) => Promise<BaseResponse<MeetingsCreateMeetingsInviteLinksResponse>>;
        getMeetingsJoinTokenForLiveStreaming: (_: {
            path: MeetingsGetMeetingsJoinTokenForLiveStreamingPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingsJoinTokenForLiveStreamingResponse>>;
        getMeetingsArchiveTokenForLocalArchiving: (_: {
            path: MeetingsGetMeetingsArchiveTokenForLocalArchivingPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingsArchiveTokenForLocalArchivingResponse>>;
        getMeetingsJoinTokenForLocalRecording: (_: {
            path: MeetingsGetMeetingsJoinTokenForLocalRecordingPathParams;
        } & object & {
            query?: MeetingsGetMeetingsJoinTokenForLocalRecordingQueryParams;
        }) => Promise<BaseResponse<MeetingsGetMeetingsJoinTokenForLocalRecordingResponse>>;
        getLivestreamDetails: (_: {
            path: MeetingsGetLivestreamDetailsPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetLivestreamDetailsResponse>>;
        updateLivestream: (_: {
            path: MeetingsUpdateLivestreamPathParams;
        } & {
            body: MeetingsUpdateLivestreamRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateLivestreamStatus: (_: {
            path: MeetingsUpdateLivestreamStatusPathParams;
        } & {
            body?: MeetingsUpdateLivestreamStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getMeetingSummary: (_: {
            path: MeetingsGetMeetingSummaryPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingSummaryResponse>>;
        addMeetingApp: (_: {
            path: MeetingsAddMeetingAppPathParams;
        } & object) => Promise<BaseResponse<MeetingsAddMeetingAppResponse>>;
        deleteMeetingApp: (_: {
            path: MeetingsDeleteMeetingAppPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listMeetingPolls: (_: {
            path: MeetingsListMeetingPollsPathParams;
        } & object & {
            query?: MeetingsListMeetingPollsQueryParams;
        }) => Promise<BaseResponse<MeetingsListMeetingPollsResponse>>;
        createMeetingPoll: (_: {
            path: MeetingsCreateMeetingPollPathParams;
        } & {
            body?: MeetingsCreateMeetingPollRequestBody;
        } & object) => Promise<BaseResponse<MeetingsCreateMeetingPollResponse>>;
        getMeetingPoll: (_: {
            path: MeetingsGetMeetingPollPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingPollResponse>>;
        updateMeetingPoll: (_: {
            path: MeetingsUpdateMeetingPollPathParams;
        } & {
            body?: MeetingsUpdateMeetingPollRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteMeetingPoll: (_: {
            path: MeetingsDeleteMeetingPollPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listMeetingRegistrants: (_: {
            path: MeetingsListMeetingRegistrantsPathParams;
        } & object & {
            query?: MeetingsListMeetingRegistrantsQueryParams;
        }) => Promise<BaseResponse<MeetingsListMeetingRegistrantsResponse>>;
        addMeetingRegistrant: (_: {
            path: MeetingsAddMeetingRegistrantPathParams;
        } & {
            body: MeetingsAddMeetingRegistrantRequestBody;
        } & {
            query?: MeetingsAddMeetingRegistrantQueryParams;
        }) => Promise<BaseResponse<MeetingsAddMeetingRegistrantResponse>>;
        listRegistrationQuestions: (_: {
            path: MeetingsListRegistrationQuestionsPathParams;
        } & object) => Promise<BaseResponse<MeetingsListRegistrationQuestionsResponse>>;
        updateRegistrationQuestions: (_: {
            path: MeetingsUpdateRegistrationQuestionsPathParams;
        } & {
            body?: MeetingsUpdateRegistrationQuestionsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateRegistrantsStatus: (_: {
            path: MeetingsUpdateRegistrantsStatusPathParams;
        } & {
            body: MeetingsUpdateRegistrantsStatusRequestBody;
        } & {
            query?: MeetingsUpdateRegistrantsStatusQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getMeetingRegistrant: (_: {
            path: MeetingsGetMeetingRegistrantPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingRegistrantResponse>>;
        deleteMeetingRegistrant: (_: {
            path: MeetingsDeleteMeetingRegistrantPathParams;
        } & object & {
            query?: MeetingsDeleteMeetingRegistrantQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getMeetingSIPURIWithPasscode: (_: {
            path: MeetingsGetMeetingSIPURIWithPasscodePathParams;
        } & {
            body?: MeetingsGetMeetingSIPURIWithPasscodeRequestBody;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingSIPURIWithPasscodeResponse>>;
        updateMeetingStatus: (_: {
            path: MeetingsUpdateMeetingStatusPathParams;
        } & {
            body?: MeetingsUpdateMeetingStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getMeetingSurvey: (_: {
            path: MeetingsGetMeetingSurveyPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetMeetingSurveyResponse>>;
        deleteMeetingSurvey: (_: {
            path: MeetingsDeleteMeetingSurveyPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateMeetingSurvey: (_: {
            path: MeetingsUpdateMeetingSurveyPathParams;
        } & {
            body?: MeetingsUpdateMeetingSurveyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getMeetingsToken: (_: {
            path: MeetingsGetMeetingsTokenPathParams;
        } & object & {
            query?: MeetingsGetMeetingsTokenQueryParams;
        }) => Promise<BaseResponse<MeetingsGetMeetingsTokenResponse>>;
        getPastMeetingDetails: (_: {
            path: MeetingsGetPastMeetingDetailsPathParams;
        } & object) => Promise<BaseResponse<MeetingsGetPastMeetingDetailsResponse>>;
        listPastMeetingInstances: (_: {
            path: MeetingsListPastMeetingInstancesPathParams;
        } & object) => Promise<BaseResponse<MeetingsListPastMeetingInstancesResponse>>;
        getPastMeetingParticipants: (_: {
            path: MeetingsGetPastMeetingParticipantsPathParams;
        } & object & {
            query?: MeetingsGetPastMeetingParticipantsQueryParams;
        }) => Promise<BaseResponse<MeetingsGetPastMeetingParticipantsResponse>>;
        listPastMeetingsPollResults: (_: {
            path: MeetingsListPastMeetingsPollResultsPathParams;
        } & object) => Promise<BaseResponse<MeetingsListPastMeetingsPollResultsResponse>>;
        listPastMeetingsQA: (_: {
            path: MeetingsListPastMeetingsQAPathParams;
        } & object) => Promise<BaseResponse<MeetingsListPastMeetingsQAResponse>>;
        listMeetingTemplates: (_: {
            path: MeetingsListMeetingTemplatesPathParams;
        } & object) => Promise<BaseResponse<MeetingsListMeetingTemplatesResponse>>;
        createMeetingTemplateFromExistingMeeting: (_: {
            path: MeetingsCreateMeetingTemplateFromExistingMeetingPathParams;
        } & {
            body?: MeetingsCreateMeetingTemplateFromExistingMeetingRequestBody;
        } & object) => Promise<BaseResponse<MeetingsCreateMeetingTemplateFromExistingMeetingResponse>>;
        listMeetings: (_: {
            path: MeetingsListMeetingsPathParams;
        } & object & {
            query?: MeetingsListMeetingsQueryParams;
        }) => Promise<BaseResponse<MeetingsListMeetingsResponse>>;
        createMeeting: (_: {
            path: MeetingsCreateMeetingPathParams;
        } & {
            body?: MeetingsCreateMeetingRequestBody;
        } & object) => Promise<BaseResponse<MeetingsCreateMeetingResponse>>;
        listUpcomingMeetings: (_: {
            path: MeetingsListUpcomingMeetingsPathParams;
        } & object) => Promise<BaseResponse<MeetingsListUpcomingMeetingsResponse>>;
    };
    readonly pAC: {
        listUsersPACAccounts: (_: {
            path: PACListUsersPACAccountsPathParams;
        } & object) => Promise<BaseResponse<PACListUsersPACAccountsResponse>>;
    };
    readonly reports: {
        getSignInSignOutActivityReport: (_: object & {
            query?: ReportsGetSignInSignOutActivityReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetSignInSignOutActivityReportResponse>>;
        getBillingReports: (_: object) => Promise<BaseResponse<ReportsGetBillingReportsResponse>>;
        getBillingInvoiceReports: (_: object & {
            query: ReportsGetBillingInvoiceReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetBillingInvoiceReportsResponse>>;
        getCloudRecordingUsageReport: (_: object & {
            query: ReportsGetCloudRecordingUsageReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetCloudRecordingUsageReportResponse>>;
        getDailyUsageReport: (_: object & {
            query?: ReportsGetDailyUsageReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetDailyUsageReportResponse>>;
        getMeetingActivitiesReport: (_: object & {
            query: ReportsGetMeetingActivitiesReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetMeetingActivitiesReportResponse>>;
        getMeetingDetailReports: (_: {
            path: ReportsGetMeetingDetailReportsPathParams;
        } & object) => Promise<BaseResponse<ReportsGetMeetingDetailReportsResponse>>;
        getMeetingParticipantReports: (_: {
            path: ReportsGetMeetingParticipantReportsPathParams;
        } & object & {
            query?: ReportsGetMeetingParticipantReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetMeetingParticipantReportsResponse>>;
        getMeetingPollReports: (_: {
            path: ReportsGetMeetingPollReportsPathParams;
        } & object) => Promise<BaseResponse<ReportsGetMeetingPollReportsResponse>>;
        getMeetingQAReport: (_: {
            path: ReportsGetMeetingQAReportPathParams;
        } & object) => Promise<BaseResponse<ReportsGetMeetingQAReportResponse>>;
        getMeetingSurveyReport: (_: {
            path: ReportsGetMeetingSurveyReportPathParams;
        } & object) => Promise<BaseResponse<ReportsGetMeetingSurveyReportResponse>>;
        getOperationLogsReport: (_: object & {
            query: ReportsGetOperationLogsReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetOperationLogsReportResponse>>;
        getTelephoneReports: (_: object & {
            query: ReportsGetTelephoneReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetTelephoneReportsResponse>>;
        getUpcomingEventsReport: (_: object & {
            query: ReportsGetUpcomingEventsReportQueryParams;
        }) => Promise<BaseResponse<ReportsGetUpcomingEventsReportResponse>>;
        getActiveOrInactiveHostReports: (_: object & {
            query: ReportsGetActiveOrInactiveHostReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetActiveOrInactiveHostReportsResponse>>;
        getMeetingReports: (_: {
            path: ReportsGetMeetingReportsPathParams;
        } & object & {
            query: ReportsGetMeetingReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetMeetingReportsResponse>>;
        getWebinarDetailReports: (_: {
            path: ReportsGetWebinarDetailReportsPathParams;
        } & object) => Promise<BaseResponse<ReportsGetWebinarDetailReportsResponse>>;
        getWebinarParticipantReports: (_: {
            path: ReportsGetWebinarParticipantReportsPathParams;
        } & object & {
            query?: ReportsGetWebinarParticipantReportsQueryParams;
        }) => Promise<BaseResponse<ReportsGetWebinarParticipantReportsResponse>>;
        getWebinarPollReports: (_: {
            path: ReportsGetWebinarPollReportsPathParams;
        } & object) => Promise<BaseResponse<ReportsGetWebinarPollReportsResponse>>;
        getWebinarQAReport: (_: {
            path: ReportsGetWebinarQAReportPathParams;
        } & object) => Promise<BaseResponse<ReportsGetWebinarQAReportResponse>>;
        getWebinarSurveyReport: (_: {
            path: ReportsGetWebinarSurveyReportPathParams;
        } & object) => Promise<BaseResponse<ReportsGetWebinarSurveyReportResponse>>;
    };
    readonly sIPPhone: {
        listSIPPhones: (_: object & {
            query?: SIPPhoneListSIPPhonesQueryParams;
        }) => Promise<BaseResponse<SIPPhoneListSIPPhonesResponse>>;
        enableSIPPhone: (_: object & {
            body: SIPPhoneEnableSIPPhoneRequestBody;
        }) => Promise<BaseResponse<SIPPhoneEnableSIPPhoneResponse>>;
        deleteSIPPhone: (_: {
            path: SIPPhoneDeleteSIPPhonePathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateSIPPhone: (_: {
            path: SIPPhoneUpdateSIPPhonePathParams;
        } & {
            body: SIPPhoneUpdateSIPPhoneRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly tSP: {
        getAccountsTSPInformation: (_: object) => Promise<BaseResponse<TSPGetAccountsTSPInformationResponse>>;
        updateAccountsTSPInformation: (_: object & {
            body?: TSPUpdateAccountsTSPInformationRequestBody;
        }) => Promise<BaseResponse<unknown>>;
        listUsersTSPAccounts: (_: {
            path: TSPListUsersTSPAccountsPathParams;
        } & object) => Promise<BaseResponse<TSPListUsersTSPAccountsResponse>>;
        addUsersTSPAccount: (_: {
            path: TSPAddUsersTSPAccountPathParams;
        } & {
            body: TSPAddUsersTSPAccountRequestBody;
        } & object) => Promise<BaseResponse<TSPAddUsersTSPAccountResponse>>;
        setGlobalDialInURLForTSPUser: (_: {
            path: TSPSetGlobalDialInURLForTSPUserPathParams;
        } & {
            body?: TSPSetGlobalDialInURLForTSPUserRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getUsersTSPAccount: (_: {
            path: TSPGetUsersTSPAccountPathParams;
        } & object) => Promise<BaseResponse<TSPGetUsersTSPAccountResponse>>;
        deleteUsersTSPAccount: (_: {
            path: TSPDeleteUsersTSPAccountPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateTSPAccount: (_: {
            path: TSPUpdateTSPAccountPathParams;
        } & {
            body: TSPUpdateTSPAccountRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly trackingField: {
        listTrackingFields: (_: object) => Promise<BaseResponse<TrackingFieldListTrackingFieldsResponse>>;
        createTrackingField: (_: object & {
            body?: TrackingFieldCreateTrackingFieldRequestBody;
        }) => Promise<BaseResponse<TrackingFieldCreateTrackingFieldResponse>>;
        getTrackingField: (_: {
            path: TrackingFieldGetTrackingFieldPathParams;
        } & object) => Promise<BaseResponse<TrackingFieldGetTrackingFieldResponse>>;
        deleteTrackingField: (_: {
            path: TrackingFieldDeleteTrackingFieldPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateTrackingField: (_: {
            path: TrackingFieldUpdateTrackingFieldPathParams;
        } & {
            body?: TrackingFieldUpdateTrackingFieldRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly webinars: {
        deleteLiveWebinarMessage: (_: {
            path: WebinarsDeleteLiveWebinarMessagePathParams;
        } & object & {
            query?: WebinarsDeleteLiveWebinarMessageQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getWebinarAbsentees: (_: {
            path: WebinarsGetWebinarAbsenteesPathParams;
        } & object & {
            query?: WebinarsGetWebinarAbsenteesQueryParams;
        }) => Promise<BaseResponse<WebinarsGetWebinarAbsenteesResponse>>;
        listPastWebinarInstances: (_: {
            path: WebinarsListPastWebinarInstancesPathParams;
        } & object) => Promise<BaseResponse<WebinarsListPastWebinarInstancesResponse>>;
        listWebinarParticipants: (_: {
            path: WebinarsListWebinarParticipantsPathParams;
        } & object & {
            query?: WebinarsListWebinarParticipantsQueryParams;
        }) => Promise<BaseResponse<WebinarsListWebinarParticipantsResponse>>;
        listPastWebinarPollResults: (_: {
            path: WebinarsListPastWebinarPollResultsPathParams;
        } & object) => Promise<BaseResponse<WebinarsListPastWebinarPollResultsResponse>>;
        listQAsOfPastWebinar: (_: {
            path: WebinarsListQAsOfPastWebinarPathParams;
        } & object) => Promise<BaseResponse<WebinarsListQAsOfPastWebinarResponse>>;
        listWebinarTemplates: (_: {
            path: WebinarsListWebinarTemplatesPathParams;
        } & object) => Promise<BaseResponse<WebinarsListWebinarTemplatesResponse>>;
        createWebinarTemplate: (_: {
            path: WebinarsCreateWebinarTemplatePathParams;
        } & {
            body?: WebinarsCreateWebinarTemplateRequestBody;
        } & object) => Promise<BaseResponse<WebinarsCreateWebinarTemplateResponse>>;
        listWebinars: (_: {
            path: WebinarsListWebinarsPathParams;
        } & object & {
            query?: WebinarsListWebinarsQueryParams;
        }) => Promise<BaseResponse<WebinarsListWebinarsResponse>>;
        createWebinar: (_: {
            path: WebinarsCreateWebinarPathParams;
        } & {
            body?: WebinarsCreateWebinarRequestBody;
        } & object) => Promise<BaseResponse<WebinarsCreateWebinarResponse>>;
        getWebinar: (_: {
            path: WebinarsGetWebinarPathParams;
        } & object & {
            query?: WebinarsGetWebinarQueryParams;
        }) => Promise<BaseResponse<WebinarsGetWebinarResponse>>;
        deleteWebinar: (_: {
            path: WebinarsDeleteWebinarPathParams;
        } & object & {
            query?: WebinarsDeleteWebinarQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateWebinar: (_: {
            path: WebinarsUpdateWebinarPathParams;
        } & {
            body?: WebinarsUpdateWebinarRequestBody;
        } & {
            query?: WebinarsUpdateWebinarQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        performBatchRegistration: (_: {
            path: WebinarsPerformBatchRegistrationPathParams;
        } & {
            body?: WebinarsPerformBatchRegistrationRequestBody;
        } & object) => Promise<BaseResponse<WebinarsPerformBatchRegistrationResponse>>;
        getWebinarsSessionBranding: (_: {
            path: WebinarsGetWebinarsSessionBrandingPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarsSessionBrandingResponse>>;
        createWebinarsBrandingNameTag: (_: {
            path: WebinarsCreateWebinarsBrandingNameTagPathParams;
        } & {
            body: WebinarsCreateWebinarsBrandingNameTagRequestBody;
        } & object) => Promise<BaseResponse<WebinarsCreateWebinarsBrandingNameTagResponse>>;
        deleteWebinarsBrandingNameTag: (_: {
            path: WebinarsDeleteWebinarsBrandingNameTagPathParams;
        } & object & {
            query?: WebinarsDeleteWebinarsBrandingNameTagQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        updateWebinarsBrandingNameTag: (_: {
            path: WebinarsUpdateWebinarsBrandingNameTagPathParams;
        } & {
            body?: WebinarsUpdateWebinarsBrandingNameTagRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        uploadWebinarsBrandingVirtualBackground: (_: {
            path: WebinarsUploadWebinarsBrandingVirtualBackgroundPathParams;
        } & {
            body: WebinarsUploadWebinarsBrandingVirtualBackgroundRequestBody;
        } & object) => Promise<BaseResponse<WebinarsUploadWebinarsBrandingVirtualBackgroundResponse>>;
        deleteWebinarsBrandingVirtualBackgrounds: (_: {
            path: WebinarsDeleteWebinarsBrandingVirtualBackgroundsPathParams;
        } & object & {
            query?: WebinarsDeleteWebinarsBrandingVirtualBackgroundsQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        setWebinarsDefaultBrandingVirtualBackground: (_: {
            path: WebinarsSetWebinarsDefaultBrandingVirtualBackgroundPathParams;
        } & object & {
            query?: WebinarsSetWebinarsDefaultBrandingVirtualBackgroundQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        uploadWebinarsBrandingWallpaper: (_: {
            path: WebinarsUploadWebinarsBrandingWallpaperPathParams;
        } & {
            body: WebinarsUploadWebinarsBrandingWallpaperRequestBody;
        } & object) => Promise<BaseResponse<WebinarsUploadWebinarsBrandingWallpaperResponse>>;
        deleteWebinarsBrandingWallpaper: (_: {
            path: WebinarsDeleteWebinarsBrandingWallpaperPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        createWebinarsInviteLinks: (_: {
            path: WebinarsCreateWebinarsInviteLinksPathParams;
        } & {
            body?: WebinarsCreateWebinarsInviteLinksRequestBody;
        } & object) => Promise<BaseResponse<WebinarsCreateWebinarsInviteLinksResponse>>;
        getWebinarsJoinTokenForLiveStreaming: (_: {
            path: WebinarsGetWebinarsJoinTokenForLiveStreamingPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarsJoinTokenForLiveStreamingResponse>>;
        getWebinarsArchiveTokenForLocalArchiving: (_: {
            path: WebinarsGetWebinarsArchiveTokenForLocalArchivingPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarsArchiveTokenForLocalArchivingResponse>>;
        getWebinarsJoinTokenForLocalRecording: (_: {
            path: WebinarsGetWebinarsJoinTokenForLocalRecordingPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarsJoinTokenForLocalRecordingResponse>>;
        getLiveStreamDetails: (_: {
            path: WebinarsGetLiveStreamDetailsPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetLiveStreamDetailsResponse>>;
        updateLiveStream: (_: {
            path: WebinarsUpdateLiveStreamPathParams;
        } & {
            body: WebinarsUpdateLiveStreamRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateLiveStreamStatus: (_: {
            path: WebinarsUpdateLiveStreamStatusPathParams;
        } & {
            body?: WebinarsUpdateLiveStreamStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        listPanelists: (_: {
            path: WebinarsListPanelistsPathParams;
        } & object) => Promise<BaseResponse<WebinarsListPanelistsResponse>>;
        addPanelists: (_: {
            path: WebinarsAddPanelistsPathParams;
        } & {
            body?: WebinarsAddPanelistsRequestBody;
        } & object) => Promise<BaseResponse<WebinarsAddPanelistsResponse>>;
        removeAllPanelists: (_: {
            path: WebinarsRemoveAllPanelistsPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        removePanelist: (_: {
            path: WebinarsRemovePanelistPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listWebinarsPolls: (_: {
            path: WebinarsListWebinarsPollsPathParams;
        } & object & {
            query?: WebinarsListWebinarsPollsQueryParams;
        }) => Promise<BaseResponse<WebinarsListWebinarsPollsResponse>>;
        createWebinarsPoll: (_: {
            path: WebinarsCreateWebinarsPollPathParams;
        } & {
            body?: WebinarsCreateWebinarsPollRequestBody;
        } & object) => Promise<BaseResponse<WebinarsCreateWebinarsPollResponse>>;
        getWebinarPoll: (_: {
            path: WebinarsGetWebinarPollPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarPollResponse>>;
        updateWebinarPoll: (_: {
            path: WebinarsUpdateWebinarPollPathParams;
        } & {
            body?: WebinarsUpdateWebinarPollRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        deleteWebinarPoll: (_: {
            path: WebinarsDeleteWebinarPollPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        listWebinarRegistrants: (_: {
            path: WebinarsListWebinarRegistrantsPathParams;
        } & object & {
            query?: WebinarsListWebinarRegistrantsQueryParams;
        }) => Promise<BaseResponse<WebinarsListWebinarRegistrantsResponse>>;
        addWebinarRegistrant: (_: {
            path: WebinarsAddWebinarRegistrantPathParams;
        } & {
            body: WebinarsAddWebinarRegistrantRequestBody;
        } & {
            query?: WebinarsAddWebinarRegistrantQueryParams;
        }) => Promise<BaseResponse<WebinarsAddWebinarRegistrantResponse>>;
        listRegistrationQuestions: (_: {
            path: WebinarsListRegistrationQuestionsPathParams;
        } & object) => Promise<BaseResponse<WebinarsListRegistrationQuestionsResponse>>;
        updateRegistrationQuestions: (_: {
            path: WebinarsUpdateRegistrationQuestionsPathParams;
        } & {
            body?: WebinarsUpdateRegistrationQuestionsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        updateRegistrantsStatus: (_: {
            path: WebinarsUpdateRegistrantsStatusPathParams;
        } & {
            body: WebinarsUpdateRegistrantsStatusRequestBody;
        } & {
            query?: WebinarsUpdateRegistrantsStatusQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getWebinarRegistrant: (_: {
            path: WebinarsGetWebinarRegistrantPathParams;
        } & object & {
            query?: WebinarsGetWebinarRegistrantQueryParams;
        }) => Promise<BaseResponse<WebinarsGetWebinarRegistrantResponse>>;
        deleteWebinarRegistrant: (_: {
            path: WebinarsDeleteWebinarRegistrantPathParams;
        } & object & {
            query?: WebinarsDeleteWebinarRegistrantQueryParams;
        }) => Promise<BaseResponse<unknown>>;
        getWebinarSIPURIWithPasscode: (_: {
            path: WebinarsGetWebinarSIPURIWithPasscodePathParams;
        } & {
            body?: WebinarsGetWebinarSIPURIWithPasscodeRequestBody;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarSIPURIWithPasscodeResponse>>;
        updateWebinarStatus: (_: {
            path: WebinarsUpdateWebinarStatusPathParams;
        } & {
            body?: WebinarsUpdateWebinarStatusRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getWebinarSurvey: (_: {
            path: WebinarsGetWebinarSurveyPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarSurveyResponse>>;
        deleteWebinarSurvey: (_: {
            path: WebinarsDeleteWebinarSurveyPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        updateWebinarSurvey: (_: {
            path: WebinarsUpdateWebinarSurveyPathParams;
        } & {
            body?: WebinarsUpdateWebinarSurveyRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
        getWebinarsToken: (_: {
            path: WebinarsGetWebinarsTokenPathParams;
        } & object & {
            query?: WebinarsGetWebinarsTokenQueryParams;
        }) => Promise<BaseResponse<WebinarsGetWebinarsTokenResponse>>;
        getWebinarTrackingSources: (_: {
            path: WebinarsGetWebinarTrackingSourcesPathParams;
        } & object) => Promise<BaseResponse<WebinarsGetWebinarTrackingSourcesResponse>>;
    };
}

type WebinarSharingStartedEvent = Event<"webinar.sharing_started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                sharing_details: {
                    content: string;
                    link_source: string;
                    file_link: string;
                    date_time: string;
                    source: string;
                };
            };
        };
    };
};
type MeetingParticipantJbhWaitingEvent = Event<"meeting.participant_jbh_waiting"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time?: string;
            timezone?: string;
            duration: number;
            participant: {
                id?: string;
                user_name: string;
                customer_key?: string;
            };
        };
    };
};
type MeetingRegistrationCreatedEvent = Event<"meeting.registration_created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
                address?: string;
                city?: string;
                country?: string;
                zip?: string;
                state?: string;
                phone?: string;
                industry?: string;
                org?: string;
                job_title?: string;
                purchasing_time_frame?: string;
                role_in_purchase_process?: string;
                no_of_employees?: string;
                comments?: string;
                custom_questions?: ExactlyOneOf<[
                    {
                        title: string;
                        value: string;
                    }
                ]>[];
                status: string;
                join_url: string;
                participant_pin_code?: number;
            };
        };
    };
};
type MeetingSummaryRecoveredEvent = Event<"meeting.summary_recovered"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            meeting_host_id: string;
            meeting_host_email: string;
            meeting_uuid: string;
            meeting_id: number;
            meeting_topic: string;
            meeting_start_time: string;
            meeting_end_time: string;
            summary_start_time: string;
            summary_end_time: string;
            summary_created_time: string;
            summary_last_modified_time: string;
            summary_title: string;
        };
    };
};
type RecordingRecoveredEvent = Event<"recording.recovered"> & {
    event: string;
    event_ts: number;
    download_token?: string;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            account_id: string;
            timezone?: string;
            duration: number;
            share_url: string;
            total_size: number;
            recording_count: number;
            recording_files: {
                id: string;
                meeting_id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_size: number;
                file_extension: string;
                file_name?: string;
                play_url?: string;
                download_url: string;
                status: string;
                recording_type: string;
            }[];
            participant_audio_files?: {
                id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_name: string;
                file_size: number;
                file_extension: string;
                play_url?: string;
                download_url: string;
                file_path?: string;
                status: string;
            }[];
        };
    };
};
type MeetingSharingEndedEvent = Event<"meeting.sharing_ended"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                sharing_details: {
                    content: string;
                    link_source: string;
                    file_link: string;
                    date_time: string;
                    source: string;
                };
            };
        };
    };
};
type RecordingCloudStorageUsageUpdatedEvent = Event<"recording.cloud_storage_usage_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            free_storage: string;
            plan_storage: string;
            plan_type: string;
            storage_used: string;
            storage_used_percentage: number;
            storage_exceed: string;
            max_exceed_date?: string;
        };
    };
};
type MeetingParticipantLeftBreakoutRoomEvent = Event<"meeting.participant_left_breakout_room"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            breakout_room_uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                parent_user_id?: string;
                user_name: string;
                id?: string;
                participant_uuid?: string;
                leave_time: string;
                leave_reason?: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                phone_number?: string;
                customer_key?: string;
            };
        };
    };
};
type MeetingDeviceTestedEvent = Event<"meeting.device_tested"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            test_result: {
                user_id: string;
                user_name: string;
                camera_status: number;
                speaker_status: number;
                microphone_status: number;
                os?: string;
            };
        };
    };
};
type MeetingSummarySharedEvent = Event<"meeting.summary_shared"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            meeting_host_id: string;
            meeting_host_email: string;
            meeting_uuid: string;
            meeting_id: number;
            meeting_topic: string;
            meeting_start_time: string;
            meeting_end_time: string;
            summary_start_time: string;
            summary_end_time: string;
            summary_created_time: string;
            summary_last_modified_time: string;
            summary_title: string;
            share_with_users: {
                user_email: string;
            }[];
        };
    };
};
type RecordingTranscriptCompletedEvent = Event<"recording.transcript_completed"> & {
    event: string;
    event_ts: number;
    download_token?: string;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            account_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            host_email: string;
            duration: number;
            password?: string;
            share_url: string;
            total_size: number;
            recording_count: number;
            recording_files: {
                id: string;
                meeting_id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_size: number;
                file_extension: string;
                file_name?: string;
                play_url?: string;
                download_url: string;
                file_path?: string;
                status: string;
                recording_type: string;
            }[];
        };
    };
};
type RecordingStoppedEvent = Event<"recording.stopped"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            recording_file: {
                recording_start: string;
                recording_end: string;
            };
        };
    };
};
type RecordingBatchTrashedEvent = Event<"recording.batch_trashed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operation: string;
        object?: {
            meeting_uuids: string[];
        };
    };
};
type WebinarStartedEvent = Event<"webinar.started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone: string;
            duration: number;
        };
    };
};
type WebinarSharingEndedEvent = Event<"webinar.sharing_ended"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                sharing_details: {
                    content: string;
                    link_source: string;
                    file_link: string;
                    date_time: string;
                    source: string;
                };
            };
        };
    };
};
type MeetingSummaryTrashedEvent = Event<"meeting.summary_trashed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            meeting_host_id: string;
            meeting_host_email: string;
            meeting_uuid: string;
            meeting_id: number;
            meeting_topic: string;
            meeting_start_time: string;
            meeting_end_time: string;
            summary_start_time: string;
            summary_end_time: string;
            summary_created_time: string;
            summary_last_modified_time: string;
            summary_title: string;
        };
    };
};
type WebinarDeletedEvent = Event<"webinar.deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id?: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic?: string;
            type: number;
            start_time?: string;
            duration?: number;
            timezone?: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
        };
    };
};
type RecordingRegistrationApprovedEvent = Event<"recording.registration_approved"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            registrant: {
                id?: string;
                email: string;
                first_name: string;
                last_name: string;
            };
        };
    };
};
type MeetingSharingStartedEvent = Event<"meeting.sharing_started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                sharing_details: {
                    content: string;
                    link_source: string;
                    file_link: string;
                    date_time: string;
                    source: string;
                };
            };
        };
    };
};
type WebinarRegistrationCreatedEvent = Event<"webinar.registration_created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
                address?: string;
                city?: string;
                country?: string;
                zip?: string;
                state?: string;
                phone?: string;
                industry?: string;
                org?: string;
                job_title?: string;
                purchasing_time_frame?: string;
                role_in_purchase_process?: string;
                no_of_employees?: string;
                comments?: string;
                custom_questions?: ExactlyOneOf<[
                    {
                        title: string;
                        value: string;
                    }
                ]>[];
                status: string;
                join_url: string;
                tracking_source?: {
                    id: string;
                    source_name: string;
                    tracking_url: string;
                };
            };
        };
    };
};
type MeetingChatMessageSentEvent = Event<"meeting.chat_message_sent"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            chat_message: {
                date_time: string;
                sender_session_id: string;
                sender_name: string;
                sender_email?: string;
                sender_type: string;
                recipient_session_id?: string;
                recipient_name?: string;
                recipient_email?: string;
                recipient_type: string;
                message_id: string;
                message_content: string;
                file_ids?: string[];
            };
        };
    };
};
type MeetingParticipantRoleChangedEvent = Event<"meeting.participant_role_changed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: string;
            uuid: string;
            host_id: string;
            topic?: string;
            type: number;
            start_time?: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                participant_uuid?: string;
                date_time: string;
                old_role: string;
                new_role: string;
            };
        };
    };
};
type MeetingRiskAlertEvent = Event<"meeting.risk_alert"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            host_email: string;
            topic?: string;
            type: number;
            start_time?: string;
            timezone?: string;
            armn_details: {
                post_platform?: string;
                social_link?: string;
                post_time?: string;
                post_user?: string;
                meeting_url?: string;
                recommended_enable_settings?: string[];
                recommended_disable_settings?: string[];
            };
        };
    };
};
type MeetingPermanentlyDeletedEvent = Event<"meeting.permanently_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
        };
    };
};
type WebinarParticipantFeedbackEvent = Event<"webinar.participant_feedback"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            participant: {
                participant_uuid: string;
                participant_user_id: string;
                user_name: string;
                feedback: {
                    satisfied: boolean;
                    feedback_details?: {
                        id: string;
                        name: string;
                    }[];
                    comments?: string;
                };
            };
        };
    };
};
type RecordingRegistrationCreatedEvent = Event<"recording.registration_created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            registrant: {
                id?: string;
                email: string;
                status: string;
                first_name: string;
                last_name: string;
                address: string;
                city: string;
                country: string;
                zip: string;
                state: string;
                phone: string;
                industry: string;
                org: string;
                job_title: string;
                purchasing_time_frame: string;
                role_in_purchase_process: string;
                no_of_employees: string;
                comments: string;
                custom_questions?: {
                    title?: string;
                    value?: string;
                }[];
            };
        };
    };
};
type MeetingParticipantJoinedWaitingRoomEvent = Event<"meeting.participant_joined_waiting_room"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                participant_uuid?: string;
                date_time: string;
                email: string;
                phone_number?: string;
                participant_user_id?: string;
                customer_key?: string;
                registrant_id?: string;
            };
        };
    };
};
type MeetingParticipantPhoneCalloutRingingEvent = Event<"meeting.participant_phone_callout_ringing"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
            };
        };
    };
};
type MeetingCreatedEvent = Event<"meeting.created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time?: string;
            duration: number;
            timezone?: string;
            join_url: string;
            password?: string;
            pmi?: string;
            occurrences?: {
                occurrence_id: string;
                start_time: string;
                duration?: number;
                status?: string;
            }[];
            settings: {
                use_pmi: boolean;
                alternative_hosts: string;
                meeting_invitees?: {
                    email?: string;
                }[];
                join_before_host?: boolean;
                jbh_time?: number;
            };
            recurrence?: {
                type?: number;
                repeat_interval?: number;
                weekly_days?: string;
                monthly_day?: number;
                monthly_week_day?: number;
                end_times?: number;
                end_date_time?: string;
                monthly_week?: number;
            };
            tracking_fields?: {
                field?: string;
                value?: string;
                visible?: boolean;
            }[];
        };
    };
};
type MeetingLiveStreamingStartedEvent = Event<"meeting.live_streaming_started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            live_streaming: {
                service: string;
                custom_live_streaming_settings?: {
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
type MeetingParticipantRoomSystemCalloutAcceptedEvent = Event<"meeting.participant_room_system_callout_accepted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
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
type WebinarRegistrationApprovedEvent = Event<"webinar.registration_approved"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
                join_url: string;
                tracking_source?: {
                    id: string;
                    source_name: string;
                    tracking_url: string;
                };
            };
        };
    };
};
type MeetingParticipantJbhJoinedEvent = Event<"meeting.participant_jbh_joined"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time?: string;
            timezone?: string;
            duration: number;
            participant: {
                id?: string;
                user_name?: string;
                customer_key?: string;
                registrant_id?: string;
            };
        };
    };
};
type RecordingArchiveFilesCompletedEvent = Event<"recording.archive_files_completed"> & {
    event: string;
    event_ts: number;
    download_token: string;
    payload: {
        account_id?: string;
        object?: {
            uuid?: string;
            id?: number;
            host_id?: string;
            topic?: string;
            type?: number;
            start_time?: string;
            timezone?: string;
            duration?: number;
            duration_in_second?: number;
            total_size?: number;
            recording_count?: number;
            meeting_type?: string;
            account_name?: string;
            complete_time?: string;
            is_breakout_room?: boolean;
            parent_meeting_id?: string;
            archive_files?: {
                id?: string;
                file_type?: string;
                file_extension?: string;
                file_name?: string;
                file_size?: number;
                download_url?: string;
                status?: string;
                recording_type?: string;
                individual?: boolean;
                participant_email?: string;
                participant_join_time?: string;
                participant_leave_time?: string;
                encryption_fingerprint?: string;
                number_of_messages?: number;
                storage_location?: string;
            }[];
            status?: string;
            group_id?: string;
        };
    };
};
type MeetingBreakoutRoomSharingStartedEvent = Event<"meeting.breakout_room_sharing_started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            breakout_room_uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                parent_user_id?: string;
                user_name?: string;
                id?: string;
                sharing_details: {
                    content: string;
                    link_source: string;
                    file_link: string;
                    date_time: string;
                    source: string;
                };
            };
        };
    };
};
type MeetingAlertEvent = Event<"meeting.alert"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            issues: string[];
        };
    };
};
type MeetingChatMessageFileSentEvent = Event<"meeting.chat_message_file_sent"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            meeting_id: number;
            meeting_uuid: string;
            chat_message_file: {
                date_time: string;
                sender_session_id: string;
                sender_name: string;
                sender_email?: string;
                sender_type: string;
                recipient_session_id?: string;
                recipient_name?: string;
                recipient_email?: string;
                recipient_type: string;
                message_id: string;
                file_id: string;
                file_name: string;
                file_size: number;
                file_type: string;
                download_url: string;
            };
        };
    };
};
type MeetingParticipantBindEvent = Event<"meeting.participant_bind"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: string;
            uuid: string;
            host_id: string;
            topic?: string;
            type: number;
            start_time?: string;
            timezone?: string;
            duration?: number;
            participant: {
                user_id: string;
                bind_user_id: string;
                user_name?: string;
                id?: string;
                participant_uuid?: string;
                bind_participant_uuid?: string;
                join_time: string;
                registrant_id?: string;
                phone_number: string;
            };
        };
    };
};
type MeetingDeletedEvent = Event<"meeting.deleted"> & {
    event: string;
    event_ts?: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id?: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic?: string;
            type: number;
            start_time?: string;
            duration?: number;
            timezone?: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
        };
    };
};
type MeetingParticipantFeedbackEvent = Event<"meeting.participant_feedback"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            participant: {
                participant_uuid: string;
                participant_user_id: string;
                user_name: string;
                feedback: {
                    satisfied: boolean;
                    feedback_details?: {
                        id: string;
                        name: string;
                    }[];
                    comments?: string;
                };
            };
        };
    };
};
type MeetingParticipantJoinedEvent = Event<"meeting.participant_joined"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: string;
            uuid: string;
            host_id: string;
            topic?: string;
            type: number;
            start_time?: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name: string;
                id?: string;
                participant_uuid?: string;
                join_time: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                customer_key?: string;
                phone_number?: string;
            };
        };
    };
};
type UserTspDeletedEvent = Event<"user.tsp_deleted"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operator_id?: string;
        object?: {
            id?: string;
            email?: string;
            tsp_credentials?: {
                conference_code?: string;
                leader_pin?: string;
                tsp_bridge?: string;
                dial_in_numbers?: {
                    code?: string;
                    number?: string;
                    type?: string;
                    country_label?: string;
                }[];
            };
        };
    };
};
type RecordingDeletedEvent = Event<"recording.deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            account_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            share_url: string;
            total_size: number;
            recording_count: number;
            recording_files: {
                id: string;
                meeting_id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_size: number;
                file_extension: string;
                file_name?: string;
                play_url?: string;
                download_url: string;
                status: string;
                recording_type: string;
            }[];
            participant_audio_files?: {
                id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_name: string;
                file_size: number;
                file_extension: string;
                play_url?: string;
                download_url: string;
                file_path?: string;
                status: string;
            }[];
        };
    };
};
type RecordingPausedEvent = Event<"recording.paused"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            recording_file: {
                recording_start: string;
                recording_end: string;
            };
        };
    };
};
type MeetingParticipantRoomSystemCalloutRingingEvent = Event<"meeting.participant_room_system_callout_ringing"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
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
type RecordingStartedEvent = Event<"recording.started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            recording_file: {
                recording_start: string;
                recording_end: string;
            };
        };
    };
};
type UserTspUpdatedEvent = Event<"user.tsp_updated"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operator_id?: string;
        object?: {
            id?: string;
            email?: string;
            tsp_credentials?: {
                conference_code?: string;
                leader_pin?: string;
                tsp_bridge?: string;
                dial_in_numbers?: {
                    code?: string;
                    number?: string;
                    type?: string;
                    country_label?: string;
                }[];
            };
        };
    };
};
type WebinarEndedEvent = Event<"webinar.ended"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone: string;
            end_time?: string;
            duration: number;
        };
    };
};
type WebinarRecoveredEvent = Event<"webinar.recovered"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
        };
    };
};
type MeetingParticipantAdmittedEvent = Event<"meeting.participant_admitted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                participant_uuid?: string;
                date_time: string;
                email: string;
                customer_key?: string;
                registrant_id?: string;
            };
        };
    };
};
type MeetingParticipantRoomSystemCalloutFailedEvent = Event<"meeting.participant_room_system_callout_failed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            message_id: string;
            inviter_name: string;
            reason_type: number;
            participant: {
                call_type: string;
                device_ip: string;
            };
        };
    };
};
type RecordingResumedEvent = Event<"recording.resumed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            recording_file: {
                recording_start: string;
                recording_end: string;
            };
        };
    };
};
type WebinarParticipantRoleChangedEvent = Event<"webinar.participant_role_changed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone: string;
            duration: number;
            participant: {
                user_id: string;
                user_name: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                participant_uuid?: string;
                date_time: string;
                old_role: string;
                new_role: string;
            };
        };
    };
};
type MeetingParticipantPhoneCalloutMissedEvent = Event<"meeting.participant_phone_callout_missed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
            };
        };
    };
};
type MeetingSummaryUpdatedEvent = Event<"meeting.summary_updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            meeting_host_id: string;
            meeting_host_email: string;
            meeting_uuid: string;
            meeting_id: number;
            meeting_topic: string;
            meeting_start_time: string;
            meeting_end_time: string;
            summary_start_time: string;
            summary_end_time: string;
            summary_created_time: string;
            summary_last_modified_time: string;
            summary_title: string;
            summary_overview?: string;
            summary_details: {
                label: string;
                summary: string;
            }[];
            next_steps: string[];
            edited_summary: {
                summary_details?: string;
                next_steps?: string[];
            };
        };
    };
};
type WebinarParticipantJoinedEvent = Event<"webinar.participant_joined"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone: string;
            duration: number;
            participant: {
                user_id: string;
                user_name: string;
                id: string;
                join_time: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                participant_uuid?: string;
                customer_key?: string;
                phone_number?: string;
            };
        };
    };
};
type RecordingRenamedEvent = Event<"recording.renamed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        time_stamp: number;
        object: {
            uuid: string;
            id: number;
            topic: string;
            type: number;
            host_id: string;
        };
        old_object: {
            uuid: string;
            id: number;
            topic: string;
            type: number;
            host_id: string;
        };
    };
};
type MeetingParticipantJbhWaitingLeftEvent = Event<"meeting.participant_jbh_waiting_left"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                id?: string;
                user_name: string;
                customer_key?: string;
                registrant_id?: string;
            };
        };
    };
};
type UserTspCreatedEvent = Event<"user.tsp_created"> & {
    event?: string;
    event_ts?: number;
    payload?: {
        account_id?: string;
        operator?: string;
        operator_id?: string;
        object?: {
            id?: string;
            email?: string;
            tsp_credentials?: {
                conference_code?: string;
                leader_pin?: string;
                tsp_bridge?: string;
                dial_in_numbers?: {
                    code?: string;
                    number?: string;
                    type?: string;
                    country_label?: string;
                }[];
            };
        };
    };
};
type MeetingBreakoutRoomSharingEndedEvent = Event<"meeting.breakout_room_sharing_ended"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            breakout_room_uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                parent_user_id?: string;
                user_name?: string;
                id?: string;
                sharing_details: {
                    content: string;
                    link_source: string;
                    file_link: string;
                    date_time: string;
                    source: string;
                };
            };
        };
    };
};
type MeetingUpdatedEvent = Event<"meeting.updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        scope?: string;
        object: {
            id: number;
            uuid?: string;
            host_id?: string;
            topic?: string;
            type?: number;
            start_time?: string;
            duration?: number;
            timezone?: string;
            join_url?: string;
            password?: string;
            agenda?: string;
            registration_url?: string;
            occurrences?: {
                occurrence_id: string;
                start_time: string;
                duration?: number;
                status?: string;
            }[];
            settings?: {
                host_video?: boolean;
                participant_video?: boolean;
                join_before_host?: boolean;
                jbh_time?: number;
                mute_upon_entry?: boolean;
                audio?: string;
                auto_recording?: string;
                use_pmi?: boolean;
                waiting_room?: boolean;
                watermark?: boolean;
                enforce_login?: boolean;
                enforce_login_domains?: string;
                approval_type?: number;
                registration_type?: number;
                alternative_hosts?: string;
                meeting_authentication?: boolean;
                authentication_option?: string;
                authentication_name?: string;
                authentication_domains?: string;
                meeting_invitees?: {
                    email?: string;
                }[];
                language_interpretation?: {
                    enable: boolean;
                    interpreters?: {
                        email?: string;
                        languages?: string;
                    }[];
                };
                sign_language_interpretation?: {
                    enable: boolean;
                    interpreters?: {
                        email?: string;
                        sign_language?: string;
                    }[];
                };
                continuous_meeting_chat?: {
                    enable?: boolean;
                    auto_add_invited_external_users?: boolean;
                    auto_add_meeting_participants?: boolean;
                };
                auto_start_meeting_summary?: boolean;
                auto_start_ai_companion_questions?: boolean;
            };
            recurrence?: {
                type?: number;
                repeat_interval?: number;
                weekly_days?: string;
                monthly_day?: number;
                monthly_week_day?: number;
                end_times?: number;
                end_date_time?: string;
                monthly_week?: number;
            };
            tracking_fields?: {
                field?: string;
                value?: string;
            }[];
        };
        time_stamp: number;
        old_object: {
            id: number;
            uuid?: string;
            host_id?: string;
            topic?: string;
            type?: number;
            start_time?: string;
            duration?: number;
            timezone?: string;
            join_url?: string;
            password?: string;
            agenda?: string;
            registration_url?: string;
            occurrences?: {
                occurrence_id: string;
                start_time: string;
                duration?: number;
                status?: string;
            }[];
            settings?: {
                host_video?: boolean;
                participant_video?: boolean;
                join_before_host?: boolean;
                jbh_time?: number;
                mute_upon_entry?: boolean;
                audio?: string;
                auto_recording?: string;
                use_pmi?: boolean;
                waiting_room?: boolean;
                watermark?: boolean;
                enforce_login?: boolean;
                enforce_login_domains?: string;
                approval_type?: number;
                registration_type?: number;
                alternative_hosts?: string;
                meeting_authentication?: boolean;
                authentication_option?: string;
                authentication_name?: string;
                authentication_domains?: string;
                meeting_invitees?: {
                    email?: string;
                }[];
                language_interpretation?: {
                    enable: boolean;
                    interpreters?: {
                        email?: string;
                        languages?: string;
                    }[];
                };
                sign_language_interpretation?: {
                    enable: boolean;
                    interpreters?: {
                        email?: string;
                        sign_language?: string;
                    }[];
                };
                continuous_meeting_chat?: {
                    enable?: boolean;
                    auto_add_invited_external_users?: boolean;
                    auto_add_meeting_participants?: boolean;
                };
                auto_start_meeting_summary?: boolean;
                auto_start_ai_companion_questions?: boolean;
            };
            recurrence?: {
                type?: number;
                repeat_interval?: number;
                weekly_days?: string;
                monthly_day?: number;
                monthly_week_day?: number;
                end_times?: number;
                end_date_time?: string;
                monthly_week?: number;
            };
            tracking_fields?: {
                field?: string;
                value?: string;
            }[];
        };
    };
};
type MeetingParticipantRoomSystemCalloutMissedEvent = Event<"meeting.participant_room_system_callout_missed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
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
type MeetingRegistrationDeniedEvent = Event<"meeting.registration_denied"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
            };
        };
    };
};
type WebinarCreatedEvent = Event<"webinar.created"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time?: string;
            duration: number;
            timezone: string;
            join_url: string;
            password?: string;
            creation_source: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                    duration?: number;
                    status?: string;
                }
            ]>[];
            settings: {
                use_pmi: boolean;
                alternative_hosts: string;
            };
            recurrence?: {
                type?: number;
                repeat_interval?: number;
                weekly_days?: string;
                monthly_day?: number;
                monthly_week_day?: number;
                end_times?: number;
                end_date_time?: string;
                monthly_week?: number;
            };
        };
    };
};
type WebinarRegistrationDeniedEvent = Event<"webinar.registration_denied"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
                tracking_source?: {
                    id: string;
                    source_name: string;
                    tracking_url: string;
                };
            };
        };
    };
};
type MeetingRegistrationApprovedEvent = Event<"meeting.registration_approved"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
                join_url: string;
                participant_pin_code?: number;
            };
        };
    };
};
type WebinarParticipantLeftEvent = Event<"webinar.participant_left"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                leave_time?: string;
                leave_reason?: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                participant_uuid?: string;
                customer_key?: string;
                phone_number?: string;
            };
        };
    };
};
type RecordingBatchDeletedEvent = Event<"recording.batch_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object?: {
            meetings: {
                meeting_uuid?: string;
                recording_file_ids?: any[];
            }[];
        };
    };
};
type WebinarAlertEvent = Event<"webinar.alert"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone: string;
            duration: number;
            issues: string[];
        };
    };
};
type RecordingRegistrationDeniedEvent = Event<"recording.registration_denied"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            registrant: {
                id?: string;
                email: string;
                first_name: string;
                last_name: string;
            };
        };
    };
};
type WebinarChatMessageSentEvent = Event<"webinar.chat_message_sent"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            chat_message: {
                date_time: string;
                sender_session_id: string;
                sender_name: string;
                sender_email?: string;
                sender_type: string;
                recipient_session_id?: string;
                recipient_name?: string;
                recipient_email?: string;
                recipient_type: string;
                message_id: string;
                message_content: string;
                file_ids?: string[];
            };
        };
    };
};
type MeetingLiveStreamingStoppedEvent = Event<"meeting.live_streaming_stopped"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            live_streaming: {
                service: string;
                custom_live_streaming_settings?: {
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
type WebinarChatMessageFileSentEvent = Event<"webinar.chat_message_file_sent"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            webinar_id: number;
            webinar_uuid: string;
            chat_message_file: {
                date_time: string;
                sender_session_id: string;
                sender_name: string;
                sender_email?: string;
                sender_type: string;
                recipient_session_id?: string;
                recipient_name?: string;
                recipient_email?: string;
                recipient_type: string;
                message_id: string;
                file_id: string;
                file_name: string;
                file_size: number;
                file_type: string;
                download_url: string;
            };
        };
    };
};
type MeetingEndedEvent = Event<"meeting.ended"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            end_time: string;
        };
    };
};
type WebinarRegistrationCancelledEvent = Event<"webinar.registration_cancelled"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
                tracking_source?: {
                    id: string;
                    source_name: string;
                    tracking_url: string;
                };
            };
        };
    };
};
type MeetingParticipantJoinedBreakoutRoomEvent = Event<"meeting.participant_joined_breakout_room"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            breakout_room_uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                parent_user_id?: string;
                user_name: string;
                id?: string;
                participant_uuid?: string;
                join_time: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                phone_number?: string;
                customer_key?: string;
            };
        };
    };
};
type MeetingParticipantLeftWaitingRoomEvent = Event<"meeting.participant_left_waiting_room"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                participant_uuid?: string;
                date_time: string;
                email: string;
                phone_number?: string;
                participant_user_id?: string;
                customer_key?: string;
                registrant_id?: string;
            };
        };
    };
};
type MeetingStartedEvent = Event<"meeting.started"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
        };
    };
};
type MeetingRegistrationCancelledEvent = Event<"meeting.registration_cancelled"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
            registrant: {
                id: string;
                first_name: string;
                last_name?: string;
                email: string;
            };
        };
    };
};
type MeetingSummaryCompletedEvent = Event<"meeting.summary_completed"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            meeting_host_id: string;
            meeting_host_email: string;
            meeting_uuid: string;
            meeting_id: number;
            meeting_topic: string;
            meeting_start_time: string;
            meeting_end_time: string;
            summary_start_time: string;
            summary_end_time: string;
            summary_created_time: string;
            summary_last_modified_time: string;
            summary_title: string;
            summary_overview?: string;
            summary_details: {
                label: string;
                summary: string;
            }[];
            next_steps: string[];
        };
    };
};
type MeetingParticipantLeftEvent = Event<"meeting.participant_left"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                participant_uuid?: string;
                leave_time: string;
                leave_reason?: string;
                email: string;
                registrant_id?: string;
                participant_user_id?: string;
                customer_key?: string;
                phone_number?: string;
            };
        };
    };
};
type MeetingRecoveredEvent = Event<"meeting.recovered"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
        };
    };
};
type MeetingParticipantPhoneCalloutRejectedEvent = Event<"meeting.participant_phone_callout_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
            };
        };
    };
};
type WebinarPermanentlyDeletedEvent = Event<"webinar.permanently_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        operation?: string;
        object: {
            uuid: string;
            id: number;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            duration: number;
            timezone: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                }
            ]>[];
        };
    };
};
type RecordingCompletedEvent = Event<"recording.completed"> & {
    event: string;
    event_ts: number;
    download_token: string;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            account_id: string;
            topic: string;
            type: number;
            start_time: string;
            password: string;
            timezone?: string;
            host_email: string;
            duration: number;
            share_url: string;
            total_size: number;
            recording_count: number;
            on_prem?: boolean;
            recording_play_passcode?: string;
            auto_delete?: boolean;
            auto_delete_date?: string;
            recording_files: {
                id: string;
                meeting_id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_size: number;
                file_extension: string;
                file_name?: string;
                play_url?: string;
                download_url: string;
                file_path?: string;
                status: string;
                recording_type: string;
            }[];
            participant_audio_files?: {
                id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_name: string;
                file_size: number;
                file_extension: string;
                play_url?: string;
                download_url: string;
                file_path?: string;
                status: string;
            }[];
        };
    };
};
type MeetingParticipantPhoneCalloutAcceptedEvent = Event<"meeting.participant_phone_callout_accepted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            participant: {
                invitee_name: string;
                phone_number: number;
            };
        };
    };
};
type MeetingParticipantPutInWaitingRoomEvent = Event<"meeting.participant_put_in_waiting_room"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: string;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            participant: {
                user_id: string;
                user_name?: string;
                id?: string;
                participant_uuid?: string;
                date_time: string;
                email: string;
                participant_user_id?: string;
                customer_key?: string;
                registrant_id?: string;
            };
        };
    };
};
type RecordingTrashedEvent = Event<"recording.trashed"> & {
    event: string;
    event_ts: number;
    download_token?: string;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            id: number;
            uuid: string;
            host_id: string;
            topic: string;
            type: number;
            start_time: string;
            timezone?: string;
            duration: number;
            share_url: string;
            total_size: number;
            recording_count: number;
            account_id: string;
            recording_files?: {
                id: string;
                meeting_id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_extension: string;
                file_name?: string;
                file_size: number;
                play_url?: string;
                download_url: string;
                status: string;
                recording_type: string;
            }[];
            participant_audio_files?: {
                id: string;
                recording_start: string;
                recording_end: string;
                file_type: string;
                file_name: string;
                file_size: number;
                file_extension: string;
                play_url?: string;
                download_url: string;
                file_path?: string;
                status: string;
            }[];
        };
    };
};
type MeetingSummaryDeletedEvent = Event<"meeting.summary_deleted"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object: {
            meeting_host_id: string;
            meeting_host_email: string;
            meeting_uuid: string;
            meeting_id: number;
            meeting_topic: string;
            meeting_start_time: string;
            meeting_end_time: string;
            summary_start_time: string;
            summary_end_time: string;
            summary_created_time: string;
            summary_last_modified_time: string;
            summary_title: string;
        };
    };
};
type WebinarParticipantBindEvent = Event<"webinar.participant_bind"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id?: string;
            uuid: string;
            host_id: string;
            topic?: string;
            type: number;
            start_time?: string;
            timezone?: string;
            duration?: number;
            participant: {
                user_id: string;
                bind_user_id: string;
                user_name?: string;
                id?: string;
                participant_uuid?: string;
                bind_participant_uuid?: string;
                join_time: string;
                registrant_id?: string;
                phone_number: string;
            };
        };
    };
};
type WebinarUpdatedEvent = Event<"webinar.updated"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        scope?: string;
        object: {
            id: number;
            uuid?: string;
            host_id?: string;
            topic?: string;
            type?: number;
            start_time?: string;
            duration?: number;
            timezone?: string;
            password?: string;
            agenda?: string;
            registration_url?: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                    duration?: number;
                    status?: string;
                }
            ]>[];
            settings?: {
                host_video?: boolean;
                panelists_video?: boolean;
                practice_session?: boolean;
                approval_type?: number;
                registration_type?: number;
                audio?: string;
                auto_recording?: string;
                enforce_login?: boolean;
                meeting_authentication?: boolean;
                authentication_option?: string;
                authentication_name?: string;
                authentication_domains?: string;
            };
            recurrence?: {
                type?: number;
                repeat_interval?: number;
                weekly_days?: string;
                monthly_day?: number;
                monthly_week_day?: number;
                end_times?: number;
                end_date_time?: string;
                monthly_week?: number;
            };
        };
        time_stamp: number;
        old_object: {
            id: number;
            uuid?: string;
            host_id?: string;
            topic?: string;
            type?: number;
            start_time?: string;
            duration?: number;
            timezone?: string;
            password?: string;
            agenda?: string;
            registration_url?: string;
            occurrences?: ExactlyOneOf<[
                {
                    occurrence_id: string;
                    start_time: string;
                    duration?: number;
                    status?: string;
                }
            ]>[];
            settings?: {
                host_video?: boolean;
                panelists_video?: boolean;
                practice_session?: boolean;
                approval_type?: number;
                registration_type?: number;
                audio?: string;
                auto_recording?: string;
                enforce_login?: boolean;
                meeting_authentication?: boolean;
                authentication_option?: string;
                authentication_name?: string;
                authentication_domains?: string;
            };
            recurrence?: {
                type?: number;
                repeat_interval?: number;
                weekly_days?: string;
                monthly_day?: number;
                monthly_week_day?: number;
                end_times?: number;
                end_date_time?: string;
                monthly_week?: number;
            };
        };
    };
};
type RecordingBatchRecoveredEvent = Event<"recording.batch_recovered"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        operator: string;
        operator_id: string;
        object?: {
            meetings: {
                meeting_uuid?: string;
                recording_file_ids?: any[];
            }[];
        };
    };
};
type MeetingParticipantRoomSystemCalloutRejectedEvent = Event<"meeting.participant_room_system_callout_rejected"> & {
    event: string;
    event_ts: number;
    payload: {
        account_id: string;
        object: {
            id: number;
            uuid: string;
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
type MeetingsEvents = WebinarSharingStartedEvent | MeetingParticipantJbhWaitingEvent | MeetingRegistrationCreatedEvent | MeetingSummaryRecoveredEvent | RecordingRecoveredEvent | MeetingSharingEndedEvent | RecordingCloudStorageUsageUpdatedEvent | MeetingParticipantLeftBreakoutRoomEvent | MeetingDeviceTestedEvent | MeetingSummarySharedEvent | RecordingTranscriptCompletedEvent | RecordingStoppedEvent | RecordingBatchTrashedEvent | WebinarStartedEvent | WebinarSharingEndedEvent | MeetingSummaryTrashedEvent | WebinarDeletedEvent | RecordingRegistrationApprovedEvent | MeetingSharingStartedEvent | WebinarRegistrationCreatedEvent | MeetingChatMessageSentEvent | MeetingParticipantRoleChangedEvent | MeetingRiskAlertEvent | MeetingPermanentlyDeletedEvent | WebinarParticipantFeedbackEvent | RecordingRegistrationCreatedEvent | MeetingParticipantJoinedWaitingRoomEvent | MeetingParticipantPhoneCalloutRingingEvent | MeetingCreatedEvent | MeetingLiveStreamingStartedEvent | MeetingParticipantRoomSystemCalloutAcceptedEvent | WebinarRegistrationApprovedEvent | MeetingParticipantJbhJoinedEvent | RecordingArchiveFilesCompletedEvent | MeetingBreakoutRoomSharingStartedEvent | MeetingAlertEvent | MeetingChatMessageFileSentEvent | MeetingParticipantBindEvent | MeetingDeletedEvent | MeetingParticipantFeedbackEvent | MeetingParticipantJoinedEvent | UserTspDeletedEvent | RecordingDeletedEvent | RecordingPausedEvent | MeetingParticipantRoomSystemCalloutRingingEvent | RecordingStartedEvent | UserTspUpdatedEvent | WebinarEndedEvent | WebinarRecoveredEvent | MeetingParticipantAdmittedEvent | MeetingParticipantRoomSystemCalloutFailedEvent | RecordingResumedEvent | WebinarParticipantRoleChangedEvent | MeetingParticipantPhoneCalloutMissedEvent | MeetingSummaryUpdatedEvent | WebinarParticipantJoinedEvent | RecordingRenamedEvent | MeetingParticipantJbhWaitingLeftEvent | UserTspCreatedEvent | MeetingBreakoutRoomSharingEndedEvent | MeetingUpdatedEvent | MeetingParticipantRoomSystemCalloutMissedEvent | MeetingRegistrationDeniedEvent | WebinarCreatedEvent | WebinarRegistrationDeniedEvent | MeetingRegistrationApprovedEvent | WebinarParticipantLeftEvent | RecordingBatchDeletedEvent | WebinarAlertEvent | RecordingRegistrationDeniedEvent | WebinarChatMessageSentEvent | MeetingLiveStreamingStoppedEvent | WebinarChatMessageFileSentEvent | MeetingEndedEvent | WebinarRegistrationCancelledEvent | MeetingParticipantJoinedBreakoutRoomEvent | MeetingParticipantLeftWaitingRoomEvent | MeetingStartedEvent | MeetingRegistrationCancelledEvent | MeetingSummaryCompletedEvent | MeetingParticipantLeftEvent | MeetingRecoveredEvent | MeetingParticipantPhoneCalloutRejectedEvent | WebinarPermanentlyDeletedEvent | RecordingCompletedEvent | MeetingParticipantPhoneCalloutAcceptedEvent | MeetingParticipantPutInWaitingRoomEvent | RecordingTrashedEvent | MeetingSummaryDeletedEvent | WebinarParticipantBindEvent | WebinarUpdatedEvent | RecordingBatchRecoveredEvent | MeetingParticipantRoomSystemCalloutRejectedEvent;
declare class MeetingsEventProcessor extends EventManager<MeetingsEndpoints, MeetingsEvents> {
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

type MeetingsOptions<R extends Receiver> = CommonClientOptions<OAuth, R>;
declare class MeetingsOAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<OAuth, ReceiverType> = MeetingsOptions<ReceiverType>> extends ProductClient<OAuth, MeetingsEndpoints, MeetingsEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, ...restOptions }: OptionsType): OAuth;
    protected initEndpoints(auth: OAuth, options: OptionsType): MeetingsEndpoints;
    protected initEventProcessor(endpoints: MeetingsEndpoints): MeetingsEventProcessor;
}

type MeetingsS2SAuthOptions<R extends Receiver> = CommonClientOptions<S2SAuth, R>;
declare class MeetingsS2SAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<S2SAuth, ReceiverType> = MeetingsS2SAuthOptions<ReceiverType>> extends ProductClient<S2SAuth, MeetingsEndpoints, MeetingsEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore, accountId }: OptionsType): S2SAuth;
    protected initEndpoints(auth: S2SAuth, options: OptionsType): MeetingsEndpoints;
    protected initEventProcessor(endpoints: MeetingsEndpoints): MeetingsEventProcessor;
}

export { ApiResponseError, type ArchivingDeleteMeetingsArchivedFilesPathParams, type ArchivingGetArchivedFileStatisticsQueryParams, type ArchivingGetArchivedFileStatisticsResponse, type ArchivingGetMeetingsArchivedFilesPathParams, type ArchivingGetMeetingsArchivedFilesResponse, type ArchivingListArchivedFilesQueryParams, type ArchivingListArchivedFilesResponse, type ArchivingUpdateArchivedFilesAutoDeleteStatusPathParams, type ArchivingUpdateArchivedFilesAutoDeleteStatusRequestBody, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, type CloudRecordingCreateRecordingRegistrantPathParams, type CloudRecordingCreateRecordingRegistrantRequestBody, type CloudRecordingCreateRecordingRegistrantResponse, type CloudRecordingDeleteMeetingOrWebinarRecordingsPathParams, type CloudRecordingDeleteMeetingOrWebinarRecordingsQueryParams, type CloudRecordingDeleteRecordingFileForMeetingOrWebinarPathParams, type CloudRecordingDeleteRecordingFileForMeetingOrWebinarQueryParams, type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsPathParams, type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsQueryParams, type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsDetailsResponse, type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryPathParams, type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryQueryParams, type CloudRecordingGetMeetingOrWebinarRecordingsAnalyticsSummaryResponse, type CloudRecordingGetMeetingRecordingSettingsPathParams, type CloudRecordingGetMeetingRecordingSettingsResponse, type CloudRecordingGetMeetingRecordingsPathParams, type CloudRecordingGetMeetingRecordingsQueryParams, type CloudRecordingGetMeetingRecordingsResponse, type CloudRecordingGetRegistrationQuestionsPathParams, type CloudRecordingGetRegistrationQuestionsResponse, type CloudRecordingListAllRecordingsPathParams, type CloudRecordingListAllRecordingsQueryParams, type CloudRecordingListAllRecordingsResponse, type CloudRecordingListRecordingRegistrantsPathParams, type CloudRecordingListRecordingRegistrantsQueryParams, type CloudRecordingListRecordingRegistrantsResponse, type CloudRecordingRecoverMeetingRecordingsPathParams, type CloudRecordingRecoverMeetingRecordingsRequestBody, type CloudRecordingRecoverSingleRecordingPathParams, type CloudRecordingRecoverSingleRecordingRequestBody, type CloudRecordingUpdateMeetingRecordingSettingsPathParams, type CloudRecordingUpdateMeetingRecordingSettingsRequestBody, type CloudRecordingUpdateRegistrantsStatusPathParams, type CloudRecordingUpdateRegistrantsStatusRequestBody, type CloudRecordingUpdateRegistrationQuestionsPathParams, type CloudRecordingUpdateRegistrationQuestionsRequestBody, CommonHttpRequestError, ConsoleLogger, type DevicesAddNewDeviceRequestBody, type DevicesAssignDeviceToUserOrCommonareaRequestBody, type DevicesChangeDeviceAssociationPathParams, type DevicesChangeDeviceAssociationRequestBody, type DevicesChangeDevicePathParams, type DevicesChangeDeviceRequestBody, type DevicesDeleteDevicePathParams, type DevicesDeleteZPADeviceByVendorAndMacAddressPathParams, type DevicesGetDeviceDetailPathParams, type DevicesGetDeviceDetailResponse, type DevicesGetZDMGroupInfoQueryParams, type DevicesGetZDMGroupInfoResponse, type DevicesGetZPAVersionInfoPathParams, type DevicesGetZPAVersionInfoResponse, type DevicesListDevicesQueryParams, type DevicesListDevicesResponse, type DevicesUpgradeZpaOsAppRequestBody, type H323DevicesCreateHSIPDeviceRequestBody, type H323DevicesCreateHSIPDeviceResponse, type H323DevicesDeleteHSIPDevicePathParams, type H323DevicesListHSIPDevicesQueryParams, type H323DevicesListHSIPDevicesResponse, type H323DevicesUpdateHSIPDevicePathParams, type H323DevicesUpdateHSIPDeviceRequestBody, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, type HttpReceiverOptions, LogLevel, type Logger, type MeetingAlertEvent, type MeetingBreakoutRoomSharingEndedEvent, type MeetingBreakoutRoomSharingStartedEvent, type MeetingChatMessageFileSentEvent, type MeetingChatMessageSentEvent, type MeetingCreatedEvent, type MeetingDeletedEvent, type MeetingDeviceTestedEvent, type MeetingEndedEvent, type MeetingLiveStreamingStartedEvent, type MeetingLiveStreamingStoppedEvent, type MeetingParticipantAdmittedEvent, type MeetingParticipantBindEvent, type MeetingParticipantFeedbackEvent, type MeetingParticipantJbhJoinedEvent, type MeetingParticipantJbhWaitingEvent, type MeetingParticipantJbhWaitingLeftEvent, type MeetingParticipantJoinedBreakoutRoomEvent, type MeetingParticipantJoinedEvent, type MeetingParticipantJoinedWaitingRoomEvent, type MeetingParticipantLeftBreakoutRoomEvent, type MeetingParticipantLeftEvent, type MeetingParticipantLeftWaitingRoomEvent, type MeetingParticipantPhoneCalloutAcceptedEvent, type MeetingParticipantPhoneCalloutMissedEvent, type MeetingParticipantPhoneCalloutRejectedEvent, type MeetingParticipantPhoneCalloutRingingEvent, type MeetingParticipantPutInWaitingRoomEvent, type MeetingParticipantRoleChangedEvent, type MeetingParticipantRoomSystemCalloutAcceptedEvent, type MeetingParticipantRoomSystemCalloutFailedEvent, type MeetingParticipantRoomSystemCalloutMissedEvent, type MeetingParticipantRoomSystemCalloutRejectedEvent, type MeetingParticipantRoomSystemCalloutRingingEvent, type MeetingPermanentlyDeletedEvent, type MeetingRecoveredEvent, type MeetingRegistrationApprovedEvent, type MeetingRegistrationCancelledEvent, type MeetingRegistrationCreatedEvent, type MeetingRegistrationDeniedEvent, type MeetingRiskAlertEvent, type MeetingSharingEndedEvent, type MeetingSharingStartedEvent, type MeetingStartedEvent, type MeetingSummaryCompletedEvent, type MeetingSummaryDeletedEvent, type MeetingSummaryRecoveredEvent, type MeetingSummarySharedEvent, type MeetingSummaryTrashedEvent, type MeetingSummaryUpdatedEvent, type MeetingUpdatedEvent, type MeetingsAddMeetingAppPathParams, type MeetingsAddMeetingAppResponse, type MeetingsAddMeetingRegistrantPathParams, type MeetingsAddMeetingRegistrantQueryParams, type MeetingsAddMeetingRegistrantRequestBody, type MeetingsAddMeetingRegistrantResponse, type MeetingsCreateMeetingPathParams, type MeetingsCreateMeetingPollPathParams, type MeetingsCreateMeetingPollRequestBody, type MeetingsCreateMeetingPollResponse, type MeetingsCreateMeetingRequestBody, type MeetingsCreateMeetingResponse, type MeetingsCreateMeetingTemplateFromExistingMeetingPathParams, type MeetingsCreateMeetingTemplateFromExistingMeetingRequestBody, type MeetingsCreateMeetingTemplateFromExistingMeetingResponse, type MeetingsCreateMeetingsInviteLinksPathParams, type MeetingsCreateMeetingsInviteLinksRequestBody, type MeetingsCreateMeetingsInviteLinksResponse, type MeetingsDeleteLiveMeetingMessagePathParams, type MeetingsDeleteLiveMeetingMessageQueryParams, type MeetingsDeleteMeetingAppPathParams, type MeetingsDeleteMeetingPathParams, type MeetingsDeleteMeetingPollPathParams, type MeetingsDeleteMeetingQueryParams, type MeetingsDeleteMeetingRegistrantPathParams, type MeetingsDeleteMeetingRegistrantQueryParams, type MeetingsDeleteMeetingSurveyPathParams, MeetingsEndpoints, MeetingsEventProcessor, type MeetingsGetLivestreamDetailsPathParams, type MeetingsGetLivestreamDetailsResponse, type MeetingsGetMeetingInvitationPathParams, type MeetingsGetMeetingInvitationResponse, type MeetingsGetMeetingPathParams, type MeetingsGetMeetingPollPathParams, type MeetingsGetMeetingPollResponse, type MeetingsGetMeetingQueryParams, type MeetingsGetMeetingRegistrantPathParams, type MeetingsGetMeetingRegistrantResponse, type MeetingsGetMeetingResponse, type MeetingsGetMeetingSIPURIWithPasscodePathParams, type MeetingsGetMeetingSIPURIWithPasscodeRequestBody, type MeetingsGetMeetingSIPURIWithPasscodeResponse, type MeetingsGetMeetingSummaryPathParams, type MeetingsGetMeetingSummaryResponse, type MeetingsGetMeetingSurveyPathParams, type MeetingsGetMeetingSurveyResponse, type MeetingsGetMeetingsArchiveTokenForLocalArchivingPathParams, type MeetingsGetMeetingsArchiveTokenForLocalArchivingResponse, type MeetingsGetMeetingsJoinTokenForLiveStreamingPathParams, type MeetingsGetMeetingsJoinTokenForLiveStreamingResponse, type MeetingsGetMeetingsJoinTokenForLocalRecordingPathParams, type MeetingsGetMeetingsJoinTokenForLocalRecordingQueryParams, type MeetingsGetMeetingsJoinTokenForLocalRecordingResponse, type MeetingsGetMeetingsTokenPathParams, type MeetingsGetMeetingsTokenQueryParams, type MeetingsGetMeetingsTokenResponse, type MeetingsGetPastMeetingDetailsPathParams, type MeetingsGetPastMeetingDetailsResponse, type MeetingsGetPastMeetingParticipantsPathParams, type MeetingsGetPastMeetingParticipantsQueryParams, type MeetingsGetPastMeetingParticipantsResponse, type MeetingsListMeetingPollsPathParams, type MeetingsListMeetingPollsQueryParams, type MeetingsListMeetingPollsResponse, type MeetingsListMeetingRegistrantsPathParams, type MeetingsListMeetingRegistrantsQueryParams, type MeetingsListMeetingRegistrantsResponse, type MeetingsListMeetingSummariesOfAccountQueryParams, type MeetingsListMeetingSummariesOfAccountResponse, type MeetingsListMeetingTemplatesPathParams, type MeetingsListMeetingTemplatesResponse, type MeetingsListMeetingsPathParams, type MeetingsListMeetingsQueryParams, type MeetingsListMeetingsResponse, type MeetingsListPastMeetingInstancesPathParams, type MeetingsListPastMeetingInstancesResponse, type MeetingsListPastMeetingsPollResultsPathParams, type MeetingsListPastMeetingsPollResultsResponse, type MeetingsListPastMeetingsQAPathParams, type MeetingsListPastMeetingsQAResponse, type MeetingsListRegistrationQuestionsPathParams, type MeetingsListRegistrationQuestionsResponse, type MeetingsListUpcomingMeetingsPathParams, type MeetingsListUpcomingMeetingsResponse, MeetingsOAuthClient, type MeetingsOptions, type MeetingsPerformBatchPollCreationPathParams, type MeetingsPerformBatchPollCreationRequestBody, type MeetingsPerformBatchPollCreationResponse, type MeetingsPerformBatchRegistrationPathParams, type MeetingsPerformBatchRegistrationRequestBody, type MeetingsPerformBatchRegistrationResponse, MeetingsS2SAuthClient, type MeetingsS2SAuthOptions, type MeetingsUpdateLiveMeetingMessagePathParams, type MeetingsUpdateLiveMeetingMessageRequestBody, type MeetingsUpdateLivestreamPathParams, type MeetingsUpdateLivestreamRequestBody, type MeetingsUpdateLivestreamStatusPathParams, type MeetingsUpdateLivestreamStatusRequestBody, type MeetingsUpdateMeetingPathParams, type MeetingsUpdateMeetingPollPathParams, type MeetingsUpdateMeetingPollRequestBody, type MeetingsUpdateMeetingQueryParams, type MeetingsUpdateMeetingRequestBody, type MeetingsUpdateMeetingStatusPathParams, type MeetingsUpdateMeetingStatusRequestBody, type MeetingsUpdateMeetingSurveyPathParams, type MeetingsUpdateMeetingSurveyRequestBody, type MeetingsUpdateRegistrantsStatusPathParams, type MeetingsUpdateRegistrantsStatusQueryParams, type MeetingsUpdateRegistrantsStatusRequestBody, type MeetingsUpdateRegistrationQuestionsPathParams, type MeetingsUpdateRegistrationQuestionsRequestBody, type MeetingsUseInMeetingControlsPathParams, type MeetingsUseInMeetingControlsRequestBody, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, type PACListUsersPACAccountsPathParams, type PACListUsersPACAccountsResponse, ProductClientConstructionError, type Receiver, ReceiverInconsistentStateError, type ReceiverInitOptions, ReceiverOAuthFlowError, type RecordingArchiveFilesCompletedEvent, type RecordingBatchDeletedEvent, type RecordingBatchRecoveredEvent, type RecordingBatchTrashedEvent, type RecordingCloudStorageUsageUpdatedEvent, type RecordingCompletedEvent, type RecordingDeletedEvent, type RecordingPausedEvent, type RecordingRecoveredEvent, type RecordingRegistrationApprovedEvent, type RecordingRegistrationCreatedEvent, type RecordingRegistrationDeniedEvent, type RecordingRenamedEvent, type RecordingResumedEvent, type RecordingStartedEvent, type RecordingStoppedEvent, type RecordingTranscriptCompletedEvent, type RecordingTrashedEvent, type ReportsGetActiveOrInactiveHostReportsQueryParams, type ReportsGetActiveOrInactiveHostReportsResponse, type ReportsGetBillingInvoiceReportsQueryParams, type ReportsGetBillingInvoiceReportsResponse, type ReportsGetBillingReportsResponse, type ReportsGetCloudRecordingUsageReportQueryParams, type ReportsGetCloudRecordingUsageReportResponse, type ReportsGetDailyUsageReportQueryParams, type ReportsGetDailyUsageReportResponse, type ReportsGetMeetingActivitiesReportQueryParams, type ReportsGetMeetingActivitiesReportResponse, type ReportsGetMeetingDetailReportsPathParams, type ReportsGetMeetingDetailReportsResponse, type ReportsGetMeetingParticipantReportsPathParams, type ReportsGetMeetingParticipantReportsQueryParams, type ReportsGetMeetingParticipantReportsResponse, type ReportsGetMeetingPollReportsPathParams, type ReportsGetMeetingPollReportsResponse, type ReportsGetMeetingQAReportPathParams, type ReportsGetMeetingQAReportResponse, type ReportsGetMeetingReportsPathParams, type ReportsGetMeetingReportsQueryParams, type ReportsGetMeetingReportsResponse, type ReportsGetMeetingSurveyReportPathParams, type ReportsGetMeetingSurveyReportResponse, type ReportsGetOperationLogsReportQueryParams, type ReportsGetOperationLogsReportResponse, type ReportsGetSignInSignOutActivityReportQueryParams, type ReportsGetSignInSignOutActivityReportResponse, type ReportsGetTelephoneReportsQueryParams, type ReportsGetTelephoneReportsResponse, type ReportsGetUpcomingEventsReportQueryParams, type ReportsGetUpcomingEventsReportResponse, type ReportsGetWebinarDetailReportsPathParams, type ReportsGetWebinarDetailReportsResponse, type ReportsGetWebinarParticipantReportsPathParams, type ReportsGetWebinarParticipantReportsQueryParams, type ReportsGetWebinarParticipantReportsResponse, type ReportsGetWebinarPollReportsPathParams, type ReportsGetWebinarPollReportsResponse, type ReportsGetWebinarQAReportPathParams, type ReportsGetWebinarQAReportResponse, type ReportsGetWebinarSurveyReportPathParams, type ReportsGetWebinarSurveyReportResponse, S2SRawResponseError, type SIPPhoneDeleteSIPPhonePathParams, type SIPPhoneEnableSIPPhoneRequestBody, type SIPPhoneEnableSIPPhoneResponse, type SIPPhoneListSIPPhonesQueryParams, type SIPPhoneListSIPPhonesResponse, type SIPPhoneUpdateSIPPhonePathParams, type SIPPhoneUpdateSIPPhoneRequestBody, type StateStore, StatusCode, type TSPAddUsersTSPAccountPathParams, type TSPAddUsersTSPAccountRequestBody, type TSPAddUsersTSPAccountResponse, type TSPDeleteUsersTSPAccountPathParams, type TSPGetAccountsTSPInformationResponse, type TSPGetUsersTSPAccountPathParams, type TSPGetUsersTSPAccountResponse, type TSPListUsersTSPAccountsPathParams, type TSPListUsersTSPAccountsResponse, type TSPSetGlobalDialInURLForTSPUserPathParams, type TSPSetGlobalDialInURLForTSPUserRequestBody, type TSPUpdateAccountsTSPInformationRequestBody, type TSPUpdateTSPAccountPathParams, type TSPUpdateTSPAccountRequestBody, type TokenStore, type TrackingFieldCreateTrackingFieldRequestBody, type TrackingFieldCreateTrackingFieldResponse, type TrackingFieldDeleteTrackingFieldPathParams, type TrackingFieldGetTrackingFieldPathParams, type TrackingFieldGetTrackingFieldResponse, type TrackingFieldListTrackingFieldsResponse, type TrackingFieldUpdateTrackingFieldPathParams, type TrackingFieldUpdateTrackingFieldRequestBody, type UserTspCreatedEvent, type UserTspDeletedEvent, type UserTspUpdatedEvent, type WebinarAlertEvent, type WebinarChatMessageFileSentEvent, type WebinarChatMessageSentEvent, type WebinarCreatedEvent, type WebinarDeletedEvent, type WebinarEndedEvent, type WebinarParticipantBindEvent, type WebinarParticipantFeedbackEvent, type WebinarParticipantJoinedEvent, type WebinarParticipantLeftEvent, type WebinarParticipantRoleChangedEvent, type WebinarPermanentlyDeletedEvent, type WebinarRecoveredEvent, type WebinarRegistrationApprovedEvent, type WebinarRegistrationCancelledEvent, type WebinarRegistrationCreatedEvent, type WebinarRegistrationDeniedEvent, type WebinarSharingEndedEvent, type WebinarSharingStartedEvent, type WebinarStartedEvent, type WebinarUpdatedEvent, type WebinarsAddPanelistsPathParams, type WebinarsAddPanelistsRequestBody, type WebinarsAddPanelistsResponse, type WebinarsAddWebinarRegistrantPathParams, type WebinarsAddWebinarRegistrantQueryParams, type WebinarsAddWebinarRegistrantRequestBody, type WebinarsAddWebinarRegistrantResponse, type WebinarsCreateWebinarPathParams, type WebinarsCreateWebinarRequestBody, type WebinarsCreateWebinarResponse, type WebinarsCreateWebinarTemplatePathParams, type WebinarsCreateWebinarTemplateRequestBody, type WebinarsCreateWebinarTemplateResponse, type WebinarsCreateWebinarsBrandingNameTagPathParams, type WebinarsCreateWebinarsBrandingNameTagRequestBody, type WebinarsCreateWebinarsBrandingNameTagResponse, type WebinarsCreateWebinarsInviteLinksPathParams, type WebinarsCreateWebinarsInviteLinksRequestBody, type WebinarsCreateWebinarsInviteLinksResponse, type WebinarsCreateWebinarsPollPathParams, type WebinarsCreateWebinarsPollRequestBody, type WebinarsCreateWebinarsPollResponse, type WebinarsDeleteLiveWebinarMessagePathParams, type WebinarsDeleteLiveWebinarMessageQueryParams, type WebinarsDeleteWebinarPathParams, type WebinarsDeleteWebinarPollPathParams, type WebinarsDeleteWebinarQueryParams, type WebinarsDeleteWebinarRegistrantPathParams, type WebinarsDeleteWebinarRegistrantQueryParams, type WebinarsDeleteWebinarSurveyPathParams, type WebinarsDeleteWebinarsBrandingNameTagPathParams, type WebinarsDeleteWebinarsBrandingNameTagQueryParams, type WebinarsDeleteWebinarsBrandingVirtualBackgroundsPathParams, type WebinarsDeleteWebinarsBrandingVirtualBackgroundsQueryParams, type WebinarsDeleteWebinarsBrandingWallpaperPathParams, type WebinarsGetLiveStreamDetailsPathParams, type WebinarsGetLiveStreamDetailsResponse, type WebinarsGetWebinarAbsenteesPathParams, type WebinarsGetWebinarAbsenteesQueryParams, type WebinarsGetWebinarAbsenteesResponse, type WebinarsGetWebinarPathParams, type WebinarsGetWebinarPollPathParams, type WebinarsGetWebinarPollResponse, type WebinarsGetWebinarQueryParams, type WebinarsGetWebinarRegistrantPathParams, type WebinarsGetWebinarRegistrantQueryParams, type WebinarsGetWebinarRegistrantResponse, type WebinarsGetWebinarResponse, type WebinarsGetWebinarSIPURIWithPasscodePathParams, type WebinarsGetWebinarSIPURIWithPasscodeRequestBody, type WebinarsGetWebinarSIPURIWithPasscodeResponse, type WebinarsGetWebinarSurveyPathParams, type WebinarsGetWebinarSurveyResponse, type WebinarsGetWebinarTrackingSourcesPathParams, type WebinarsGetWebinarTrackingSourcesResponse, type WebinarsGetWebinarsArchiveTokenForLocalArchivingPathParams, type WebinarsGetWebinarsArchiveTokenForLocalArchivingResponse, type WebinarsGetWebinarsJoinTokenForLiveStreamingPathParams, type WebinarsGetWebinarsJoinTokenForLiveStreamingResponse, type WebinarsGetWebinarsJoinTokenForLocalRecordingPathParams, type WebinarsGetWebinarsJoinTokenForLocalRecordingResponse, type WebinarsGetWebinarsSessionBrandingPathParams, type WebinarsGetWebinarsSessionBrandingResponse, type WebinarsGetWebinarsTokenPathParams, type WebinarsGetWebinarsTokenQueryParams, type WebinarsGetWebinarsTokenResponse, type WebinarsListPanelistsPathParams, type WebinarsListPanelistsResponse, type WebinarsListPastWebinarInstancesPathParams, type WebinarsListPastWebinarInstancesResponse, type WebinarsListPastWebinarPollResultsPathParams, type WebinarsListPastWebinarPollResultsResponse, type WebinarsListQAsOfPastWebinarPathParams, type WebinarsListQAsOfPastWebinarResponse, type WebinarsListRegistrationQuestionsPathParams, type WebinarsListRegistrationQuestionsResponse, type WebinarsListWebinarParticipantsPathParams, type WebinarsListWebinarParticipantsQueryParams, type WebinarsListWebinarParticipantsResponse, type WebinarsListWebinarRegistrantsPathParams, type WebinarsListWebinarRegistrantsQueryParams, type WebinarsListWebinarRegistrantsResponse, type WebinarsListWebinarTemplatesPathParams, type WebinarsListWebinarTemplatesResponse, type WebinarsListWebinarsPathParams, type WebinarsListWebinarsPollsPathParams, type WebinarsListWebinarsPollsQueryParams, type WebinarsListWebinarsPollsResponse, type WebinarsListWebinarsQueryParams, type WebinarsListWebinarsResponse, type WebinarsPerformBatchRegistrationPathParams, type WebinarsPerformBatchRegistrationRequestBody, type WebinarsPerformBatchRegistrationResponse, type WebinarsRemoveAllPanelistsPathParams, type WebinarsRemovePanelistPathParams, type WebinarsSetWebinarsDefaultBrandingVirtualBackgroundPathParams, type WebinarsSetWebinarsDefaultBrandingVirtualBackgroundQueryParams, type WebinarsUpdateLiveStreamPathParams, type WebinarsUpdateLiveStreamRequestBody, type WebinarsUpdateLiveStreamStatusPathParams, type WebinarsUpdateLiveStreamStatusRequestBody, type WebinarsUpdateRegistrantsStatusPathParams, type WebinarsUpdateRegistrantsStatusQueryParams, type WebinarsUpdateRegistrantsStatusRequestBody, type WebinarsUpdateRegistrationQuestionsPathParams, type WebinarsUpdateRegistrationQuestionsRequestBody, type WebinarsUpdateWebinarPathParams, type WebinarsUpdateWebinarPollPathParams, type WebinarsUpdateWebinarPollRequestBody, type WebinarsUpdateWebinarQueryParams, type WebinarsUpdateWebinarRequestBody, type WebinarsUpdateWebinarStatusPathParams, type WebinarsUpdateWebinarStatusRequestBody, type WebinarsUpdateWebinarSurveyPathParams, type WebinarsUpdateWebinarSurveyRequestBody, type WebinarsUpdateWebinarsBrandingNameTagPathParams, type WebinarsUpdateWebinarsBrandingNameTagRequestBody, type WebinarsUploadWebinarsBrandingVirtualBackgroundPathParams, type WebinarsUploadWebinarsBrandingVirtualBackgroundRequestBody, type WebinarsUploadWebinarsBrandingVirtualBackgroundResponse, type WebinarsUploadWebinarsBrandingWallpaperPathParams, type WebinarsUploadWebinarsBrandingWallpaperRequestBody, type WebinarsUploadWebinarsBrandingWallpaperResponse, isCoreError, isStateStore };
