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
declare class ClientCredentialsAuth extends Auth<ClientCredentialsToken> {
    private assertRawToken;
    private fetchClientCredentials;
    getToken(): Promise<string>;
    private mapClientCredentials;
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

interface CardContent {
    settings?: any;
    head?: Header;
    body?: (MultiplePages | Sections | ContentBodyElements)[];
}
type ContentBodyElements = Message | Fields | Actions | Attachment | File | Divider | Progress | StaticSelect | MemberSelect | ChannelSelect | TimePicker | DatePicker | RadioGroup | CheckboxGroup | SwitchGroup | Alert | MultipleImage | Input | Textarea | VideoPlayer;
interface Header {
    text: string;
    style?: Style;
    sub_head?: SubHeader;
}
interface SubHeader {
    text: string;
    style?: Style;
}
interface Sections extends Partial<Footer> {
    type: "section";
    sidebar_color?: string;
    sections: ContentBodyElements[];
}
interface MultiplePages {
    type: "page";
    cur_page: number;
    pages: {
        pageNo: number;
        body: Sections[];
    }[];
}
interface Message {
    type: "message";
    text: string;
    style?: Style;
    editable?: boolean;
    is_markdown_support?: boolean;
    link?: string;
}
interface Fields {
    type: "fields";
    items: {
        key: string;
        value: string;
        short?: boolean;
        editable?: boolean;
    }[];
}
interface Actions {
    type: "actions";
    items: {
        text: string;
        value: string;
        style: string;
    }[];
}
interface Attachment {
    type: "attachments";
    resource_url: string;
    img_url: string;
    information: {
        title: {
            text: string;
        };
        description: {
            text: string;
        };
    };
}
interface File {
    type: "file";
    icon_url: string;
    title: {
        text: string;
        file_url: string;
    };
    description: {
        text: string;
    };
}
interface Divider {
    type: "divider";
    style: {
        bold: boolean;
        dotted: boolean;
        color: string;
    };
}
interface Progress {
    type: "progress_bar";
    value: number;
}
interface StaticSelect {
    type: "select";
    text: string;
    selected_item?: {
        text: string;
        value: string;
    };
    select_items: {
        text: string;
        value: string;
    }[];
}
interface MemberSelect {
    type: "select";
    text: string;
    static_source: string;
}
interface ChannelSelect {
    type: "select";
    text: string;
    static_source: string;
}
interface TimePicker {
    type: "timepicker";
    initial_time: string;
    action_id: string;
}
interface DatePicker {
    type: "datepicker";
    initial_date: string;
    action_id: string;
}
interface RadioGroup {
    type: "radio_buttons";
    initial_option: {
        value: string;
        text: string;
    };
    options: {
        value: string;
        text: string;
    }[];
    action_id: string;
}
interface CheckboxGroup {
    type: "checkboxes";
    options: {
        text: string;
        value: string;
        initial_selected?: boolean;
    }[];
    action_id: string;
}
interface SwitchGroup {
    type: "checkboxes";
    options: {
        text: string;
        value: string;
        initial_selected?: boolean;
    }[];
    action_id: string;
    style: string;
}
interface Alert {
    type: "alert";
    text: string;
    level: string;
    closable: boolean;
}
interface MultipleImage {
    type: "images";
    cur_index: number;
    images: {
        image_url: string;
        alt_text: string;
        image_index: number;
    }[];
}
interface Input {
    type: "plain_text_input";
    action_id: string;
    text: string;
    value: string;
    placeholder: string;
    multiline: boolean;
    min_length: number;
    max_length: number;
}
interface Textarea {
    type: "plain_text_input";
    action_id: string;
    text: string;
    value: string;
    placeholder: string;
    multiline: boolean;
    min_length: number;
    max_length: number;
}
interface VideoPlayer {
    type: "video";
    title: {
        text: string;
        is_markdown_support: boolean;
    };
    action_id: string;
    title_url: string;
    video_url: string;
    thumbnail_url: string;
    author_name: string;
    provider_name: string;
    provider_icon_url: string;
}
interface Style {
    color: string;
    bold: boolean;
    italic: boolean;
}
interface Footer {
    footer: string;
    footer_icon: string;
    ts: number;
}

type SendChatbotMessagesRequestBody = {
    /**The Bot JID. You can find this value in the **Feature** tab's **Chat Subscription** section of your Marketplace Chatbot app.*/
    robot_jid: string;
    /**The JID of the group channel or user to whom the message was sent.*/
    to_jid: string;
    /**The authorized account's account ID.*/
    account_id?: string;
    content: CardContent;
    /**The user ID of the user who will receive Chatbot messages in the group channel. Only this user will see the Chatbot's messages.*/
    visible_to_user?: string;
    /**The JID of the user on whose behalf the message is being sent. This is used to prevent members of a channel from getting notifications that were set up by a user who has left the channel.*/
    user_jid: string;
    /**Whether to apply the [Markdown parser to your Chatbot message](/docs/team-chat-apps/customizing-messages/message-with-markdown/).*/
    is_markdown_support?: boolean;
};
type SendChatbotMessagesResponse = object;
type EditChatbotMessagePathParams = {
    message_id: string;
};
type EditChatbotMessageRequestBody = {
    /**The Bot JID. You can find this value in the **Feature** tab's **Chat Subscription** section of your Marketplace Chatbot app.*/
    robot_jid: string;
    /**The account ID to which the message was sent. You can get this value from the [Chatbot request sent to your server](/docs/team-chat-apps/send-edit-and-delete-messages/#send-messages).*/
    account_id?: string;
    content: CardContent;
    /**The JID of the user on whose behalf the message is being sent. This is used to prevent members of a channel from getting notifications that were set up by a user who has left the channel.*/
    user_jid: string;
    /**Whether to apply the [Markdown parser to your Chatbot message](/docs/team-chat-apps/customizing-messages/message-with-markdown/).*/
    is_markdown_support?: boolean;
};
type EditChatbotMessageResponse = {
    /**The updated message's ID.*/
    message_id?: string;
    /**The Bot JID. You can find this value in the **Feature** tab's **Chat Subscription** section of your Marketplace Chatbot app.*/
    robot_jid?: string;
    /**The date and time at which the message was sent.*/
    sent_time?: string;
    /**The JID of the group channel or user to whom the message was sent.*/
    to_jid?: string;
    /**The JID of the user on whose behalf the message is being sent. This is used to prevent members of a channel from getting notifications that were set up by a user who has left the channel.*/
    user_jid?: string;
};
type DeleteChatbotMessagePathParams = {
    message_id: string;
};
type DeleteChatbotMessageQueryParams = {
    account_id?: string;
    user_jid: string;
    robot_jid: string;
};
type DeleteChatbotMessageResponse = {
    /**The deleted message's ID.*/
    message_id?: string;
    /**The Bot JID. You can find this value in the **Feature** tab's **Chat Subscription** section of your Marketplace Chatbot app.*/
    robot_jid?: string;
    /**The date and time at which the message was deleted.*/
    sent_time?: string;
    /**The JID of the group channel or user to whom the message was sent.*/
    to_jid?: string;
    /**The JID of the user on whose behalf the message is being sent. This is used to prevent members of a channel from getting notifications that were set up by a user who has left the channel.*/
    user_jid?: string;
};
type LinkUnfurlsPathParams = {
    userId: string;
    triggerId: string;
};
type LinkUnfurlsRequestBody = {
    /**A JSON-format template that describes how the edited message should be displayed for the user. For more information, see the Chatbot [Customizing-Messages](https://developers.zoom.us/docs/team-chat-apps/customizing-messages/) documentation. */
    content: string;
};
declare class ChatbotEndpoints extends WebEndpoints {
    readonly messages: {
        /** Insert Send Docs here */
        sendChatbotMessage: (_: object & {
            body: SendChatbotMessagesRequestBody;
        }) => Promise<BaseResponse<object>>;
        editChatbotMessage: (_: {
            path: EditChatbotMessagePathParams;
        } & {
            body: EditChatbotMessageRequestBody;
        } & object) => Promise<BaseResponse<EditChatbotMessageResponse>>;
        deleteChatbotMessage: (_: {
            path: DeleteChatbotMessagePathParams;
        } & object & {
            query: DeleteChatbotMessageQueryParams;
        }) => Promise<BaseResponse<DeleteChatbotMessageResponse>>;
        linkUnfurls: (_: {
            path: LinkUnfurlsPathParams;
        } & {
            body: LinkUnfurlsRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
}

interface BotInstalledEvent extends Event<"bot_installed"> {
    payload: {
        accountId: string;
        robotJid: string;
        timestamp: number;
        userId: string;
        userJid: string;
        userName: string;
    };
}
interface BotNotification extends Event<"bot_notification"> {
    payload: {
        accountId: string;
        channelName: string;
        cmd: string;
        robotJid: string;
        timestamp: number;
        toJid: string;
        triggerId: string;
        userId: string;
        userJid: string;
        userName: string;
    };
}
interface InteractiveMessageActions extends Event<"interactive_message_actions"> {
    payload: {
        accountId: string;
        actionItem: {
            text: string;
            value: string;
        };
        channelName: string;
        messageId: string;
        original: CardContent;
        robotJid: string;
        timestamp: number;
        toJid: string;
        userId: string;
        userJid: string;
        userName: string;
    };
}
interface InteractiveMessageEditable extends Event<"interactive_message_editable"> {
    payload: {
        accountId: string;
        channelName: string;
        editItem: {
            origin: string;
            target: string;
        };
        messageId: string;
        original: CardContent;
        robotJid: string;
        timestamp: number;
        toJid: string;
        userId: string;
        userJid: string;
        userName: string;
    };
}
interface InteractiveMessageFieldsEditable extends Event<"interactive_message_fields_editable"> {
    payload: {
        accountId: string;
        channelName: string;
        fieldEditItem: {
            currentValue: string;
            key: string;
            newValue: string;
        };
        messageId: string;
        original: CardContent;
        robotJid: string;
        timestamp: number;
        toJid: string;
        userId: string;
        userJid: string;
        userName: string;
    };
}
interface InteractiveMessageSelect extends Event<"interactive_message_select"> {
    payload: {
        accountId: string;
        channelName: string;
        messageId: string;
        original: CardContent;
        robotJid: string;
        selectedItems: {
            value: string;
        }[];
        timestamp: number;
        toJid: string;
        userId: string;
        userJid: string;
        userName: string;
    };
}
interface TeamChatLinkShared extends Event<"team_chat.link_shared"> {
    event_ts: number;
    response_url: string;
    payload: {
        account_id: string;
        operator_id: string;
        operator: string;
        operator_member_id: string;
        by_external_user: boolean;
        object: {
            message_id: string;
            type: "to_contact" | "to_channel";
            channel_id: string;
            channel_name: string;
            contact_id: string;
            contact_member_id: string;
            trigger_id: string;
            link: string;
            reply_main_message_id: string;
            date_time: Date;
            timestamp: number;
        };
    };
}
type ChatbotEvents = BotInstalledEvent | BotNotification | InteractiveMessageActions | InteractiveMessageEditable | InteractiveMessageFieldsEditable | InteractiveMessageSelect | TeamChatLinkShared;
type CommandReplyContext = {
    say: (msg: string | CardContent) => Promise<Awaited<ReturnType<ChatbotEndpoints["messages"]["sendChatbotMessage"]>>>;
};
declare class ChatbotEventProcessor extends EventManager<ChatbotEndpoints, ChatbotEvents> {
    onSlashCommand(commandName: string | RegExp, listener: ReturnType<typeof this.withContext<"bot_notification", CommandReplyContext>>): void;
    onButtonClick(actionId: string, listener: ReturnType<typeof this.withContext<"interactive_message_actions", CommandReplyContext>>): void;
}

type ChatbotOptions<R extends Receiver> = CommonClientOptions<ClientCredentialsAuth, R>;
declare class ChatbotClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<ClientCredentialsAuth, ReceiverType> = ChatbotOptions<ReceiverType>> extends ProductClient<ClientCredentialsAuth, ChatbotEndpoints, ChatbotEventProcessor, OptionsType, ReceiverType> {
    protected initAuth({ clientId, clientSecret, tokenStore }: OptionsType): ClientCredentialsAuth;
    protected initEndpoints(auth: ClientCredentialsAuth, options: OptionsType): ChatbotEndpoints;
    protected initEventProcessor(endpoints: ChatbotEndpoints): ChatbotEventProcessor;
}

export { ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ChatbotClient, ChatbotEventProcessor, ClientCredentialsRawResponseError, CommonHttpRequestError, ConsoleLogger, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, LogLevel, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, ReceiverInconsistentStateError, ReceiverOAuthFlowError, S2SRawResponseError, StatusCode, isCoreError, isStateStore };
export type { Actions, Alert, Attachment, BotInstalledEvent, BotNotification, CardContent, ChannelSelect, ChatbotEvents, ChatbotOptions, CheckboxGroup, ClientCredentialsToken, CommandReplyContext, DatePicker, DeleteChatbotMessagePathParams, DeleteChatbotMessageQueryParams, DeleteChatbotMessageResponse, Divider, EditChatbotMessagePathParams, EditChatbotMessageRequestBody, EditChatbotMessageResponse, Fields, File, Footer, Header, HttpReceiverOptions, Input, InteractiveMessageActions, InteractiveMessageEditable, InteractiveMessageFieldsEditable, InteractiveMessageSelect, JwtToken, LinkUnfurlsPathParams, LinkUnfurlsRequestBody, Logger, MemberSelect, Message, MultipleImage, MultiplePages, OAuthToken, Progress, RadioGroup, Receiver, ReceiverInitOptions, S2SAuthToken, Sections, SendChatbotMessagesRequestBody, SendChatbotMessagesResponse, StateStore, StaticSelect, Style, SubHeader, SwitchGroup, TeamChatLinkShared, Textarea, TimePicker, TokenStore, VideoPlayer };
