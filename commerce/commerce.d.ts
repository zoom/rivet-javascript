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

type AccountManagementCreateEndCustomerAccountRequestBody = {
    account_name: string;
    employee_count: string;
    website: string;
    sub_reseller_crm_account_number?: string;
    contacts: {
        first_name: string;
        last_name: string;
        job_title: string;
        company_email: string;
        business_phone: string;
        primary_role?: string;
    }[];
    currency: string;
    billing_address: {
        line_1: string;
        city: string;
        postal_code: string;
        state: string;
        country: string;
    };
};
type AccountManagementCreateEndCustomerAccountResponse = {
    create_reference_id?: string;
    crm_account_number?: string;
    status?: string;
    status_detail?: string;
};
type AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountPathParams = {
    accountKey: string;
};
type AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountRequestBody = {
    contacts?: {
        first_name: string;
        last_name: string;
        job_title: string;
        company_email: string;
        business_phone: string;
        primary_role?: string;
    }[];
};
type AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountResponse = {
    create_reference_id?: string;
    crm_account_number?: string;
    status?: string;
    status_detail?: string;
};
type AccountManagementGetsListOfAllAccountsAssociatedWithZoomPartnerSubResellerByAccountTypeQueryParams = {
    relationship_type?: string;
    account_name?: string;
    crm_account_number?: string;
    zoom_account_number?: string;
    create_reference_id?: string;
    sub_reseller_crm_account_number?: string;
    sibling_crm_account_number?: string;
    page_size?: number;
    page_number?: number;
};
type AccountManagementGetsListOfAllAccountsAssociatedWithZoomPartnerSubResellerByAccountTypeResponse = {
    page_count?: number;
    account_list?: {
        create_reference_id?: string;
        crm_account_number?: string;
        account_name?: string;
        zoom_account_number?: string;
        account_type?: string;
        country?: string;
        currency?: string;
        website?: string;
    }[];
};
type AccountManagementGetAccountDetailsForZoomPartnerSubResellerEndCustomerPathParams = {
    accountKey: string;
};
type AccountManagementGetAccountDetailsForZoomPartnerSubResellerEndCustomerResponse = {
    crm_account_number?: string;
    create_reference_id?: string;
    status?: string;
    zoom_account_number?: string;
    account_name?: string;
    account_type?: string;
    created_on_date?: string;
    employee_count?: string;
    website?: string;
    currency?: string;
    contacts?: {
        contact_crm_number?: string;
        first_name: string;
        last_name: string;
        job_title: string;
        company_email: string;
        business_phone: string;
        primary_role?: string;
    }[];
    billing_address?: {
        line_1: string;
        line_2?: string;
        line_3?: string;
        city: string;
        postal_code?: string;
        state: string;
        country: string;
    };
};
type BillingGetsAllBillingDocumentsForDistributorOrResellerQueryParams = {
    document_type?: string;
    payment_status?: string;
    document_date_start?: string;
    document_date_end?: string;
    due_date?: string;
    document_number?: string;
    currency?: string;
    end_customer_name?: string;
    invoice_owner_crm_account_number?: string;
    page_size?: number;
    next_page_token?: string;
    sort?: string;
};
type BillingGetsAllBillingDocumentsForDistributorOrResellerResponse = {
    document_count?: number;
    billing_documents?: {
        document_number?: string;
        document_date?: string;
        document_type?: string;
        customer_name?: string[];
        sub_reseller_name?: string;
        invoice_owner_name?: string;
        due_date?: string;
        payment_status?: string;
        balance?: {
            amount?: number;
            currency?: string;
        };
        net_amount?: {
            amount?: number;
            currency?: string;
        };
        po_number?: string;
        billing_description?: string;
        posted_date?: string;
        reason_detail?: string;
        reference_billing_document_id?: string;
    }[];
    next_page_token?: string;
};
type BillingGetsPDFDocumentForBillingDocumentIDPathParams = {
    documentNumber: string;
};
type BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerPathParams = {
    invoiceNumber: string;
};
type BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerQueryParams = {
    zoom_account_number?: string;
    crm_account_number?: string;
};
type BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerResponse = {
    invoice_number?: string;
    invoice_date?: string;
    customer_name?: string[];
    invoice_owner_account?: {
        zoom_account_number?: string;
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    sub_reseller?: {
        zoom_account_number?: string;
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    sold_to_contact?: {
        crm_contact_number?: string;
        first_name?: string;
        last_name?: string;
        email?: string;
    };
    bill_to_contact?: {
        crm_contact_number?: string;
        first_name?: string;
        last_name?: string;
        email?: string;
    };
    due_date?: string;
    payment_status?: string;
    balance?: {
        amount?: number;
        currency?: string;
    };
    net_amount?: {
        amount?: number;
        currency?: string;
    };
    po_numbers?: string;
    billing_description?: string;
    posted_date?: string;
    reason_detail?: string;
    reference_billing_document_id?: string;
    total_tax_amount?: {
        amount?: number;
        currency?: string;
    };
    target_date?: object;
    invoice_items?: {
        end_customer_account?: {
            zoom_account_number?: string;
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
        };
        charge_name?: string;
        charge_type?: string;
        description?: string;
        offer_name?: string;
        offer_price_list_name?: string;
        start_date?: string;
        end_date?: string;
        subscription_number?: string;
        partner_sku_code?: string;
        po_number?: string;
        quantity?: number;
        tax_amount?: {
            amount?: number;
            currency?: string;
        };
        total_amount?: {
            amount?: number;
            currency?: string;
        };
    }[];
};
type DealRegistrationRetrievesAllValidZoomCampaignsWhichDealRegistrationCanBeAssociatedWithQueryParams = {
    end_customer_crm_account_number: string;
    sub_reseller_crm_account_number?: string;
    campaign_member_crm_contact_number: string;
    product_groups: string;
};
type DealRegistrationRetrievesAllValidZoomCampaignsWhichDealRegistrationCanBeAssociatedWithResponse = {
    campaigns?: {
        campaign_number: number;
        campaign_name?: string;
        campaign_description?: string;
        campaign_start_date?: string;
        campaign_end_date?: string;
    }[];
};
type DealRegistrationCreatesNewDealRegistrationForPartnerRequestBody = {
    opportunity_type: string;
    sub_reseller_crm_account_number?: string;
    sales_rep_contact_crm_number: string;
    partner_contacts?: {
        contact_crm_number?: string;
    }[];
    end_customer_crm_account_number: string;
    end_customer_contact_crm_number: string;
    end_customer_contacts?: {
        contact_crm_number?: string;
    }[];
    end_customer_department?: string[];
    met_decision_maker: boolean;
    decision_maker_crm_number?: string;
    budget_identified?: boolean;
    is_public_sector?: boolean;
    buy_gov_skus?: boolean;
    end_customer_industry: string;
    opportunity_name: string;
    opportunity_desc?: string;
    estimated_close_date: string;
    estimated_mrr: number;
    currency: string;
    requires_professional_services: boolean;
    professional_services_description?: string;
    phone_carrier?: string;
    product_groups: {
        name: string;
        quantity: number;
    }[];
    campaign_number?: string;
    sales_activities: {
        type: string;
        date: string;
    }[];
    rfp_details?: {
        is_rfp: boolean;
        rfp_link?: string;
        rfp_issue_date?: string;
        rfp_due_date?: string;
    };
    submitter_contact_crm_number?: string;
    migration_type?: string;
    additional_comments?: string;
};
type DealRegistrationCreatesNewDealRegistrationForPartnerResponse = {
    create_reference_id?: string;
    deal_reg_number?: string;
    status?: string;
    errors?: {
        error_code: string;
        error_description: string;
    }[];
};
type DealRegistrationGetsAllValidDealRegistrationsForPartnerQueryParams = {
    deal_reg_number?: string;
    create_reference_id?: string;
    end_customer_name?: string;
    end_customer_crm_account_number?: string;
    end_customer_zoom_account_number?: string;
    sub_reseller_name?: string;
    sub_reseller_crm_account_number?: string;
    invoice_owner_crm_account_number?: string;
    status: string;
    page_size?: number;
    page_number?: string;
};
type DealRegistrationGetsAllValidDealRegistrationsForPartnerResponse = {
    page_count?: number;
    deal_registrations?: {
        deal_reg_number?: string;
        create_reference_id?: string;
        deal_name?: string;
        invoice_owner_crm_account_number?: string;
        opportunity_stage?: string;
        submitted_date?: string;
        expected_closed_date?: string;
        estimated_mrr?: number;
        currency?: string;
        program_name?: string;
        original_expiry_date?: string;
        extended_expiry_date?: string;
        partner_sales_rep?: string;
        zoom_account_executive?: string;
        zoom_cam?: string;
        status?: string;
        end_customer?: {
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
            department?: string;
            industry?: string;
            account_local_name?: string;
            employee_count?: string;
            website?: string;
        };
        opportunity?: {
            opportunity_id?: string;
            opportunity_name?: string;
            opportunity_type?: string;
            expected_close_date?: string;
            partner_role?: string;
            channel_sales_motion?: string;
        };
    }[];
};
type DealRegistrationGetsDetailsForDealRegistrationByDealRegistrationNumberPathParams = {
    dealRegKey: string;
};
type DealRegistrationGetsDetailsForDealRegistrationByDealRegistrationNumberResponse = {
    deal_reg_number?: string;
    create_reference_id?: string;
    deal_name?: string;
    deal_description?: string;
    currency?: string;
    program_name?: string;
    opportunity_stage?: string;
    submitted_date?: string;
    approved_date?: string;
    denied_date?: string;
    expected_close_date?: string;
    partner_role?: string;
    original_expiry_date?: string;
    extended_expiry_date?: string;
    sales_representative?: {
        self_sales_representative?: boolean;
        sales_rep_contact?: {
            contact_crm_number: string;
            first_name?: string;
            last_name?: string;
            email?: string;
            title?: string;
            phone?: string;
        };
    };
    submitter?: {
        contact_crm_number: string;
        first_name?: string;
        last_name?: string;
        email?: string;
        title?: string;
        phone?: string;
    };
    related_partner?: string;
    partner_contacts?: {
        contact_crm_number: string;
        first_name?: string;
        last_name?: string;
        email?: string;
        title?: string;
        phone?: string;
    }[];
    is_existing_customer?: boolean;
    sub_reseller?: {
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    invoice_owner?: {
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    end_customer?: {
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
        department?: string;
        industry?: string;
        account_local_name?: string;
        employee_count?: string;
        website?: string;
    };
    end_customer_primary_contact?: {
        contact_crm_number: string;
        first_name?: string;
        last_name?: string;
        email?: string;
        title?: string;
        phone?: string;
        end_customer_contact_domain_reason?: string;
    };
    end_customer_other_contacts?: {
        contact_crm_number: string;
        first_name?: string;
        last_name?: string;
        email?: string;
        title?: string;
        phone?: string;
        end_customer_contact_domain_reason?: string;
    }[];
    end_customer_website_details?: {
        empty_website?: boolean;
        empty_website_reason?: string;
        public_website_reason?: string;
    };
    is_public_sector?: boolean;
    budget_identified?: boolean;
    buy_gov_skus?: boolean;
    met_decision_maker?: boolean;
    decision_maker_email?: string;
    decision_maker_name?: string;
    estimated_mrr?: number;
    requires_professional_services?: boolean;
    professional_services_description?: string;
    phone_carrier?: string;
    product_groups?: {
        name: string;
        quantity: number;
    }[];
    campaign?: string;
    sales_activities?: {
        sales_activity_number?: string;
        type: string;
        date: string;
    }[];
    rfp_details?: {
        is_rfp?: boolean;
        rfp_link?: string;
        issue_date?: string;
        due_date?: string;
    };
    zoom_cams?: {
        zoom_territory_cam?: string;
        zoom_named_cam?: string;
        zoom_distribution_cam?: string;
    };
    additional_comments?: string;
    opportunity?: {
        opportunity_number?: string;
        opportunity_name?: string;
        opportunity_type?: string;
        partner_role?: string;
        channel_sales_motion?: string;
        expected_close_date?: string;
    };
    status?: string;
    status_detail?: {
        return_reason?: string;
        revoke_reason?: string;
        denied_reason?: string;
        other_comments?: string;
    };
};
type DealRegistrationUpdatesExistingDealRegistrationPathParams = {
    dealRegKey: string;
};
type DealRegistrationUpdatesExistingDealRegistrationRequestBody = {
    sales_rep_contact_crm_number?: string;
    add_partner_contacts?: {
        contact_crm_number?: string;
    }[];
    add_end_customer_contacts?: {
        contact_crm_number?: string;
    }[];
    end_customer_department?: string[];
    met_decision_maker?: boolean;
    decision_maker_crm_number?: string;
    budget_identified?: boolean;
    is_public_sector?: boolean;
    buy_gov_skus?: boolean;
    end_customer_industry?: string;
    opportunity_name?: string;
    opportunity_desc?: string;
    estimated_close_date?: string;
    estimated_mrr?: number;
    currency?: string;
    requires_professional_services?: boolean;
    professional_services_description?: string;
    phone_carrier?: string;
    add_product_groups?: {
        name: string;
        quantity: number;
    }[];
    remove_product_groups?: {
        name: string;
    }[];
    campaign_number?: string;
    sales_activities?: {
        sales_activity_number?: string;
        type: string;
        date: string;
    }[];
    rfp_details?: {
        is_rfp: boolean;
        rfp_link?: string;
        issue_date?: string;
        due_date?: string;
    };
    submitter_contact_crm_number?: string;
    additional_comments?: string;
};
type OrderCreatesSubscriptionOrderForZoomPartnerRequestBody = {
    header: {
        order_type?: string;
        order_description?: string;
        deal_reg_number?: string;
        order_date: string;
        po_number?: string;
        additional_attributes?: {
            name?: string;
            value_type?: string;
            value?: string;
        }[];
    };
    create_subscriptions?: {
        end_customer_account_number?: string;
        end_customer_crm_account_number: string;
        sold_to_crm_contact_number: string;
        end_customer_language?: string;
        initial_term: {
            term_type: string;
            term_period?: number;
            start_date?: string;
            end_date?: string;
        };
        renewal_term?: {
            term_type: string;
            term_period?: number;
            start_date?: string;
            end_date?: string;
        };
        sub_reseller?: {
            crm_account_number?: string;
            account_name?: string;
        };
        service_start_date?: string;
        paid_period_start_date?: string;
        free_months_reason_code?: string;
        currency: string;
        auto_renew?: boolean;
        add_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        add_add_ons?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
    }[];
    amend_subscriptions?: {
        subscription_number?: string;
        zoom_account_number?: string;
        add_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        add_add_ons?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        upgrade_offers?: {
            new_offer_price_list_id?: string;
            new_partner_sku_code?: string;
            old_offer_price_list_id?: string;
            old_partner_sku_code?: string;
            quantity?: number;
            start_date: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        remove_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            end_date: string;
            remove_reason?: string;
        }[];
        update_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        cancel_subscription?: {
            cancel_by?: string;
            cancel_on?: string;
            cancel_reason: string;
        };
        renew_subscription?: {
            renewal_term?: {
                term_type: string;
                term_period?: number;
                start_date?: string;
                end_date?: string;
            };
        };
        update_subscription?: {
            auto_renew?: boolean;
            sold_to_crm_contact_number?: string;
            end_customer_language?: string;
        };
    }[];
};
type OrderCreatesSubscriptionOrderForZoomPartnerResponse = {
    status?: string;
    order_reference_id?: string;
    order_number?: string;
    order_date?: string;
    subscriptions?: {
        subscription_number?: string;
        zoom_account_number?: string;
        subscription_status?: string;
        subscription_owner_id?: string;
        invoice_owner_id?: string;
        invoice_owner_crm_account_number?: string;
    }[];
    errors?: {
        error_code: string;
        error_description: string;
    }[];
};
type OrderPreviewDeltaOrderMetricsAndSubscriptionsInOrderRequestBody = {
    header: {
        order_type?: string;
        order_description?: string;
        deal_reg_number?: string;
        order_date: string;
        po_number?: string;
        additional_attributes?: {
            name?: string;
            value?: string;
        }[];
    };
    create_subscriptions?: {
        end_customer_account_number?: string;
        end_customer_crm_account_number: string;
        sold_to_crm_contact_number: string;
        end_customer_language?: string;
        initial_term: {
            term_type: string;
            term_period?: number;
            start_date?: string;
            end_date?: string;
        };
        renewal_term?: {
            term_type: string;
            term_period?: number;
            start_date?: string;
            end_date?: string;
        };
        sub_reseller?: {
            crm_account_number?: string;
            account_name?: string;
        };
        service_start_date?: string;
        paid_period_start_date?: string;
        free_months_reason_code?: string;
        currency: string;
        auto_renew?: boolean;
        add_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        add_add_ons?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
    }[];
    amend_subscriptions?: {
        subscription_number?: string;
        zoom_account_number?: string;
        add_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        add_add_ons?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        upgrade_offers?: {
            new_offer_price_list_id?: string;
            new_partner_sku_code?: string;
            old_offer_price_list_id?: string;
            old_partner_sku_code?: string;
            quantity?: number;
            start_date: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        remove_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            end_date: string;
            remove_reason?: string;
        }[];
        update_offers?: {
            offer_price_list_id: string;
            partner_sku_code?: string;
            quantity?: number;
            start_date: string;
            offer_attributes?: {
                name?: string;
                value?: string;
            }[];
        }[];
        cancel_subscription?: {
            cancel_by?: string;
            cancel_on?: string;
            cancel_reason: string;
        };
        renew_subscription?: {
            renewal_term?: {
                term_type: string;
                term_period?: number;
                start_date?: string;
                end_date?: string;
            };
        };
        update_subscription?: {
            auto_renew?: boolean;
            sold_to_crm_contact_number?: string;
            end_customer_language?: string;
        };
    }[];
};
type OrderPreviewDeltaOrderMetricsAndSubscriptionsInOrderResponse = {
    status?: string;
    order_reference_id?: string;
    order_date?: string;
    order_metrics?: {
        tcv?: number;
        tcb?: number;
        mrr?: number;
        total_discount_pct?: number;
    };
    subscription_preview?: {
        subscription_number?: object;
        tcv?: number;
        tcb?: number;
        mrr?: number;
        total_discount_pct?: number;
    }[];
    subscription_item_metrics?: {
        offer_id?: string;
        offer_name?: string;
        sku?: string;
        offer_price_list_id?: string;
        offer_price_list_name?: string;
        charges?: {
            charge_model?: string;
            charge_type?: string;
            sale_price?: {
                amount?: number;
                currency?: string;
            };
            net_price?: {
                amount?: number;
                currency?: string;
            };
            net_amount?: {
                amount?: number;
                currency?: string;
            };
            discounts?: {
                discount_type: string;
                percent_value?: number;
                amount_value?: number;
                apply_to: string;
                discount_level: string;
            }[];
        }[];
        mrr?: {
            amount?: number;
            currency?: string;
        };
    }[];
    errors?: string[];
};
type OrderGetsAllOrdersForZoomPartnerQueryParams = {
    invoice_owner_crm_account_number?: string;
    page_size?: number;
    page_num?: string;
    date_filter_option?: string;
    from?: string;
    to?: string;
    order_type?: string;
    order_reference_id?: string;
    order_number?: string;
    po_number?: string;
    deal_reg_number?: string;
    end_customer_name?: string;
    end_customer_crm_account_number?: string;
    end_customer_zoom_account_number?: string;
    sub_reseller_name?: string;
    sub_reseller_crm_account_number?: string;
    status?: string;
    subscription_number?: string;
    sort?: string;
};
type OrderGetsAllOrdersForZoomPartnerResponse = {
    order_list?: {
        order_reference_id?: string;
        order_number?: string;
        status?: string;
        order_type?: string;
        invoice_owner_crm_account_number?: string;
        end_customer_account_name?: string;
        end_customer_account_number?: string;
        end_customer_crm_account_number?: string;
        sub_reseller_name?: string;
        sub_reseller_crm_account_number?: string;
        creation_date?: string;
        effective_date?: string;
        net_amount?: {
            amount?: number;
            currency?: string;
        };
        updated_date?: string;
        trade_screening?: boolean;
        deal_reg_number?: string;
        po_number?: string;
    }[];
};
type OrderGetsOrderDetailsByOrderReferenceIDPathParams = {
    orderReferenceId: string;
};
type OrderGetsOrderDetailsByOrderReferenceIDResponse = {
    header?: {
        order_reference_id?: string;
        order_type?: string;
        order_description?: string;
        status?: string;
        order_number?: string;
        deal_reg_number?: string;
        order_date: string;
        po_number?: string;
        trade_screening?: boolean;
        order_metrics?: {
            tcv?: number;
            tcb?: number;
            mrr?: number;
            total_discount_pct?: number;
        };
        additional_attributes?: {
            name?: string;
            value?: string;
        }[];
    };
    create_subscription?: {
        subscription_number?: string;
        end_customer_account?: {
            zoom_account_number?: string;
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
        };
        invoice_owner_account?: {
            zoom_account_number?: string;
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
        };
        sub_reseller?: {
            zoom_account_number?: string;
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
        };
        sold_to_contact?: {
            crm_contact_number?: string;
            first_name?: string;
            last_name?: string;
            email?: string;
        };
        bill_to_contact?: {
            crm_contact_number?: string;
            first_name?: string;
            last_name?: string;
            email?: string;
        };
        initial_term?: {
            term_type: string;
            period_type?: string;
            term_period?: number;
            start_date?: string;
            end_date?: string;
        };
        renewal_term?: {
            term_type: string;
            period_type?: string;
            term_period?: number;
            start_date?: string;
            end_date?: string;
        };
        agreement_dates?: {
            contract_effective_date?: string;
            service_activation_date?: string;
            customer_acceptance_date?: string;
        };
        sold_to_crm_contact_number?: string;
        end_customer_language?: string;
        payment_term?: string;
        service_start_date?: string;
        paid_period_start_date?: string;
        free_months_included?: boolean;
        free_months_reason_code?: string;
        auto_renew?: boolean;
        currency?: string;
        deal_reg_number?: string;
        po_number?: string;
        subscription_metrics?: {
            subscription_number?: string;
            tcv?: number;
            tcb?: number;
            mrr?: number;
            total_discount_pct?: number;
        };
        offers?: {
            offer_id?: string;
            offer_name?: string;
            sku?: string;
            offer_price_list_id?: string;
            partner_sku_code?: string;
            offer_price_list_name?: string;
            quantity?: number;
            start_date?: string;
            end_date?: string;
            charges?: {
                charge_model?: string;
                charge_type?: string;
                sale_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_amount?: {
                    amount?: number;
                    currency?: string;
                };
                discounts?: {
                    discount_type: string;
                    percent_value?: number;
                    amount_value?: number;
                    apply_to: string;
                    discount_level: string;
                }[];
            }[];
            usage_based_charge?: boolean;
        }[];
        add_ons?: {
            offer_id?: string;
            offer_name?: string;
            sku?: string;
            offer_price_list_id?: string;
            partner_sku_code?: string;
            offer_price_list_name?: string;
            quantity?: number;
            start_date?: string;
            end_date?: string;
            charges?: {
                charge_model?: string;
                charge_type?: string;
                sale_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_amount?: {
                    amount?: number;
                    currency?: string;
                };
                discounts?: {
                    discount_type: string;
                    percent_value?: number;
                    amount_value?: number;
                    apply_to: string;
                    discount_level: string;
                }[];
            }[];
            usage_based_charge?: boolean;
        }[];
    }[];
    amend_subscriptions?: {
        subscription_number?: string;
        end_customer_account?: {
            zoom_account_number?: string;
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
        };
        invoice_owner_account?: {
            zoom_account_number?: string;
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
        };
        sub_reseller?: {
            zoom_account_number?: string;
            crm_account_number?: string;
            account_name?: string;
            address?: {
                address_type: string;
                line_1: string;
                line_2?: string;
                line_3?: string;
                city: string;
                postal_code?: string;
                state: string;
                country: string;
            };
        };
        sold_to_contact?: {
            crm_account_number?: string;
            first_name?: string;
            last_name?: string;
            email?: string;
        };
        bill_to_contact?: {
            crm_account_number?: string;
            first_name?: string;
            last_name?: string;
            email?: string;
        };
        currency?: string;
        deal_reg_number?: string;
        po_number?: string;
        subscription_metrics?: {
            subscription_number?: string;
            tcv?: number;
            tcb?: number;
            mrr?: number;
            total_discount_pct?: number;
        };
        add_offers?: {
            offer_id?: string;
            offer_name?: string;
            sku?: string;
            offer_price_list_id?: string;
            partner_sku_code?: string;
            offer_price_list_name?: string;
            quantity?: number;
            start_date?: string;
            end_date?: string;
            charges?: {
                charge_model?: string;
                charge_type?: string;
                sale_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_amount?: {
                    amount?: number;
                    currency?: string;
                };
                discounts?: {
                    discount_type: string;
                    percent_value?: number;
                    amount_value?: number;
                    apply_to: string;
                    discount_level: string;
                }[];
            }[];
            usage_based_charge?: boolean;
        }[];
        add_add_ons?: {
            offer_id?: string;
            offer_name?: string;
            sku?: string;
            offer_price_list_id?: string;
            partner_sku_code?: string;
            offer_price_list_name?: string;
            quantity?: number;
            start_date?: string;
            end_date?: string;
            charges?: {
                charge_model?: string;
                charge_type?: string;
                sale_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_amount?: {
                    amount?: number;
                    currency?: string;
                };
                discounts?: {
                    discount_type: string;
                    percent_value?: number;
                    amount_value?: number;
                    apply_to: string;
                    discount_level: string;
                }[];
            }[];
            usage_based_charge?: boolean;
        }[];
        upgrade_offers?: {
            offer_id?: string;
            offer_name?: string;
            sku?: string;
            offer_price_list_id?: string;
            partner_sku_code?: string;
            offer_price_list_name?: string;
            old_offer_price_list_id?: string;
            old_partner_sku_code?: string;
            quantity?: number;
            start_date?: string;
            end_date?: string;
            charges?: {
                charge_model?: string;
                charge_type?: string;
                sale_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_amount?: {
                    amount?: number;
                    currency?: string;
                };
                discounts?: {
                    discount_type: string;
                    percent_value?: number;
                    amount_value?: number;
                    apply_to: string;
                    discount_level: string;
                }[];
            }[];
            usage_based_charge?: boolean;
        }[];
        remove_offers?: {
            offer_id?: string;
            offer_name?: string;
            sku?: string;
            offer_price_list_id?: string;
            partner_sku_code?: string;
            offer_price_list_name?: string;
            quantity?: number;
            start_date?: string;
            end_date?: string;
            charges?: {
                charge_model?: string;
                charge_type?: string;
                sale_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_amount?: {
                    amount?: number;
                    currency?: string;
                };
                discounts?: {
                    discount_type: string;
                    percent_value?: number;
                    amount_value?: number;
                    apply_to: string;
                    discount_level: string;
                }[];
            }[];
            usage_based_charge?: boolean;
        }[];
        update_offers?: {
            offer_id?: string;
            offer_name?: string;
            sku?: string;
            offer_price_list_id?: string;
            partner_sku_code?: string;
            offer_price_list_name?: string;
            quantity?: number;
            start_date?: string;
            end_date?: string;
            charges?: {
                charge_model?: string;
                charge_type?: string;
                sale_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_price?: {
                    amount?: number;
                    currency?: string;
                };
                net_amount?: {
                    amount?: number;
                    currency?: string;
                };
                discounts?: {
                    discount_type: string;
                    percent_value?: number;
                    amount_value?: number;
                    apply_to: string;
                    discount_level: string;
                }[];
            }[];
            usage_based_charge?: boolean;
        }[];
        cancel_subscription?: {
            cancel_by?: string;
            cancel_on?: string;
            cancel_reason?: string;
        };
        renew_subscription?: {
            renewal_term?: {
                term_type: string;
                period_type?: string;
                term_period?: number;
                start_date?: string;
                end_date?: string;
            };
        };
        update_subscription?: {
            auto_renew?: boolean;
            sold_to_crm_contact_number?: string;
            end_customer_language?: string;
        };
    }[];
    errors?: {
        error_code?: string;
        error_description?: string;
    }[];
};
type ProductCatalogGetsZoomProductCatalogForZoomPartnerRequestBody = {
    filter_options: {
        filter_by: string;
        filter_value: string;
        operand?: string;
    }[];
    eligibility_criteria?: {
        only_trial_eligible?: boolean;
        only_base_plans?: boolean;
        upgrade_offer_id?: string;
    };
};
type ProductCatalogGetsZoomProductCatalogForZoomPartnerResponse = {
    offers: {
        offer_id: string;
        offer_name: string;
        offer_desc?: string;
        offer_type?: string;
        z_product_category?: string;
        sku?: string;
        status?: string;
        start_date?: string;
        end_date?: string;
        offer_products?: {
            product_name?: string;
            product_id?: string;
            product_family_id?: string;
            product_family_name?: string;
            product_group_id?: string;
            product_group_name?: string;
            product_type?: string;
            sku?: string;
            product_features?: {
                feature_id?: string;
                name?: string;
                value_type?: string;
                value?: string;
                uom?: string;
            }[];
            price_list?: {
                price_list_id?: string;
                price_list_name?: string;
                prices?: {
                    price_list_charge_id?: string;
                    partner_sku_code?: string;
                    charge_type?: string;
                    charge_model?: string;
                    name?: string;
                    uom?: string;
                    amount?: number;
                    currency?: string;
                    region?: string;
                    country?: string;
                    min_unit_quantity?: number;
                    status?: string;
                    start_date?: string;
                    end_date?: string;
                    price_tiers?: {
                        partner_sku_code?: string;
                        lower?: number;
                        upper?: number;
                        price?: number;
                        apply_rule?: string;
                    }[];
                }[];
                start_date?: string;
                end_date?: string;
                billing_period?: string;
                status?: string;
                eccn_value?: string;
            }[];
        }[];
        offer_attributes?: {
            name?: string;
            uom?: string;
            value_type?: string;
            value?: string;
        }[];
        pricebook?: {
            price_list_id?: string;
            price_list_name?: string;
            prices?: {
                price_list_charge_id?: string;
                partner_sku_code?: string;
                charge_type?: string;
                charge_model?: string;
                name?: string;
                uom?: string;
                amount?: number;
                currency?: string;
                region?: string;
                country?: string;
                min_unit_quantity?: number;
                status?: string;
                start_date?: string;
                end_date?: string;
                price_tiers?: {
                    partner_sku_code?: string;
                    lower?: number;
                    upper?: number;
                    price?: number;
                    apply_rule?: string;
                }[];
            }[];
            start_date?: string;
            end_date?: string;
            billing_period?: string;
            status?: string;
            eccn_value?: string;
            pricebook_attributes?: {
                name?: string;
                value_type?: string;
                value?: string;
            }[];
        }[];
    }[];
};
type ProductCatalogGetsDetailsForZoomProductOrOfferPathParams = {
    offerId: number;
};
type ProductCatalogGetsDetailsForZoomProductOrOfferResponse = {
    offer_id: string;
    offer_name: string;
    offer_desc?: string;
    offer_type?: string;
    z_product_category?: string;
    sku?: string;
    status?: string;
    start_date?: string;
    end_date?: string;
    offer_products?: {
        product_name?: string;
        product_id?: string;
        product_family_id?: string;
        product_family_name?: string;
        product_group_id?: string;
        product_group_name?: string;
        product_type?: string;
        sku?: string;
        product_features?: {
            feature_id?: string;
            name?: string;
            value_type?: string;
            value?: string;
            uom?: string;
        }[];
        price_list?: {
            price_list_id?: string;
            price_list_name?: string;
            prices?: {
                price_list_charge_id?: string;
                partner_sku_code?: string;
                charge_type?: string;
                charge_model?: string;
                name?: string;
                uom?: string;
                amount?: number;
                currency?: string;
                region?: string;
                country?: string;
                min_unit_quantity?: number;
                status?: string;
                start_date?: string;
                end_date?: string;
                price_tiers?: {
                    partner_sku_code?: string;
                    lower?: number;
                    upper?: number;
                    price?: number;
                    apply_rule?: string;
                }[];
            }[];
            start_date?: string;
            end_date?: string;
            billing_period?: string;
            status?: string;
            eccn_value?: string;
        }[];
    }[];
    offer_attributes?: {
        name?: string;
        uom?: string;
        value_type?: string;
        value?: string;
    }[];
    pricebook?: {
        price_list_id?: string;
        price_list_name?: string;
        prices?: {
            price_list_charge_id?: string;
            partner_sku_code?: string;
            charge_type?: string;
            charge_model?: string;
            name?: string;
            uom?: string;
            amount?: number;
            currency?: string;
            country?: string;
            min_unit_quantity?: number;
            status?: string;
            start_date?: string;
            end_date?: string;
            price_tiers?: {
                partner_sku_code?: string;
                lower?: number;
                upper?: number;
                price?: number;
                apply_rule?: string;
            }[];
        }[];
        start_date?: string;
        end_date?: string;
        billing_period?: string;
        status?: string;
        eccn_value?: string;
        pricebook_attributes?: {
            name?: string;
            value_type?: string;
            value?: string;
        }[];
    }[];
};
type ProductCatalogGetsPricebookInDownloadableFileQueryParams = {
    currency?: string;
    file_type?: string;
};
type SubscriptionGetsSubscriptionsForZoomPartnerQueryParams = {
    page_size?: number;
    sort?: string;
    status?: string;
    start?: string;
    end?: string;
    duration?: string;
    end_customer_name?: string;
    end_customer_crm_account_number?: string;
    end_customer_zoom_account_number?: string;
    sub_reseller_name?: string;
    sub_reseller_crm_account_number?: string;
    subscription_number?: string;
    invoice_owner_crm_account_number?: string;
    next_page_token?: string;
};
type SubscriptionGetsSubscriptionsForZoomPartnerResponse = {
    next_page_token?: string;
    subscription_list?: {
        subscription_number?: string;
        subscription_status?: string;
        subscription_owner?: {
            crm_account_number?: string;
            account_name?: string;
            zoom_account_number?: string;
        };
        invoice_owner?: {
            crm_account_number?: string;
            account_name?: string;
            zoom_account_number?: string;
        };
        start_date?: string;
        end_date?: string;
        order_number?: string;
        sub_reseller_name?: string;
        sold_to_email?: string;
        mrr?: {
            gross_amount?: number;
            net_amount?: number;
            currency?: string;
        };
        auto_renew?: boolean;
        trade_screening?: boolean;
    }[];
};
type SubscriptionGetsSubscriptionDetailsForGivenSubscriptionNumberPathParams = {
    subscriptionNumber: string;
};
type SubscriptionGetsSubscriptionDetailsForGivenSubscriptionNumberResponse = {
    subscription_number?: string;
    status?: string;
    payment_term?: string;
    service_start_date?: string;
    paid_period_start_date?: string;
    free_months_included?: boolean;
    free_months_reason_code?: string;
    deal_reg_number?: string;
    po_number?: string;
    currency?: string;
    end_customer_account?: {
        zoom_account_number?: string;
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    invoice_owner_account?: {
        zoom_account_number?: string;
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    sub_reseller?: {
        zoom_account_number?: string;
        crm_account_number?: string;
        account_name?: string;
        address?: {
            address_type: string;
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    agreement_dates?: {
        contract_effective_date?: string;
        service_activation_date?: string;
        customer_acceptance_date?: string;
    };
    initial_term?: {
        term_type: string;
        period_type?: string;
        term_period?: number;
        start_date?: string;
        end_date?: string;
    };
    renewal_term?: {
        term_type: string;
        period_type?: string;
        term_period?: number;
        start_date?: string;
        end_date?: string;
    };
    current_term?: {
        term_type: string;
        period_type?: string;
        term_period?: number;
        start_date?: string;
        end_date?: string;
    };
    auto_renew?: boolean;
    start_date?: string;
    end_date?: string;
    invoice_separately?: boolean;
    contracted_mrr?: number;
    mrr?: {
        amount?: number;
        currency?: string;
    };
    bill_to?: {
        zoom_account_number?: string;
        crm_account_number?: string;
        account_name?: string;
        address?: {
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    sold_to?: {
        zoom_account_number?: string;
        crm_account_number?: string;
        account_name?: string;
        address?: {
            line_1: string;
            line_2?: string;
            line_3?: string;
            city: string;
            postal_code?: string;
            state: string;
            country: string;
        };
    };
    sold_to_contact?: {
        crm_contact_number?: string;
        first_name?: string;
        last_name?: string;
        email?: string;
    };
    bill_to_contact?: {
        crm_contact_number?: string;
        first_name?: string;
        last_name?: string;
        email?: string;
    };
    subscription_lines?: {
        offer_id?: string;
        offer_name?: string;
        sku?: string;
        offer_price_list_id?: string;
        offer_price_list_name?: string;
        quantity?: number;
        start_date?: string;
        end_date?: string;
        status?: string;
        charges?: {
            charge_model?: string;
            charge_type?: string;
            sale_price?: {
                amount?: number;
                currency?: string;
            };
            net_price?: {
                amount?: number;
                currency?: string;
            };
            net_amount?: {
                amount?: number;
                currency?: string;
            };
            discounts?: {
                discount_type: string;
                percent_value?: number;
                amount_value?: number;
                apply_to: string;
                discount_level: string;
            }[];
        }[];
        offer_attributes?: {
            name?: string;
            uom?: string;
            value_type?: string;
            value?: string;
        }[];
    }[];
    created_date?: string;
    updated_date?: string;
};
type SubscriptionGetsSubscriptionChangesVersionsForGivenSubscriptionNumberPathParams = {
    subscriptionNumber: string;
};
type SubscriptionGetsSubscriptionChangesVersionsForGivenSubscriptionNumberResponse = {
    subscription_number?: string;
    status?: string;
    start_date?: string;
    end_date?: string;
    subscription_versions?: {
        sequence?: number;
        version?: number;
        latest_version?: boolean;
        action?: string[];
        start_date?: string;
        end_date?: string;
        mrr?: number;
        currency?: string;
    }[];
};
declare class CommerceEndpoints extends WebEndpoints {
    readonly accountManagement: {
        createEndCustomerAccount: (_: object & {
            body: AccountManagementCreateEndCustomerAccountRequestBody;
        }) => Promise<BaseResponse<AccountManagementCreateEndCustomerAccountResponse>>;
        addContactsToExistingEndCustomerOrYourOwnAccount: (_: {
            path: AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountPathParams;
        } & {
            body?: AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountRequestBody;
        } & object) => Promise<BaseResponse<AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountResponse>>;
        getsListOfAllAccountsAssociatedWithZoomPartnerSubResellerByAccountType: (_: object & {
            query?: AccountManagementGetsListOfAllAccountsAssociatedWithZoomPartnerSubResellerByAccountTypeQueryParams;
        }) => Promise<BaseResponse<AccountManagementGetsListOfAllAccountsAssociatedWithZoomPartnerSubResellerByAccountTypeResponse>>;
        getAccountDetailsForZoomPartnerSubResellerEndCustomer: (_: {
            path: AccountManagementGetAccountDetailsForZoomPartnerSubResellerEndCustomerPathParams;
        } & object) => Promise<BaseResponse<AccountManagementGetAccountDetailsForZoomPartnerSubResellerEndCustomerResponse>>;
    };
    readonly billing: {
        getsAllBillingDocumentsForDistributorOrReseller: (_: object & {
            query?: BillingGetsAllBillingDocumentsForDistributorOrResellerQueryParams;
        }) => Promise<BaseResponse<BillingGetsAllBillingDocumentsForDistributorOrResellerResponse>>;
        getsPDFDocumentForBillingDocumentID: (_: {
            path: BillingGetsPDFDocumentForBillingDocumentIDPathParams;
        } & object) => Promise<BaseResponse<unknown>>;
        getDetailedInformationAboutSpecificInvoiceForDistributorOrReseller: (_: {
            path: BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerPathParams;
        } & object & {
            query?: BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerQueryParams;
        }) => Promise<BaseResponse<BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerResponse>>;
    };
    readonly dealRegistration: {
        retrievesAllValidZoomCampaignsWhichDealRegistrationCanBeAssociatedWith: (_: object & {
            query: DealRegistrationRetrievesAllValidZoomCampaignsWhichDealRegistrationCanBeAssociatedWithQueryParams;
        }) => Promise<BaseResponse<DealRegistrationRetrievesAllValidZoomCampaignsWhichDealRegistrationCanBeAssociatedWithResponse>>;
        createsNewDealRegistrationForPartner: (_: object & {
            body: DealRegistrationCreatesNewDealRegistrationForPartnerRequestBody;
        }) => Promise<BaseResponse<DealRegistrationCreatesNewDealRegistrationForPartnerResponse>>;
        getsAllValidDealRegistrationsForPartner: (_: object & {
            query: DealRegistrationGetsAllValidDealRegistrationsForPartnerQueryParams;
        }) => Promise<BaseResponse<DealRegistrationGetsAllValidDealRegistrationsForPartnerResponse>>;
        getsDetailsForDealRegistrationByDealRegistrationNumber: (_: {
            path: DealRegistrationGetsDetailsForDealRegistrationByDealRegistrationNumberPathParams;
        } & object) => Promise<BaseResponse<DealRegistrationGetsDetailsForDealRegistrationByDealRegistrationNumberResponse>>;
        updatesExistingDealRegistration: (_: {
            path: DealRegistrationUpdatesExistingDealRegistrationPathParams;
        } & {
            body?: DealRegistrationUpdatesExistingDealRegistrationRequestBody;
        } & object) => Promise<BaseResponse<unknown>>;
    };
    readonly order: {
        createsSubscriptionOrderForZoomPartner: (_: object & {
            body: OrderCreatesSubscriptionOrderForZoomPartnerRequestBody;
        }) => Promise<BaseResponse<OrderCreatesSubscriptionOrderForZoomPartnerResponse>>;
        previewDeltaOrderMetricsAndSubscriptionsInOrder: (_: object & {
            body: OrderPreviewDeltaOrderMetricsAndSubscriptionsInOrderRequestBody;
        }) => Promise<BaseResponse<OrderPreviewDeltaOrderMetricsAndSubscriptionsInOrderResponse>>;
        getsAllOrdersForZoomPartner: (_: object & {
            query?: OrderGetsAllOrdersForZoomPartnerQueryParams;
        }) => Promise<BaseResponse<OrderGetsAllOrdersForZoomPartnerResponse>>;
        getsOrderDetailsByOrderReferenceID: (_: {
            path: OrderGetsOrderDetailsByOrderReferenceIDPathParams;
        } & object) => Promise<BaseResponse<OrderGetsOrderDetailsByOrderReferenceIDResponse>>;
    };
    readonly productCatalog: {
        getsZoomProductCatalogForZoomPartner: (_: object & {
            body: ProductCatalogGetsZoomProductCatalogForZoomPartnerRequestBody;
        }) => Promise<BaseResponse<ProductCatalogGetsZoomProductCatalogForZoomPartnerResponse>>;
        getsDetailsForZoomProductOrOffer: (_: {
            path: ProductCatalogGetsDetailsForZoomProductOrOfferPathParams;
        } & object) => Promise<BaseResponse<ProductCatalogGetsDetailsForZoomProductOrOfferResponse>>;
        getsPricebookInDownloadableFile: (_: object & {
            query?: ProductCatalogGetsPricebookInDownloadableFileQueryParams;
        }) => Promise<BaseResponse<unknown>>;
    };
    readonly subscription: {
        getsSubscriptionsForZoomPartner: (_: object & {
            query?: SubscriptionGetsSubscriptionsForZoomPartnerQueryParams;
        }) => Promise<BaseResponse<SubscriptionGetsSubscriptionsForZoomPartnerResponse>>;
        getsSubscriptionDetailsForGivenSubscriptionNumber: (_: {
            path: SubscriptionGetsSubscriptionDetailsForGivenSubscriptionNumberPathParams;
        } & object) => Promise<BaseResponse<SubscriptionGetsSubscriptionDetailsForGivenSubscriptionNumberResponse>>;
        getsSubscriptionChangesVersionsForGivenSubscriptionNumber: (_: {
            path: SubscriptionGetsSubscriptionChangesVersionsForGivenSubscriptionNumberPathParams;
        } & object) => Promise<BaseResponse<SubscriptionGetsSubscriptionChangesVersionsForGivenSubscriptionNumberResponse>>;
    };
}

type CommerceS2SAuthOptions<R extends Receiver> = CommonClientOptions<S2SAuth, R>;
declare class CommerceS2SAuthClient<ReceiverType extends Receiver = HttpReceiver, OptionsType extends CommonClientOptions<S2SAuth, ReceiverType> = CommerceS2SAuthOptions<ReceiverType>> extends ProductClient<S2SAuth, CommerceEndpoints, never, OptionsType, ReceiverType> {
    protected initAuth({ accountId, clientId, clientSecret, tokenStore }: OptionsType): S2SAuth;
    protected initEndpoints(auth: S2SAuth, options: OptionsType): CommerceEndpoints;
    protected initEventProcessor(): never;
}

export { ApiResponseError, AwsLambdaReceiver, AwsReceiverRequestError, ClientCredentialsRawResponseError, CommerceEndpoints, CommerceS2SAuthClient, CommonHttpRequestError, ConsoleLogger, HTTPReceiverConstructionError, HTTPReceiverPortNotNumberError, HTTPReceiverRequestError, HttpReceiver, LogLevel, OAuthInstallerNotInitializedError, OAuthStateVerificationFailedError, OAuthTokenDoesNotExistError, OAuthTokenFetchFailedError, OAuthTokenRawResponseError, OAuthTokenRefreshFailedError, ProductClientConstructionError, ReceiverInconsistentStateError, ReceiverOAuthFlowError, S2SRawResponseError, StatusCode, isCoreError, isStateStore };
export type { AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountPathParams, AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountRequestBody, AccountManagementAddContactsToExistingEndCustomerOrYourOwnAccountResponse, AccountManagementCreateEndCustomerAccountRequestBody, AccountManagementCreateEndCustomerAccountResponse, AccountManagementGetAccountDetailsForZoomPartnerSubResellerEndCustomerPathParams, AccountManagementGetAccountDetailsForZoomPartnerSubResellerEndCustomerResponse, AccountManagementGetsListOfAllAccountsAssociatedWithZoomPartnerSubResellerByAccountTypeQueryParams, AccountManagementGetsListOfAllAccountsAssociatedWithZoomPartnerSubResellerByAccountTypeResponse, BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerPathParams, BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerQueryParams, BillingGetDetailedInformationAboutSpecificInvoiceForDistributorOrResellerResponse, BillingGetsAllBillingDocumentsForDistributorOrResellerQueryParams, BillingGetsAllBillingDocumentsForDistributorOrResellerResponse, BillingGetsPDFDocumentForBillingDocumentIDPathParams, ClientCredentialsToken, CommerceS2SAuthOptions, DealRegistrationCreatesNewDealRegistrationForPartnerRequestBody, DealRegistrationCreatesNewDealRegistrationForPartnerResponse, DealRegistrationGetsAllValidDealRegistrationsForPartnerQueryParams, DealRegistrationGetsAllValidDealRegistrationsForPartnerResponse, DealRegistrationGetsDetailsForDealRegistrationByDealRegistrationNumberPathParams, DealRegistrationGetsDetailsForDealRegistrationByDealRegistrationNumberResponse, DealRegistrationRetrievesAllValidZoomCampaignsWhichDealRegistrationCanBeAssociatedWithQueryParams, DealRegistrationRetrievesAllValidZoomCampaignsWhichDealRegistrationCanBeAssociatedWithResponse, DealRegistrationUpdatesExistingDealRegistrationPathParams, DealRegistrationUpdatesExistingDealRegistrationRequestBody, HttpReceiverOptions, JwtToken, Logger, OAuthToken, OrderCreatesSubscriptionOrderForZoomPartnerRequestBody, OrderCreatesSubscriptionOrderForZoomPartnerResponse, OrderGetsAllOrdersForZoomPartnerQueryParams, OrderGetsAllOrdersForZoomPartnerResponse, OrderGetsOrderDetailsByOrderReferenceIDPathParams, OrderGetsOrderDetailsByOrderReferenceIDResponse, OrderPreviewDeltaOrderMetricsAndSubscriptionsInOrderRequestBody, OrderPreviewDeltaOrderMetricsAndSubscriptionsInOrderResponse, ProductCatalogGetsDetailsForZoomProductOrOfferPathParams, ProductCatalogGetsDetailsForZoomProductOrOfferResponse, ProductCatalogGetsPricebookInDownloadableFileQueryParams, ProductCatalogGetsZoomProductCatalogForZoomPartnerRequestBody, ProductCatalogGetsZoomProductCatalogForZoomPartnerResponse, Receiver, ReceiverInitOptions, S2SAuthToken, StateStore, SubscriptionGetsSubscriptionChangesVersionsForGivenSubscriptionNumberPathParams, SubscriptionGetsSubscriptionChangesVersionsForGivenSubscriptionNumberResponse, SubscriptionGetsSubscriptionDetailsForGivenSubscriptionNumberPathParams, SubscriptionGetsSubscriptionDetailsForGivenSubscriptionNumberResponse, SubscriptionGetsSubscriptionsForZoomPartnerQueryParams, SubscriptionGetsSubscriptionsForZoomPartnerResponse, TokenStore };
