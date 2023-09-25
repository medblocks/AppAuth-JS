import {
  AuthorizationListener,
  AuthorizationNotifier,
  AuthorizationRequest,
  AuthorizationServiceConfiguration,
  BaseTokenRequestHandler,
  FetchRequestor,
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_REFRESH_TOKEN,
  RedirectRequestHandler,
  TokenRequest,
} from "./index";
import { LocalStorageBackend } from "./storage";
import decode from "jwt-decode";
import { SmartConfiguration } from "./smart_configuration";
import {
  AuthConfig,
  IdToken,
  SMARTContext,
  SMARTResponse,
} from "./medblocks_types";

const WELL_KNOWN_PATH = ".well-known";
const SMART_CONFIGURATION = "smart-configuration";

const STORAGE_PREFIX = "medblocks-auth-";
const ORIGINAL_URL_KEY = `${STORAGE_PREFIX}original-url-`;

const defaultRedirect = (originalUrl: string) => {
  window.history.replaceState({}, "", originalUrl);
};

// export const refreshToken = async (
//   clientId: string,
//   refreshToken: string,
//   redirectUri: string
// ) => {
//   const tokenHandler = new BaseTokenRequestHandler();
//   const tokenRequest = new TokenRequest({
//     client_id: clientId,
//     grant_type: GRANT_TYPE_REFRESH_TOKEN,
//     code: undefined,
//     refresh_token: refreshToken,
//     extras: undefined,
//     redirect_uri: redirectUri,
//   });
//   tokenHandler.performTokenRequest(configuration, tokenRequest);
// };

export const smartAuth = async ({
  clientId,
  iss,
  launch,
  redirectUri,
  scope,
  onRedirect = defaultRedirect,
  requestor = new FetchRequestor(),
  storage = new LocalStorageBackend(),
}: AuthConfig): Promise<SMARTResponse> => {
  /**
   * TO Implement:
   * - Refresh token automatically if available
   * - Cache token and return if it's valid - not expired, not patient scoped, has sufficient scopes, same issuer
   * - Cache smart configuration response - not expired, same issuer
   */

  const tokenHandler = new BaseTokenRequestHandler(requestor);
  const authorizationNotifier = new AuthorizationNotifier();
  const redirectHandler = new RedirectRequestHandler(storage);


  if(!iss){
    const _iss = await storage.getItem('ORIGINAL_ISS')
    if(_iss){
      iss = _iss
    }
  }
  else{
    await storage.setItem('ORIGINAL_ISS',iss)
  }

  const smartConfigurationResponse = await fetch(
    `${iss}/${WELL_KNOWN_PATH}/${SMART_CONFIGURATION}`
  );
  const smartConfigurationBody =
    (await smartConfigurationResponse.json()) as SmartConfiguration;

  const authorizationServiceConfig = new AuthorizationServiceConfiguration({
    authorization_endpoint: smartConfigurationBody.authorization_endpoint,
    token_endpoint: smartConfigurationBody.token_endpoint,
    revocation_endpoint: smartConfigurationBody.revocation_endpoint,
  });

  const authorizationListner: AuthorizationListener = async (req, res, err) => {
    if (err) {
      throw err;
    }
    if (res && req.internal) {
      const extras = {
        code_verifier: req.internal["code_verifier"],
      };
      const request = new TokenRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
        code: res.code,
        refresh_token: undefined,
        extras: extras,
      });
      const tokenResponse = await tokenHandler.performTokenRequest(
        authorizationServiceConfig,
        request
      );
      const idToken = tokenResponse?.idToken
        ? decode<IdToken>(tokenResponse.idToken)
        : undefined;
      const context: SMARTContext = {
        patient: tokenResponse.originalResponse?.patient,
        encounter: tokenResponse.originalResponse?.encounter,
        fhirUser: idToken?.fhirUser,
        smart_style_url: tokenResponse.originalResponse?.smart_style_url,
        need_patient_banner:
          tokenResponse.originalResponse?.need_patient_banner,
      };

      let services: Record<string, string> = {};
      Object.keys(smartConfigurationBody.services).forEach((key) => {
        services[key] = smartConfigurationBody.services[key].baseUrl;
      });

      const response: SMARTResponse = {
        accessToken: tokenResponse.accessToken,
        idToken,
        capabilities: smartConfigurationBody.capabilities,
        context,
        services,
      };
      const originalUrl = await storage.getItem(ORIGINAL_URL_KEY);
      onRedirect(originalUrl || redirectUri);
      return response;
    }
  };

  authorizationNotifier.setAuthorizationListener(authorizationListner);
  redirectHandler.setAuthorizationNotifier(authorizationNotifier);
  const token: SMARTResponse =
    await redirectHandler.completeAuthorizationRequestIfPossible();

  if (token) {
    return token;
  }

  const extras: Record<string, string> = {
    response_mode: "fragment",
  };

  if (launch) {
    extras["launch"] = launch;
  }
  await storage.setItem(ORIGINAL_URL_KEY, window.location.href);
  await redirectHandler.performAuthorizationRequest(
    authorizationServiceConfig,
    new AuthorizationRequest({
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scope,
      response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
      state: undefined,
      extras,
    })
  );

  return await new Promise(() => {});

  // Clear token if necessary

  // Check if smart-configuration is present and valid

  // Obtain smart-configuration from issuer

  // Store smart-configuration in storage

  // Initialize authorization request

  // Wait for redirect

  // Get code, and exchange for token

  // Store token

  // Format and return information
};

// export interface MedblocksTokenResponse extends TokenResponse {
//   patient: string | undefined;
//   encounter: string | undefined;
//   smart_style_url: string | undefined;
//   need_patient_banner: boolean | undefined;
// }

// export class MedblocksAuth {
//   private config: Config;
//   private notifier = new AuthorizationNotifier();
//   private authHandler = new RedirectRequestHandler();
//   private tokenHandler = new BaseTokenRequestHandler();
//   private authServiceConfig?: AuthorizationServiceConfiguration;
//   private storageBackend = new LocalStorageBackend();

//   public token?: MedblocksTokenResponse;

//   constructor(config: Config) {
//     this.config = config;
//     this.notifier.setAuthorizationListener(this.authListner);
//     this.authHandler.setAuthorizationNotifier(this.notifier);
//     if (config.onRedirect) {
//       this.onRedirect = config.onRedirect;
//     }
//   }

//   private authListner: AuthorizationListener = async (req, res) => {
//     if (res && req.internal) {
//       const extras: any = {};
//       extras["code_verifier"] = req.internal["code_verifier"];
//       const { client_id, redirect_uri } = this.config;
//       const request = new TokenRequest({
//         client_id,
//         redirect_uri,
//         grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
//         code: res.code,
//         refresh_token: undefined,
//         extras: extras,
//       });
//       if (this.authServiceConfig) {
//         const tokenResponse = await this.tokenHandler.performTokenRequest(
//           this.authServiceConfig,
//           request
//         );
//         const originalUrl = await this.storageBackend.getItem(ORIGINAL_URL_KEY);
//         this.onRedirect(originalUrl || redirect_uri);
//         return tokenResponse;
//       }
//     }
//   };

//   private authRequest = async () => {
//     const { client_id, redirect_uri } = this.config;
//     let request = new AuthorizationRequest({
//       client_id: client_id,
//       redirect_uri: redirect_uri,
//       scope: this.config.scope || "openid offline",
//       response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
//       state: undefined,
//       extras: { ...this.config.extra, response_mode: "fragment" },
//     });
//     if (this.authServiceConfig) {
//       this.storageBackend.setItem(ORIGINAL_URL_KEY, window.location.href);
//       await this.authHandler.performAuthorizationRequest(
//         this.authServiceConfig,
//         request
//       );
//       // Waits for the page to redirect and come back.
//       await new Promise((res) => {});
//     }
//   };

//   public revoke = (token: string) => {
//     if (this.authServiceConfig) {
//       this.tokenHandler.performRevokeTokenRequest(
//         this.authServiceConfig,
//         new RevokeTokenRequest({
//           token,
//           client_id: this.config.client_id,
//           token_type_hint: "access_token",
//         })
//       );
//     }
//   };

//   private getTokenFromSession = async (): Promise<
//     TokenResponse | undefined
//   > => {
//     const t = await this.storageBackend.getItem(TOKEN_KEY);
//     return t ? JSON.parse(t) : undefined;
//   };

//   private setTokenFromSession = async (token: TokenResponse): Promise<void> => {
//     return await this.storageBackend.setItem(TOKEN_KEY, JSON.stringify(token));
//   };

//   private onRedirect = (originalUrl: string) => {
//     window.history.replaceState({}, "", originalUrl);
//   };

//   // public isValid() {
//   //   if (!this.token) {
//   //     return false;
//   //   }
//   //   if (this.token.issuedAt + this.token?.expiresIn * 1000 < Date.now()) {
//   //   }
//   // }
//   /**
//    * Action to take upon being redirected back to the app.
//    * originalUrl - the url from which the app initiated the OAuth2 flow
//    */

//   public init = async (force: boolean = false): Promise<void> => {
//     // TODO: Get all endpoints from issuer
//     // If issuer invalid, throw error
//     const { authorization_endpoint, revocation_endpoint, token_endpoint } =
//       this.config;

//     // Create AuthorizationServiceConfiguration

//     // Also populate FHIR, openEHR and EHRScape endpoints from issuer smart-configuration
//     if (authorization_endpoint && revocation_endpoint && token_endpoint) {
//       this.authServiceConfig = new AuthorizationServiceConfiguration({
//         authorization_endpoint,
//         revocation_endpoint,
//         token_endpoint,
//       });
//     } else {
//       if (!this.config.issuer) {
//         throw new Error(
//           "issuer or (authorization_endpoint, revocation_endpoint & token_endpoint) must be provided."
//         );
//       }
//       this.authServiceConfig =
//         await AuthorizationServiceConfiguration.fetchFromIssuer(
//           this.config.issuer
//         );
//     }

//     // If forced or no token, or token expired, or token not sufficient, then initiate auth request
//     if (force) {
//       this.token = undefined;
//       await this.authRequest();
//     }

//     // else, assume it's coming from a redirect and process the token
//     const tokenFromRedirect =
//       await this.authHandler.completeAuthorizationRequestIfPossible();

//     if (tokenFromRedirect) {
//       await this.setTokenFromSession(tokenFromRedirect);
//     }

//     // This gets set incase the token is already retreived and it's valid.
//     this.token = tokenFromRedirect || (await this.getTokenFromSession());

//     if (!this.token) {
//       await this.authRequest();
//     }
//   };

//   public decodeIdToken() {
//     if (this.token?.idToken) {
//       return decode(this.token.idToken);
//     } else {
//       throw new Error("No token found");
//     }
//   }

//   public getFhirBaseUrl() {}

//   public getOpenEHRBaseUrl() {}

//   public getEhrScapeBaseUrl() {}

//   public registerAxiosInterceptor = (instance: AxiosInstance): void => {
//     instance.interceptors.request.use(
//       async (config) => {
//         if (!this.token) {
//           const msg =
//             "A request has been made before authentication has finished. Please wait for await init() to finish before making any requests. This request will be ignored.";
//           console.warn(msg, { axiosOptions: config });
//           return {
//             ...config,
//             cancelToken: new axios.CancelToken((cancel) => cancel(msg)),
//           };
//         }
//         config.headers = {
//           ...config.headers,
//           Authorization: `Bearer ${this.token?.accessToken}`,
//         };
//         return config;
//       },
//       (err: any) => Promise.reject(err)
//     );
//   };
// }
