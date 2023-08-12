import { StorageBackend } from "./storage";
import { TokenResponse } from "./token_response";
import { Requestor } from "./xhr";

export interface AuthConfig {
  iss: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  launch?: string;
  requestor?: Requestor;
  storage?: StorageBackend;
  onRedirect?: (originalUrl: string) => void;
}

export interface SMARTContext {
  patient?: string;
  encounter?: string;
  fhirUser?: string;
  need_patient_banner?: boolean;
  smart_style_url?: string;
  [key: string]: any;
}
export interface IdToken {
  [key: string]: any;
  fhirUser?: string;
  iss: string;
  iat: number;
  exp: number;
}
export interface SMARTResponse {
  accessToken: string;
  idToken?: IdToken;
  services: SMARTServices;
  context: SMARTContext;
  capabilities: string[];
}

interface SMARTServices {
  "org.fhir.rest"?: string;
  "org.openehr.rest"?: string;
  "org.medblocks.s3presignedurl"?: string;
  "org.dicomstandard.dicomweb.rest"?: string;
  [key: string]: string | undefined;
}
