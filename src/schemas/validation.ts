import { z } from "zod";

/**
 * Zod Schemas for Sanitizing and Validating EUDI Wallet Backend API Requests
 * Compatible with Zod v4. Prevents injection attacks, buffer overruns, and parameter pollution.
 */

const safeIdRegex = /^[a-zA-Z0-9_-]{1,128}$/;

// --------------------------------------------------------------------------
// WPB (Wallet Provider Backend) Schemas
// --------------------------------------------------------------------------
export const wpbRegisterSchema = z
  .object({
    pubKey: z
      .string()
      .min(10, { message: "Public key must be at least 10 characters" })
      .max(4096, { message: "Public key exceeds maximum length of 4096 characters" }),
    client_metadata: z.record(z.string(), z.unknown()).optional()
  })
  .strict();

export const wpbRevokeSchema = z
  .object({
    wpb_wi_revocation_code: z
      .string()
      .min(8, { message: "Revocation code too short" })
      .max(256, { message: "Revocation code exceeds 256 characters" })
      .regex(/^[a-zA-Z0-9_-]+$/, { message: "Revocation code contains illegal characters" })
  })
  .strict();

export const wpbAttestationSchema = z
  .object({
    wi_wia_pubk: z.string().max(4096, { message: "wi_wia_pubk exceeds maximum length" }).optional(),
    wpb_client_instance_id: z
      .string()
      .max(256)
      .regex(safeIdRegex, { message: "Client instance ID contains invalid characters" })
      .nullable()
      .optional(),
    attestation_type: z.string().max(64).optional()
  })
  .strict();

// --------------------------------------------------------------------------
// RWSCA (Remote WSCA) Schemas
// --------------------------------------------------------------------------
export const rwscaRegisterSchema = z
  .object({
    pubKey: z.string().max(4096).optional()
  })
  .strict();

export const rwscaPinInitSchema = z
  .object({
    wi_rwsca_pin_pubk: z
      .string()
      .min(8, { message: "PIN public key too short" })
      .max(4096, { message: "PIN public key too long" })
  })
  .strict();

export const rwscaCreateKeysSchema = z
  .object({
    number_of_keys: z
      .number()
      .int({ message: "number_of_keys must be an integer" })
      .min(1, { message: "number_of_keys must be at least 1" })
      .max(10, { message: "number_of_keys cannot exceed 10 keys per request" })
      .default(1),
    pp_c_nonce: z
      .string()
      .max(256)
      .regex(/^[a-zA-Z0-9_+\/=-]*$/, { message: "pp_c_nonce contains invalid characters" })
      .optional()
  })
  .strict();

export const rwscaSignDataSchema = z
  .object({
    rwsca_wi_wrapped_prvk: z
      .string()
      .min(1, { message: "Wrapped private key cannot be empty" })
      .max(16384, { message: "Wrapped private key exceeds maximum length" })
      .optional(),
    wi_key_binding_data_hash: z
      .string()
      .min(1, { message: "Key binding data hash cannot be empty" })
      .max(1024, { message: "Key binding data hash exceeds maximum length" })
      .optional(),
    data_to_sign: z.string().max(65536, { message: "Payload to sign exceeds 64KB" }).optional(),
    key_id: z.string().max(128).regex(safeIdRegex).optional()
  })
  .strict();

// --------------------------------------------------------------------------
// MDVM (Mobile Device Verification Management) Schemas
// --------------------------------------------------------------------------
export const mdvmRegisterSchema = z
  .object({
    wi_mdvm_auth_pubk: z
      .string()
      .max(4096)
      .optional(),
    wi_device_class: z
      .record(z.string(), z.unknown())
      .optional(),
    wi_android_key_attestation: z
      .union([z.array(z.string()), z.string()])
      .optional(),
    pap_devicecheck_attestation: z
      .string()
      .max(16384)
      .optional(),
    pap_devicecheck_assertion: z
      .string()
      .max(16384)
      .optional()
  })
  .strict();

export const mdvmRenewalSchema = z
  .object({
    wi_device_class: z
      .record(z.string(), z.unknown())
      .optional(),
    wi_android_key_attestation: z
      .union([z.array(z.string()), z.string()])
      .optional(),
    pap_devicecheck_assertion: z
      .string()
      .max(16384)
      .optional()
  })
  .strict();

// --------------------------------------------------------------------------
// PNS (Push Notifications Service) Schemas
// --------------------------------------------------------------------------
export const pnsRegisterSchema = z
  .object({
    mpp_registration_token: z
      .string()
      .min(10, { message: "MPP registration token too short" })
      .max(2048, { message: "MPP registration token exceeds 2048 characters" })
  })
  .strict();

// --------------------------------------------------------------------------
// Status Lists Path Sanitization Schema
// --------------------------------------------------------------------------
export const statusListParamsSchema = z
  .object({
    segment: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/, { message: "Invalid segment parameter" }),
    poolId: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/, { message: "Invalid poolId parameter" }),
    listId: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/, { message: "Invalid listId parameter" }).optional()
  })
  .strict();
