/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_groupsession_free: (a: number, b: number) => void;
export const groupsession_new: () => number;
export const groupsession_session_id: (a: number) => [number, number];
export const groupsession_session_key: (a: number) => [number, number];
export const groupsession_message_index: (a: number) => number;
export const groupsession_encrypt: (a: number, b: number, c: number) => [number, number];
export const groupsession_pickle: (a: number, b: number, c: number) => [number, number, number, number];
export const groupsession_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
export const __wbg_decryptedmessage_free: (a: number, b: number) => void;
export const __wbg_get_decryptedmessage_plaintext: (a: number) => [number, number];
export const __wbg_set_decryptedmessage_plaintext: (a: number, b: number, c: number) => void;
export const __wbg_get_decryptedmessage_message_index: (a: number) => number;
export const __wbg_set_decryptedmessage_message_index: (a: number, b: number) => void;
export const __wbg_inboundgroupsession_free: (a: number, b: number) => void;
export const inboundgroupsession_new: (a: number, b: number) => [number, number, number];
export const inboundgroupsession_import: (a: number, b: number) => [number, number, number];
export const inboundgroupsession_session_id: (a: number) => [number, number];
export const inboundgroupsession_first_known_index: (a: number) => number;
export const inboundgroupsession_export_at: (a: number, b: number) => [number, number];
export const inboundgroupsession_decrypt: (a: number, b: number, c: number) => [number, number, number];
export const inboundgroupsession_pickle: (a: number, b: number, c: number) => [number, number, number, number];
export const inboundgroupsession_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
export const inboundgroupsession_from_libolm_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
export const __wbg_account_free: (a: number, b: number) => void;
export const __wbg_inboundcreationresult_free: (a: number, b: number) => void;
export const inboundcreationresult_session: (a: number) => number;
export const inboundcreationresult_plaintext: (a: number) => [number, number];
export const account_new: () => number;
export const account_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
export const account_from_libolm_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
export const account_pickle: (a: number, b: number, c: number) => [number, number, number, number];
export const account_ed25519_key: (a: number) => [number, number];
export const account_curve25519_key: (a: number) => [number, number];
export const account_sign: (a: number, b: number, c: number) => [number, number];
export const account_max_number_of_one_time_keys: (a: number) => number;
export const account_one_time_keys: (a: number) => [number, number, number];
export const account_generate_one_time_keys: (a: number, b: number) => void;
export const account_fallback_key: (a: number) => [number, number, number];
export const account_forget_fallback_key: (a: number) => number;
export const account_generate_fallback_key: (a: number) => void;
export const account_mark_keys_as_published: (a: number) => void;
export const account_create_outbound_session: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
export const account_create_inbound_session: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const __wbg_encryptedolmmessage_free: (a: number, b: number) => void;
export const __wbg_get_encryptedolmmessage_ciphertext: (a: number) => [number, number];
export const __wbg_set_encryptedolmmessage_ciphertext: (a: number, b: number, c: number) => void;
export const __wbg_get_encryptedolmmessage_message_type: (a: number) => number;
export const __wbg_set_encryptedolmmessage_message_type: (a: number, b: number) => void;
export const __wbg_session_free: (a: number, b: number) => void;
export const session_pickle: (a: number, b: number, c: number) => [number, number, number, number];
export const session_from_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
export const session_from_libolm_pickle: (a: number, b: number, c: number, d: number) => [number, number, number];
export const session_session_id: (a: number) => [number, number];
export const session_session_matches: (a: number, b: number, c: number, d: number) => number;
export const session_encrypt: (a: number, b: number, c: number) => number;
export const session_decrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const session_has_received_message: (a: number) => number;
export const __wbg_sas_free: (a: number, b: number) => void;
export const sas_new: () => number;
export const sas_public_key: (a: number) => [number, number];
export const sas_diffie_hellman: (a: number, b: number, c: number) => [number, number, number];
export const __wbg_establishedsas_free: (a: number, b: number) => void;
export const establishedsas_bytes: (a: number, b: number, c: number) => number;
export const establishedsas_calculate_mac: (a: number, b: number, c: number, d: number, e: number) => [number, number];
export const establishedsas_calculate_mac_invalid_base64: (a: number, b: number, c: number, d: number, e: number) => [number, number];
export const establishedsas_verify_mac: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
export const __wbg_sasbytes_free: (a: number, b: number) => void;
export const sasbytes_emoji_indices: (a: number) => [number, number];
export const sasbytes_decimals: (a: number) => [number, number];
export const verify_signature: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
export const main: () => void;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_export_2: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_start: () => void;
