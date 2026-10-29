// Generated from tokenator-core (feature `ts`) by tools/ts-bindings.
// Do not edit: run `pnpm gen:types` in app/.

export type Bytes = string;

export type NodeId = string;

export type TextRange = {
  /**
   * First code unit.
   */
  start: number;
  /**
   * One past the last code unit.
   */
  end: number;
  /**
   * First line.
   */
  line_start: number;
  /**
   * One past the last line.
   */
  line_end: number;
};

export type ByteRange = {
  /**
   * First byte.
   */
  start: number;
  /**
   * One past the last byte.
   */
  end: number;
};

export type RawRange = {
  /**
   * First byte.
   */
  start: number;
  /**
   * One past the last byte.
   */
  end: number;
  /**
   * First row (hex row or segment index).
   */
  row_start: number;
  /**
   * One past the last row.
   */
  row_end: number;
};

export type Nonce =
  | {
      type: 'text';
      /**
       * The text.
       */
      value: string;
    }
  | {
      type: 'bytes';
      /**
       * The bytes.
       */
      value: Bytes;
    };

export type KidValue =
  | {
      type: 'text';
      /**
       * The text.
       */
      value: string;
    }
  | {
      type: 'bytes';
      /**
       * The bytes.
       */
      value: Bytes;
    };

export type HashName = 'sha256' | 'sha384' | 'sha512';

export type Kind =
  | { type: 'jwt' }
  | { type: 'jws_compact' }
  | {
      type: 'sd_jwt';
      /**
       * Has a KB-JWT.
       */
      kb: boolean;
    }
  | {
      type: 'jws_json';
      /**
       * General rather than flattened.
       */
      general: boolean;
    }
  | {
      type: 'sd_jwt_json';
      /**
       * General rather than flattened.
       */
      general: boolean;
      /**
       * Has a KB-JWT.
       */
      kb: boolean;
    }
  | { type: 'cose_sign1' }
  | { type: 'cwt' }
  | { type: 'sd_cwt' }
  | { type: 'sd_kbt' }
  | { type: 'json_claims' }
  | { type: 'cbor_claims' }
  | { type: 'edn_claims' }
  | { type: 'jwk' }
  | { type: 'jwk_set' }
  | { type: 'cose_key' }
  | { type: 'cose_key_set' }
  | {
      type: 'pem';
      /**
       * Block labels in order.
       */
      labels: Array<string>;
    };

export type Family = 'jose' | 'cose';

export type Layer =
  | {
      type: 'trim';
      /**
       * Before the content.
       */
      leading: string;
      /**
       * After the content.
       */
      trailing: string;
    }
  | {
      type: 'quotes';
      /**
       * The quote character.
       */
      quote: string;
    }
  | {
      type: 'authorization_header';
      /**
       * The exact text removed.
       */
      prefix: string;
    }
  | {
      type: 'bearer_prefix';
      /**
       * The exact text removed.
       */
      prefix: string;
    }
  | { type: 'url_encoded' }
  | {
      type: 'json_field';
      /**
       * Path from the root to the string.
       */
      path: Array<JsonPathSegment>;
    }
  | {
      type: 'base64_url';
      /**
       * `=` padding.
       */
      padded: boolean;
      /**
       * Line length if wrapped.
       */
      wrap: number | null;
    }
  | {
      type: 'base64_std';
      /**
       * `=` padding.
       */
      padded: boolean;
      /**
       * Line length if wrapped.
       */
      wrap: number | null;
    }
  | {
      type: 'hex';
      /**
       * Upper-case digits.
       */
      upper: boolean;
      /**
       * Byte separator (`' '` or `':'`).
       */
      separator: string | null;
      /**
       * Bytes per line if wrapped.
       */
      wrap: number | null;
    }
  | {
      type: 'cbor_tag';
      /**
       * Tag number.
       */
      tag: number;
    }
  | { type: 'edn' };

export type JsonPathSegment = string | number;

export type Candidate = {
  /**
   * Classification.
   */
  kind: Kind;
  /**
   * 0..=100; only the order matters.
   */
  confidence: number;
  /**
   * Unwrapping steps, outermost first.
   */
  layers: Array<Layer>;
  /**
   * Bytes of the input the first decoding layer operates on.
   */
  payload_range: ByteRange;
  /**
   * Display breadcrumb: one entry per shown layer, then `kind.label()`.
   */
  breadcrumb: Array<string>;
};

export type Document = {
  /**
   * What it is.
   */
  kind: Kind;
  /**
   * Outer transport layers around `bytes`, outermost first (never the
   * COSE tags, which stay in `bytes`). Empty for derived documents.
   */
  layers: Array<Layer>;
  /**
   * The credential bytes (token text, CBOR item with tags, claim set).
   */
  bytes: Bytes;
  /**
   * Whether the kind carries a signature.
   */
  signed: boolean;
  /**
   * Signed content changed without re-signing.
   */
  signature_stale: boolean;
  /**
   * The node tree (root id `""`).
   */
  tree: Node;
  /**
   * The main pane.
   */
  main: Rendered;
  /**
   * The raw pane.
   */
  raw: RawView;
  /**
   * SD disclosures in input order (empty when not SD).
   */
  disclosures: Array<DisclosureInfo>;
  /**
   * Digest slots no disclosure fills (decoys or withheld claims).
   */
  undisclosed: Array<SlotInfo>;
  /**
   * Parse problems and warnings.
   */
  diagnostics: Array<Diagnostic>;
};

export type Rendered = {
  /**
   * JSON for JOSE and JSON claim sets, EDN otherwise.
   */
  language: Language;
  /**
   * The text.
   */
  text: string;
  /**
   * Number of lines (`text.lines()`, at least 1).
   */
  line_count: number;
};

export type Language = 'json' | 'edn';

export type Node = {
  /**
   * Path-based id (`TEST-PLAN.md` §4).
   */
  id: NodeId;
  /**
   * What the node is.
   */
  kind: NodeKind;
  /**
   * Short tree label: part name, member name, CBOR key EDN, or index.
   */
  label: string;
  /**
   * Registry annotation of the key (or of the value, for registered
   * values such as `alg`).
   */
  annotation: Annotation | null;
  /**
   * Range in the main pane.
   */
  main: TextRange | null;
  /**
   * Range in the raw pane.
   */
  raw: RawRange | null;
  /**
   * For a map entry: the key's node (id ending in `~k`).
   */
  key: Node | null;
  /**
   * Human-readable time for time-valued nodes.
   */
  time: TimeHint | null;
  /**
   * SD role of the node.
   */
  sd: SdMark | null;
  /**
   * Children in arrival order.
   */
  children: Array<Node>;
};

export type NodeKind =
  | 'document'
  | 'part'
  | 'decoded'
  | 'map'
  | 'array'
  | 'text'
  | 'bytes'
  | 'integer'
  | 'float'
  | 'number'
  | 'bool'
  | 'null'
  | 'undefined'
  | 'simple'
  | 'tag';

export type Annotation = {
  /**
   * Registered name (`kid`, `iss`, `cnf`).
   */
  name: string;
  /**
   * Registered description.
   */
  description: string;
  /**
   * Name of a registered value (`ES256` for alg `-7`).
   */
  value_name: string | null;
  /**
   * Specification references (`display_text()`, no draft revisions).
   */
  spec: Array<SpecLink>;
};

export type SpecLink = {
  /**
   * `RFC 7519, Section 4.1.1`, `draft-ietf-spice-sd-cwt, Section 3`.
   */
  text: string;
  /**
   * Link with the exact revision.
   */
  url: string | null;
};

export type TimeHint = {
  /**
   * Whole epoch seconds (floor).
   */
  epoch: number;
  /**
   * RFC 3339 in UTC.
   */
  rfc3339: string;
  /**
   * Relative to `ViewOptions.now`, when given (`"in 3 h 12 m"`).
   */
  relative: string | null;
};

export type SdMark =
  | {
      type: 'slot';
      /**
       * The digest (base64url for JOSE, hex for COSE).
       */
      digest: string;
      /**
       * Index into `Document.disclosures`.
       */
      disclosure: number | null;
    }
  | { type: 'digest_list' }
  | {
      type: 'disclosure';
      /**
       * Index into `Document.disclosures`.
       */
      index: number;
    };

export type DisclosureInfo = {
  /**
   * Input order index.
   */
  index: number;
  /**
   * The disclosure's node.
   */
  node_id: NodeId;
  /**
   * Digest (base64url for JOSE, hex for COSE).
   */
  digest: string;
  /**
   * Salt (the string for JOSE, hex for COSE).
   */
  salt: string;
  /**
   * Claim name (JOSE) or key as compact EDN (COSE); `None` for array
   * elements and decoys.
   */
  claim: string | null;
  /**
   * The value as compact JSON / EDN (empty for decoys).
   */
  value: string;
  /**
   * A COSE decoy disclosure (`[salt]`).
   */
  decoy: boolean;
  /**
   * Matching result.
   */
  status: DisclosureStatus;
  /**
   * The digest slot it fills.
   */
  slot: NodeId | null;
};

export type DisclosureStatus =
  | 'matched'
  | 'unmatched'
  | 'duplicate'
  | 'malformed'
  | 'forbidden_name'
  | 'kind_mismatch'
  | 'name_collision';

export type SlotInfo = {
  /**
   * The slot's node.
   */
  node_id: NodeId;
  /**
   * The digest.
   */
  digest: string;
  /**
   * An array element slot rather than a claim slot.
   */
  array_element: boolean;
};

export type Diagnostic = {
  /**
   * How bad.
   */
  severity: Severity;
  /**
   * Stable dotted code (`jose.base64`, `cbor.trailing_bytes`, …).
   */
  code: string;
  /**
   * Human-readable text.
   */
  message: string;
  /**
   * The node concerned.
   */
  node_id: NodeId | null;
  /**
   * Where in the main pane (for edit errors, the error position).
   */
  main: TextRange | null;
  /**
   * Where in the raw pane buffer.
   */
  raw: ByteRange | null;
};

export type Severity = 'info' | 'warning' | 'error';

export type RawView =
  | {
      type: 'hex';
      /**
       * The buffer the rows index.
       */
      bytes: Bytes;
      /**
       * Rows in byte order.
       */
      rows: Array<HexRow>;
    }
  | {
      type: 'segments';
      /**
       * Segments in token order.
       */
      segments: Array<Segment>;
    }
  | { type: 'none' };

export type HexRow = {
  /**
   * The node the row belongs to (`""` for envelope tag heads).
   */
  node_id: NodeId;
  /**
   * Item or break.
   */
  kind: HexRowKind;
  /**
   * Indentation depth.
   */
  depth: number;
  /**
   * Head bytes (whole item for scalars).
   */
  head: ByteRange;
  /**
   * Content bytes of a definite string (empty at `head.end` otherwise).
   */
  payload: ByteRange;
  /**
   * `unsigned(1)`, `bytes(4)`, `map(2)`, `break`, …
   */
  description: string;
  /**
   * Registry comment.
   */
  comment: string | null;
};

export type HexRowKind = 'item' | 'break';

export type Segment = {
  /**
   * The part node (`protected`, `disclosures/2`, `kb/signature`, …).
   */
  node_id: NodeId;
  /**
   * `Protected header`, `Payload`, `Signature`, `Disclosure 2`, …
   */
  label: string;
  /**
   * Range in `Document.bytes`.
   */
  range: ByteRange;
  /**
   * The segment text.
   */
  text: string;
  /**
   * The separator after it in compact form (`.` or `~`).
   */
  separator: string | null;
};

export type ViewOptions = {
  /**
   * EDN layout.
   */
  layout?: Layout;
  /**
   * Indent width for indented layouts.
   */
  indent?: number;
  /**
   * Show decoded views at the format-defined locations.
   */
  decoded_views?: boolean;
  /**
   * Byte string nodes whose decoded view is toggled off.
   */
  hide_decoded?: Array<NodeId>;
  /**
   * Byte string nodes the user chose to decode as CBOR.
   */
  manual_decode?: Array<NodeId>;
  /**
   * Registry comments and hover annotations.
   */
  annotations?: boolean;
  /**
   * How byte strings that are not decoded are printed.
   */
  byte_style?: ByteStyle;
  /**
   * Print tag 1 as `DT'…'` where exact.
   */
  dt_literals?: boolean;
  /**
   * Layout of decoded JOSE JSON.
   */
  json_layout?: JsonLayout;
  /**
   * Clock for relative times in [`TimeHint`]s.
   */
  now?: number | null;
  /**
   * Local offset east of UTC, in minutes, for display.
   */
  local_offset_minutes?: number;
};

export type Layout = 'indented' | 'compact';

export type ByteStyle = 'hex' | 'base64';

export type JsonLayout = 'original' | 'pretty';

export type ValidationReport = {
  /**
   * `fail` if any item fails, else `warn` if any warns, else `skip` if
   * the signature or key binding was skipped, else `pass`.
   */
  overall: Status;
  /**
   * The checklist: signature, time, SD, key binding, lint.
   */
  items: Array<CheckItem>;
  /**
   * URLs the user may choose to fetch keys from (never fetched here).
   */
  fetchable: Array<FetchHint>;
};

export type CheckItem = {
  /**
   * Stable id (`signature`, `time.exp`, `sd.match`, `kb.sd_hash`,
   * `lint.encoding`, …). Ids may repeat (one item per finding).
   */
  id: string;
  /**
   * Group.
   */
  category: Category;
  /**
   * Outcome.
   */
  status: Status;
  /**
   * Human-readable text.
   */
  message: string;
  /**
   * The nodes concerned.
   */
  node_ids: Array<NodeId>;
  /**
   * The exact byte span (encoding findings: the hex row's bytes).
   */
  raw: ByteRange | null;
  /**
   * Structured details.
   */
  detail: CheckDetail | null;
};

export type Status = 'pass' | 'fail' | 'warn' | 'skip' | 'info';

export type Category = 'signature' | 'time' | 'sd' | 'key_binding' | 'lint';

export type CheckDetail =
  | {
      type: 'signature';
      /**
       * JOSE name of the alg used.
       */
      alg: string | null;
      /**
       * Index into `ValidateRequest.keys`, for panel keys.
       */
      key_index: number | null;
      /**
       * `KeyRef.label` of that key.
       */
      key_label: string | null;
      /**
       * How the key was selected.
       */
      selection: KeySelection;
      /**
       * An embedded key (x5c, cnf): not trusted.
       */
      untrusted: boolean;
    }
  | {
      type: 'time';
      /**
       * `exp`, `nbf`, or `iat`.
       */
      claim: string;
      /**
       * The claim value (whole seconds).
       */
      value: number;
      /**
       * The clock.
       */
      now: number;
      /**
       * The skew.
       */
      skew: number;
    }
  | {
      type: 'encoding';
      /**
       * `non_preferred_argument`, `non_preferred_float`,
       * `non_canonical_nan`, `non_preferred_bignum`, `indefinite_length`,
       * `map_key_order`.
       */
      finding: string;
      /**
       * Replacement bytes for `CheckItem.raw`, as hex.
       */
      preferred_hex: string;
    };

export type KeySelection =
  'panel_kid' | 'panel_thumbprint' | 'panel_unmatched' | 'embedded_x5c' | 'embedded_cnf' | 'none';

export type FetchHint = {
  /**
   * What the URL is.
   */
  kind: FetchKind;
  /**
   * The URL.
   */
  url: string;
  /**
   * Why it is offered.
   */
  reason: string;
};

export type FetchKind = 'kid_url' | 'issuer_metadata';

export type DocRef = {
  /**
   * `Document.kind`.
   */
  kind: Kind;
  /**
   * `Document.bytes`.
   */
  bytes: Bytes;
};

export type RenderRequest = {
  /**
   * The document.
   */
  doc: DocRef;
  /**
   * Outer layers to record in the result (from the original `open`).
   */
  layers?: Array<Layer>;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type EditRequest = {
  /**
   * The kind being edited.
   */
  kind: Kind;
  /**
   * The bytes before the edit (for unedited regions and the stale flag).
   */
  base: Bytes;
  /**
   * The edited main pane text.
   */
  text: string;
  /**
   * View options for the returned document.
   */
  view?: ViewOptions;
};

export type EditResult = {
  /**
   * The text parsed and bytes were built.
   */
  ok: boolean;
  /**
   * The new bytes.
   */
  bytes: Bytes | null;
  /**
   * The re-rendered document.
   */
  document: Document | null;
  /**
   * Signed content differs from `base` (the signature was kept).
   */
  signature_stale: boolean;
  /**
   * Parse errors (with their `main` position) and warnings.
   */
  diagnostics: Array<Diagnostic>;
};

export type IssueRequest = {
  /**
   * The claim set: `json_claims` issues JOSE, `edn_claims` and
   * `cbor_claims` issue COSE.
   */
  claims: DocRef;
  /**
   * The issuer's private key.
   */
  issuer: KeyRef;
  /**
   * JOSE alg name (`ES256`, `Ed25519`, `ML-DSA-44`); derived from the key
   * when absent.
   */
  alg?: string | null;
  /**
   * Header options.
   */
  header?: HeaderOptions;
  /**
   * Selective disclosure options.
   */
  sd?: SdOptions;
  /**
   * Holder confirmation (`cnf`).
   */
  cnf?: CnfChoice | null;
  /**
   * JOSE output serialization.
   */
  jose_serialization?: JoseSerialization;
  /**
   * COSE tags, outermost first (default `[18]`).
   */
  cose_tags?: Array<number> | null;
  /**
   * 32-byte seed for salts, decoys, and randomized signatures. Without
   * it, signing is deterministic and SD needs `sd.fixed_salts`.
   */
  randomness?: Bytes | null;
  /**
   * View options for the result.
   */
  view?: ViewOptions;
};

export type HeaderOptions = {
  /**
   * `typ`.
   */
  typ?: TypChoice;
  /**
   * `kid`.
   */
  kid?: KidChoice;
  /**
   * JOSE `x5c` (base64 DER), in order.
   */
  x5c?: Array<string>;
  /**
   * More protected header members: a JSON object (JOSE) or EDN map
   * (COSE), appended in order.
   */
  extra?: string | null;
  /**
   * COSE unprotected header extras (EDN map).
   */
  unprotected_extra?: string | null;
};

export type TypChoice =
  | { type: 'auto' }
  | { type: 'omit' }
  | {
      type: 'value';
      /**
       * The value.
       */
      value: string;
    };

export type KidChoice =
  | { type: 'none' }
  | { type: 'from_key' }
  | {
      type: 'value';
      /**
       * The kid.
       */
      kid: KidValue;
    };

export type SdOptions = {
  /**
   * NodeIds of JSON claims to make selectively disclosable (marking a
   * claim and something inside it gives recursive disclosures). EDN uses
   * tags 58/62 instead.
   */
  marks?: Array<NodeId>;
  /**
   * Decoy digests (JOSE).
   */
  decoys?: Array<DecoyRequest>;
  /**
   * SD hash (`_sd_alg` / `sd_alg`).
   */
  sd_alg?: HashName | null;
  /**
   * Fixed salts in creation order: JOSE salt strings, COSE hex.
   */
  fixed_salts?: Array<string>;
  /**
   * `_sd` order.
   */
  digest_order?: DigestOrder;
  /**
   * Issue SD form even if nothing is marked.
   */
  force_sd?: boolean;
};

export type DecoyRequest = {
  /**
   * NodeId of the object or array in the claim set (`""` for the top).
   */
  at: NodeId;
  /**
   * How many.
   */
  count: number;
};

export type DigestOrder = 'sorted' | 'creation';

export type CnfChoice =
  | {
      type: 'key';
      /**
       * The holder key.
       */
      key: KeyRef;
    }
  | {
      type: 'kid';
      /**
       * The kid.
       */
      kid: KidValue;
    };

export type JoseSerialization = 'compact' | 'json_flattened' | 'json_general';

export type DiscloseRequest = {
  /**
   * The SD credential.
   */
  doc: DocRef;
  /**
   * Disclosure indexes to keep, in order.
   */
  keep: Array<number>;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type PresentRequest = {
  /**
   * The credential (SD-JWT, SD-CWT, or a plain CWT).
   */
  doc: DocRef;
  /**
   * Disclosure indexes to keep, in order.
   */
  keep: Array<number>;
  /**
   * The holder's private key.
   */
  holder: KeyRef;
  /**
   * KB alg (JOSE name); derived from the key when absent.
   */
  alg?: string | null;
  /**
   * `aud`.
   */
  aud?: string | null;
  /**
   * `nonce` (JOSE, text) / `cnonce` (COSE, bytes).
   */
  nonce?: Nonce | null;
  /**
   * `iat`.
   */
  iat: number;
  /**
   * 32-byte seed for randomized signatures.
   */
  randomness?: Bytes | null;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type ValidateRequest = {
  /**
   * The credential.
   */
  doc: DocRef;
  /**
   * Candidate keys from the panel.
   */
  keys?: Array<KeyRef>;
  /**
   * The clock (seconds since the epoch).
   */
  now: number;
  /**
   * Allowed skew in seconds.
   */
  skew?: number;
  /**
   * Expected KB `aud`.
   */
  expected_aud?: string | null;
  /**
   * Expected KB `nonce` / `cnonce`.
   */
  expected_nonce?: Nonce | null;
  /**
   * Maximum KB `iat` age in seconds.
   */
  max_kb_age?: number | null;
};

export type LintRequest = {
  /**
   * The document.
   */
  doc: DocRef;
  /**
   * Keys to check against the header `alg` (the verifying key).
   */
  keys?: Array<KeyRef>;
};

export type ResignRequest = {
  /**
   * The (edited) credential.
   */
  doc: DocRef;
  /**
   * The signing key.
   */
  key: KeyRef;
  /**
   * Sign with this alg (JOSE name) instead of the header alg.
   */
  alg?: string | null;
  /**
   * 32-byte seed for randomized signatures; deterministic without.
   */
  randomness?: Bytes | null;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type TamperRequest = {
  /**
   * The credential.
   */
  doc: DocRef;
  /**
   * What to break.
   */
  op: TamperOp;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type TamperOp =
  | {
      type: 'flip_bit';
      /**
       * Which part.
       */
      part: PartRef;
      /**
       * Bit index.
       */
      bit: number;
    }
  | {
      type: 'flip_byte_bit';
      /**
       * Byte offset.
       */
      offset: number;
      /**
       * Bit in the byte.
       */
      bit: number;
    }
  | {
      type: 'set_alg';
      /**
       * The alg.
       */
      alg: AlgValue;
    }
  | { type: 'remove_alg' }
  | { type: 'strip_signature' }
  | {
      type: 'set_kid';
      /**
       * The kid.
       */
      kid: KidValue | null;
    }
  | {
      type: 'truncate';
      /**
       * Bytes kept.
       */
      len: number;
    }
  | {
      type: 'duplicate_disclosure';
      /**
       * Disclosure index.
       */
      index: number;
    }
  | {
      type: 'reencode_protected';
      /**
       * How (COSE); JOSE always re-formats the JSON.
       */
      how: EquivalentEncoding;
    }
  | {
      type: 'set_tags';
      /**
       * Tags, outermost first.
       */
      tags: Array<number>;
    };

export type PartRef =
  | { type: 'protected' }
  | { type: 'unprotected' }
  | { type: 'payload' }
  | { type: 'signature' }
  | {
      type: 'disclosure';
      /**
       * Index.
       */
      index: number;
    }
  | { type: 'kb_protected' }
  | { type: 'kb_payload' }
  | { type: 'kb_signature' };

export type AlgValue = string | number;

export type EquivalentEncoding = 'auto' | 'wide_bstr_head' | 'wide_integers' | 'indefinite_map';

export type ReencodeRequest = {
  /**
   * The credential.
   */
  doc: DocRef;
  /**
   * Outer layers for the output, outermost first (no `cbor_tag` layers;
   * use `cose_tags`).
   */
  layers?: Array<Layer>;
  /**
   * New COSE tags; `None` keeps them.
   */
  cose_tags?: Array<number> | null;
  /**
   * CBOR serialization.
   */
  cbor?: CborSerialization;
  /**
   * Also re-serialize the protected header, payload, and disclosure
   * contents (may make the signature stale).
   */
  deep?: boolean;
  /**
   * New JOSE serialization; `None` keeps it.
   */
  jose?: JoseSerialization | null;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type CborSerialization = 'preserve' | 'preferred_plus' | 'deterministic';

export type Reencoded = {
  /**
   * The full output, with the new outer layers applied.
   */
  output: Bytes;
  /**
   * The re-encoded credential (layers set to the request's).
   */
  document: Document;
};

export type EditDisclosuresRequest = {
  /**
   * The SD credential.
   */
  doc: DocRef;
  /**
   * Edits, applied in order.
   */
  ops: Array<DisclosureOp>;
  /**
   * 32-byte seed for forged salts and random digests.
   */
  randomness?: Bytes | null;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type DisclosureOp =
  | {
      type: 'remove';
      /**
       * Index.
       */
      index: number;
    }
  | {
      type: 'duplicate';
      /**
       * Index.
       */
      index: number;
    }
  | {
      type: 'move';
      /**
       * From.
       */
      from: number;
      /**
       * To.
       */
      to: number;
    }
  | {
      type: 'select';
      /**
       * Indexes.
       */
      indices: Array<number>;
    }
  | {
      type: 'append';
      /**
       * The encoded disclosure.
       */
      encoded: string;
    }
  | {
      type: 'forge';
      /**
       * Salt (JOSE string, COSE hex); random when absent.
       */
      salt: string | null;
      /**
       * Claim name / key.
       */
      claim: string | null;
      /**
       * Value.
       */
      value: string | null;
    }
  | {
      type: 'replace_value';
      /**
       * Index.
       */
      index: number;
      /**
       * JSON / EDN text.
       */
      value: string;
    }
  | {
      type: 'add_decoy';
      /**
       * NodeId of the object/array in the decoded payload.
       */
      at: NodeId;
      /**
       * The digest; random when absent.
       */
      digest: string | null;
    }
  | {
      type: 'remove_digest';
      /**
       * The digest.
       */
      digest: string;
    };

export type DecodeEmbeddedRequest = {
  /**
   * The document.
   */
  doc: DocRef;
  /**
   * A byte string node.
   */
  node_id: NodeId;
  /**
   * View options.
   */
  view?: ViewOptions;
};

export type ManualDecode = {
  /**
   * EDN of the first data item.
   */
  text: string;
  /**
   * Its tree, rooted at `<node_id>/~e`, with ranges into `text` and the
   * document's raw buffer.
   */
  tree: Node;
  /**
   * `cbor.trailing_bytes` and other warnings.
   */
  diagnostics: Array<Diagnostic>;
};

export type ConvertClaimsRequest = {
  /**
   * The claim set text.
   */
  text: string;
  /**
   * Its language.
   */
  from: Language;
  /**
   * The language to convert to.
   */
  to: Language;
  /**
   * Map registered JWT claim names to CWT labels (JSON → EDN) and back
   * (EDN → JSON), through the registry (SPEC §7). Top-level claims only.
   */
  map_claim_labels?: boolean;
  /**
   * View options for the returned document.
   */
  view?: ViewOptions;
};

export type ConvertClaimsResult = {
  /**
   * The text converted.
   */
  ok: boolean;
  /**
   * The converted text.
   */
  text: string | null;
  /**
   * The converted claim set (`json_claims` / `edn_claims`).
   */
  document: Document | null;
  /**
   * Why it did not convert: a parse error of `text` (`json.syntax`,
   * `edn.syntax`, with its position), or `convert.not_representable`
   * naming the first node JSON cannot hold (a byte string, a non-text
   * key that is not a mapped claim label, a tag, a simple value other
   * than true/false/null, undefined, a non-finite float, or nesting
   * beyond JSON's 128 levels).
   */
  diagnostics: Array<Diagnostic>;
};

export type KeyRef = {
  /**
   * JWK, JWK Set, COSE_Key, COSE_KeySet, or PEM bytes.
   */
  bytes: Bytes;
  /**
   * Format hint; detected when absent.
   */
  format?: KeyFormat | null;
  /**
   * Which key of a set (0 for a single key).
   */
  index?: number;
  /**
   * Workspace role (never serialized into key formats).
   */
  role?: Role | null;
  /**
   * The UI's name for the key card, echoed in validation reports.
   */
  label?: string | null;
};

export type KeyFormat =
  | { type: 'jwk' }
  | { type: 'jwk_set' }
  | { type: 'cose_key' }
  | { type: 'cose_key_set' }
  | {
      type: 'pem';
      /**
       * The DER structure (export only; import reads the label).
       */
      encoding: PemEncoding;
    };

export type PemEncoding =
  | 'auto'
  | 'spki'
  | 'pkcs8'
  | 'pkcs8_ml_dsa_seed'
  | 'pkcs8_ml_dsa_expanded'
  | 'pkcs8_ml_dsa_both'
  | 'sec1'
  | 'pkcs1';

export type Role = 'issuer' | 'holder' | 'verifier';

export type Visibility = 'public' | 'private';

export type KeyInfo = {
  /**
   * A self-contained reference to this one key (private when
   * available): a JWK, or a COSE_Key when the kid is binary (so it stays
   * binary), or PKCS#8 PEM for an ML-DSA key known only by its expanded
   * private key (neither JWK nor COSE_Key can hold that).
   */
  key: KeyRef;
  /**
   * JWK `kty`: `EC`, `OKP`, `RSA`, `AKP`.
   */
  kty: string;
  /**
   * JWK curve name (`P-256`, `Ed25519`).
   */
  crv: string | null;
  /**
   * RSA modulus size.
   */
  bits: number | null;
  /**
   * ML-DSA parameter set (`ML-DSA-44`).
   */
  param_set: string | null;
  /**
   * `EC P-256`, `RSA 2048`, `ML-DSA-65`, `Ed25519`.
   */
  description: string;
  /**
   * Has private material.
   */
  private: boolean;
  /**
   * The kid.
   */
  kid: KidValue | null;
  /**
   * Declared `alg` (JOSE name, or the COSE label as text if unknown).
   */
  alg: string | null;
  /**
   * JOSE names of the algorithms this key can be used with.
   */
  algs: Array<string>;
  /**
   * The role from the [`KeyRef`].
   */
  role: Role | null;
  /**
   * RFC 7638 SHA-256 thumbprint, base64url.
   */
  jwk_thumbprint: string;
  /**
   * RFC 9278 URI of it.
   */
  jwk_thumbprint_uri: string;
  /**
   * RFC 9679 SHA-256 thumbprint, hex.
   */
  cose_thumbprint: string;
  /**
   * RFC 9679 §5.7 URI of it.
   */
  cose_thumbprint_uri: string;
};

export type KeyImportRequest = {
  /**
   * The bytes: the key itself, or (with `candidate`) the input `detect`
   * was given.
   */
  bytes: Bytes;
  /**
   * Format hint.
   */
  format?: KeyFormat | null;
  /**
   * A key candidate from `detect(bytes)`: its layers (hex, base64,
   * quotes, a JSON field, ...) are unwrapped first, as `open` does for
   * credentials.
   */
  candidate?: Candidate | null;
};

export type KeyExportRequest = {
  /**
   * The key.
   */
  key: KeyRef;
  /**
   * Target format.
   */
  format: KeyFormat;
  /**
   * Public or private (private needs an explicit choice).
   */
  visibility: Visibility;
};

export type KeyExport = {
  /**
   * The bytes.
   */
  bytes: Bytes;
  /**
   * The same as text, for text formats (JWK, PEM).
   */
  text: string | null;
  /**
   * Contains private material (label the clipboard copy).
   */
  private: boolean;
};

export type KeyGenRequest = {
  /**
   * Key type.
   */
  spec: KeySpec;
  /**
   * Role for the card.
   */
  role?: Role | null;
  /**
   * Where the randomness comes from.
   */
  seed: KeySeed;
  /**
   * Set a kid right away.
   */
  kid?: KidSource | null;
};

export type KeySpec =
  | { type: 'p256' }
  | { type: 'p384' }
  | { type: 'p521' }
  | { type: 'ed25519' }
  | {
      type: 'rsa';
      /**
       * Modulus size.
       */
      bits: number;
    }
  | { type: 'ml_dsa44' }
  | { type: 'ml_dsa65' }
  | { type: 'ml_dsa87' };

export type KeySeed =
  | { type: 'well_known' }
  | {
      type: 'seed';
      /**
       * The seed.
       */
      bytes: Bytes;
    }
  | {
      type: 'entropy';
      /**
       * The entropy.
       */
      bytes: Bytes;
    };

export type KidSource =
  | {
      type: 'jwk_thumbprint';
      /**
       * Hash.
       */
      hash: HashName;
    }
  | {
      type: 'cose_thumbprint';
      /**
       * Hash.
       */
      hash: HashName;
    }
  | {
      type: 'text';
      /**
       * The kid.
       */
      value: string;
    }
  | {
      type: 'bytes';
      /**
       * The kid.
       */
      value: Bytes;
    };

export type ThumbprintRequest = {
  /**
   * The key.
   */
  key: KeyRef;
  /**
   * JWK (RFC 7638) or COSE (RFC 9679).
   */
  kind: ThumbprintKind;
  /**
   * Hash.
   */
  hash?: HashName;
};

export type ThumbprintKind = 'jwk' | 'cose';

export type Thumbprint = {
  /**
   * Kind.
   */
  kind: ThumbprintKind;
  /**
   * Hash.
   */
  hash: HashName;
  /**
   * Lowercase hex.
   */
  hex: string;
  /**
   * Unpadded base64url.
   */
  base64url: string;
  /**
   * RFC 9278 (JWK) or RFC 9679 §5.7 (COSE) URI.
   */
  uri: string;
};

export type AssignKidRequest = {
  /**
   * The key.
   */
  key: KeyRef;
  /**
   * The new kid.
   */
  source: KidSource;
};

export type KeyConvertRequest = {
  /**
   * The key.
   */
  key: KeyRef;
  /**
   * Public or private.
   */
  visibility: Visibility;
};

export type DateTimeRequest = {
  /**
   * The value being edited.
   */
  input: DateTimeInput;
  /**
   * Clock for the relative string.
   */
  now?: number | null;
  /**
   * Local offset east of UTC in minutes (the platform knows the zone).
   */
  local_offset_minutes?: number;
};

export type DateTimeInput =
  | {
      type: 'epoch';
      /**
       * The text.
       */
      text: string;
    }
  | {
      type: 'millis';
      /**
       * Milliseconds.
       */
      millis: number;
    }
  | {
      type: 'rfc3339';
      /**
       * The text.
       */
      text: string;
    }
  | {
      type: 'date';
      /**
       * The text.
       */
      text: string;
    }
  | {
      type: 'days';
      /**
       * Days.
       */
      days: number;
    }
  | {
      type: 'edn';
      /**
       * The text.
       */
      text: string;
    }
  | {
      type: 'cbor_hex';
      /**
       * The hex.
       */
      hex: string;
    };

export type DateTimeForms = {
  /**
   * Epoch seconds as decimal text (fraction only when non-zero).
   */
  epoch: string;
  /**
   * Epoch milliseconds (floor).
   */
  millis: number;
  /**
   * RFC 3339 in UTC (`Z`).
   */
  rfc3339_utc: string;
  /**
   * RFC 3339 at `local_offset_minutes` (`+02:00`; `+00:00` for 0).
   */
  rfc3339_local: string;
  /**
   * The offset used.
   */
  local_offset_minutes: number;
  /**
   * `"in 3 h 12 m"`, `"2 d ago"`, `"now"`; `None` without `now`.
   */
  relative: string | null;
  /**
   * The CBOR forms in `tokenator_edn::datetime::DateForm::ALL` order.
   */
  forms: Array<DateTimeFormView>;
};

export type DateTimeFormView = {
  /**
   * Which form.
   */
  form: DateFormKind;
  /**
   * Compact EDN.
   */
  edn: string;
  /**
   * Preferred-serialization CBOR, lowercase hex.
   */
  cbor_hex: string;
};

export type DateFormKind =
  'epoch' | 'tag1' | 'rfc3339' | 'tag0' | 'tag100' | 'tag1004' | 'dt' | 'dt_tagged';

export type RegistryQuery = {
  /**
   * Entry kind.
   */
  kind?: RegistryKind | null;
  /**
   * Exact label (needs `kind`).
   */
  label?: RegistryLabel | null;
  /**
   * Exact name (needs `kind`).
   */
  name?: string | null;
  /**
   * Name prefix (autocomplete).
   */
  prefix?: string | null;
};

export type RegistryKind =
  | 'jose_header'
  | 'jose_alg'
  | 'jwk_kty'
  | 'jwk_crv'
  | 'jwk_param'
  | 'jwt_claim'
  | 'jwt_cnf_method'
  | 'cose_header'
  | 'cose_header_alg_param'
  | 'cose_alg'
  | 'cose_key_param'
  | 'cose_key_type_param'
  | 'cose_kty'
  | 'cose_crv'
  | 'cwt_claim'
  | 'cwt_cnf_method'
  | 'cbor_tag'
  | 'cbor_simple';

export type RegistryLabel = number | string;

export type RegistryEntry = {
  /**
   * Kind.
   */
  kind: RegistryKind;
  /**
   * Label.
   */
  label: RegistryLabel;
  /**
   * Name.
   */
  name: string;
  /**
   * Description.
   */
  description: string;
  /**
   * Value type.
   */
  value_type: string | null;
  /**
   * References (`display_text()`).
   */
  spec: Array<SpecLink>;
  /**
   * Origin.
   */
  source: RegistrySource;
  /**
   * TEMPORARY registration.
   */
  temporary: boolean;
  /**
   * JWT claim name of a CWT claim.
   */
  jwt_name: string | null;
};

export type RegistrySource = 'iana' | 'local' | 'refreshed';

export type RegistryId = 'cwt' | 'cose' | 'jwt' | 'jose';

export type RegistryMergeRequest = {
  /**
   * Snapshot to merge into; the engine's current registry when absent.
   */
  base_snapshot?: Bytes | null;
  /**
   * The fetched IANA XML.
   */
  xml: Bytes;
  /**
   * Which registry it is.
   */
  which: RegistryId;
};

export type RegistryMergeResult = {
  /**
   * For [`Engine::with_registry_snapshot`](crate::Engine::with_registry_snapshot).
   */
  snapshot: Bytes;
  /**
   * What changed.
   */
  stats: RegistryStats;
};

export type RegistryStats = {
  /**
   * New entries.
   */
  added: number;
  /**
   * Changed entries.
   */
  updated: number;
  /**
   * Identical entries.
   */
  unchanged: number;
  /**
   * Entries no longer listed.
   */
  removed: number;
  /**
   * Local entries now shadowed.
   */
  superseded_local: number;
  /**
   * The registry's last-updated date.
   */
  iana_updated: string | null;
};

export type EngineInfo = {
  /**
   * `tokenator-core` version.
   */
  version: string;
  /**
   * Targeted SD-CWT draft revision (`draft-ietf-spice-sd-cwt-08`).
   */
  sd_cwt_revision: string;
  /**
   * IANA last-updated date per registry (`cwt`, `cose`, `jwt`, `jose`).
   */
  registry_updated: { [key in string]: string };
};

export type EngineError = {
  /**
   * Stable machine-readable code.
   */
  code: ErrorCode;
  /**
   * Human-readable text.
   */
  message: string;
  /**
   * The node concerned, if any.
   */
  node_id: NodeId | null;
};

export type ErrorCode =
  | 'parse'
  | 'decode'
  | 'unsupported_kind'
  | 'unsupported'
  | 'invalid_candidate'
  | 'invalid_input'
  | 'key'
  | 'no_private_key'
  | 'unsupported_alg'
  | 'crypto'
  | 'randomness'
  | 'node_not_found'
  | 'not_bytes'
  | 'nothing_to_redact'
  | 'disclosure_index'
  | 'date_time'
  | 'registry';
