// The Engine seam: one async method per `tokenator_core::Engine` method,
// taking and returning the generated DTOs. Implementations are thin
// wrappers (WasmEngine over tokenator-wasm, TauriEngine over invoke()).
import type {
  AssignKidRequest,
  Candidate,
  CheckItem,
  ConvertClaimsRequest,
  ConvertClaimsResult,
  DateTimeForms,
  DateTimeRequest,
  DecodeEmbeddedRequest,
  DiscloseRequest,
  Document,
  EditDisclosuresRequest,
  EditRequest,
  EditResult,
  EngineError,
  EngineInfo,
  IssueRequest,
  KeyConvertRequest,
  KeyExport,
  KeyExportRequest,
  KeyGenRequest,
  KeyImportRequest,
  KeyInfo,
  KeyRef,
  LintRequest,
  ManualDecode,
  PresentRequest,
  ReencodeRequest,
  Reencoded,
  RegistryEntry,
  RegistryMergeRequest,
  RegistryMergeResult,
  RegistryQuery,
  RenderRequest,
  ResignRequest,
  TamperRequest,
  Thumbprint,
  ThumbprintRequest,
  ValidateRequest,
  ValidationReport,
  ViewOptions,
} from './types';

export interface Engine {
  info(): Promise<EngineInfo>;
  detect(input: Uint8Array): Promise<Candidate[]>;
  open(input: Uint8Array, candidate: Candidate, view: ViewOptions): Promise<Document>;
  render(req: RenderRequest): Promise<Document>;
  /** Never rejects for bad text: problems come back as diagnostics. */
  parseEdit(req: EditRequest): Promise<EditResult>;
  /** Claim sets between JSON and EDN text (a draft's Format switch).
   *  `ok: false` when the text does not parse or EDN has no JSON form
   *  (`convert.not_representable`, with the node). */
  convertClaims(req: ConvertClaimsRequest): Promise<ConvertClaimsResult>;
  issue(req: IssueRequest): Promise<Document>;
  redact(req: IssueRequest): Promise<Document>;
  disclose(req: DiscloseRequest): Promise<Document>;
  present(req: PresentRequest): Promise<Document>;
  validate(req: ValidateRequest): Promise<ValidationReport>;
  lint(req: LintRequest): Promise<CheckItem[]>;
  resign(req: ResignRequest): Promise<Document>;
  tamper(req: TamperRequest): Promise<Document>;
  reencode(req: ReencodeRequest): Promise<Reencoded>;
  editDisclosures(req: EditDisclosuresRequest): Promise<Document>;
  decodeEmbedded(req: DecodeEmbeddedRequest): Promise<ManualDecode>;
  keyImport(req: KeyImportRequest): Promise<KeyInfo[]>;
  keyExport(req: KeyExportRequest): Promise<KeyExport>;
  keyPublic(key: KeyRef): Promise<KeyInfo>;
  keyGenerate(req: KeyGenRequest): Promise<KeyInfo>;
  keyThumbprint(req: ThumbprintRequest): Promise<Thumbprint>;
  keyAssignKid(req: AssignKidRequest): Promise<KeyInfo>;
  keyToJwk(req: KeyConvertRequest): Promise<string>;
  keyToCwk(req: KeyConvertRequest): Promise<Document>;
  datetime(req: DateTimeRequest): Promise<DateTimeForms>;
  registryLookup(query: RegistryQuery): Promise<RegistryEntry[]>;
  registryMerge(req: RegistryMergeRequest): Promise<RegistryMergeResult>;
}

/** An Engine call failed; `error` is the core's `EngineError`. */
export class EngineFailure extends Error {
  readonly error: EngineError;

  constructor(error: EngineError) {
    super(error.message);
    this.name = 'EngineFailure';
    this.error = error;
  }
}

export function isEngineFailure(e: unknown): e is EngineFailure {
  return e instanceof EngineFailure;
}
