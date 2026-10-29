// An Engine of vi.fn()s returning fixtures. Override per test with
// `engine.detect.mockResolvedValueOnce(...)` etc.
import { vi } from 'vitest';
import type { Engine } from '../lib/engine/Engine';
import type {
  Candidate,
  ConvertClaimsRequest,
  ConvertClaimsResult,
  Document,
  Kind,
} from '../lib/engine/types';
import * as fx from './fixtures';

function docFor(kind: Kind): Document {
  switch (kind.type) {
    case 'jwt':
      return fx.jwt;
    case 'sd_jwt':
      return kind.kb ? fx.sdJwtKb : fx.sdJwt;
    case 'cwt':
      return fx.cwt;
    case 'sd_cwt':
      return fx.sdCwt;
    case 'sd_kbt':
      return fx.sdKbt;
    case 'json_claims':
      return fx.jsonClaims;
    case 'edn_claims':
      return fx.ednClaims;
    default:
      return fx.jwt;
  }
}

export class MockEngine implements Engine {
  info = vi.fn(async () => fx.info);
  detect = vi.fn(async (_input: Uint8Array): Promise<Candidate[]> => fx.jwtCandidates);
  open = vi.fn(async (_input: Uint8Array, candidate: Candidate) => ({
    ...docFor(candidate.kind),
    layers: candidate.layers,
  }));
  render = vi.fn(async (req: Parameters<Engine['render']>[0]) => ({
    ...docFor(req.doc.kind),
    layers: req.layers ?? [],
  }));
  parseEdit = vi.fn(async (_req: Parameters<Engine['parseEdit']>[0]) => fx.editStale);
  issue = vi.fn(async (req: Parameters<Engine['issue']>[0]) =>
    (req.sd?.marks?.length ?? 0) > 0 ? fx.sdJwt : fx.jwt,
  );
  redact = vi.fn(async (_req: Parameters<Engine['redact']>[0]) => fx.sdJwt);
  disclose = vi.fn(async (_req: Parameters<Engine['disclose']>[0]) => fx.sdJwt);
  present = vi.fn(async (_req: Parameters<Engine['present']>[0]) => fx.sdJwtKb);
  validate = vi.fn(async (_req: Parameters<Engine['validate']>[0]) => fx.jwtReport);
  lint = vi.fn(async (_req: Parameters<Engine['lint']>[0]) => fx.cwtLintReport.items);
  resign = vi.fn(async (_req: Parameters<Engine['resign']>[0]) => fx.jwt);
  tamper = vi.fn(async (_req: Parameters<Engine['tamper']>[0]) => ({
    ...fx.jwt,
    signature_stale: true,
  }));
  reencode = vi.fn(async (_req: Parameters<Engine['reencode']>[0]) => ({
    output: fx.cwt.bytes,
    document: fx.cwt,
  }));
  editDisclosures = vi.fn(async (_req: Parameters<Engine['editDisclosures']>[0]) => fx.sdJwt);
  decodeEmbedded = vi.fn(async (_req: Parameters<Engine['decodeEmbedded']>[0]) => ({
    text: '{1: 2}',
    tree: fx.cwt.tree,
    diagnostics: [],
  }));
  keyImport = vi.fn(async (_req: Parameters<Engine['keyImport']>[0]) => [fx.verifierInfo]);
  keyExport = vi.fn(async (req: Parameters<Engine['keyExport']>[0]) =>
    req.visibility === 'private' ? fx.privateExport : fx.publicExport,
  );
  keyPublic = vi.fn(async (_key: Parameters<Engine['keyPublic']>[0]) => fx.verifierInfo);
  keyGenerate = vi.fn(async (_req: Parameters<Engine['keyGenerate']>[0]) => fx.issuerInfo);
  keyThumbprint = vi.fn(async (req: Parameters<Engine['keyThumbprint']>[0]) =>
    req.kind === 'jwk' ? fx.jwkThumbprint : fx.coseThumbprint,
  );
  keyAssignKid = vi.fn(async (_req: Parameters<Engine['keyAssignKid']>[0]) => ({
    ...fx.issuerInfo,
    kid: { type: 'text' as const, value: fx.issuerInfo.jwk_thumbprint },
  }));
  keyToJwk = vi.fn(async (req: Parameters<Engine['keyToJwk']>[0]) =>
    req.visibility === 'private' ? fx.ISSUER_JWK : fx.VERIFIER_JWK,
  );
  keyToCwk = vi.fn(async (_req: Parameters<Engine['keyToCwk']>[0]) => ({
    ...fx.ednClaims,
    kind: { type: 'cose_key' as const },
    main: { language: 'edn' as const, text: fx.ISSUER_CWK_EDN, line_count: 7 },
  }));
  datetime = vi.fn(async (_req: Parameters<Engine['datetime']>[0]) => fx.forms2030);
  registryLookup = vi.fn(async (_q: Parameters<Engine['registryLookup']>[0]) => []);
  registryMerge = vi.fn(async (_req: Parameters<Engine['registryMerge']>[0]) => ({
    snapshot: '',
    stats: {
      added: 0,
      updated: 0,
      unchanged: 0,
      removed: 0,
      superseded_local: 0,
      iana_updated: null,
    },
  }));
  convertClaims = vi.fn(async (req: ConvertClaimsRequest): Promise<ConvertClaimsResult> =>
    req.to === 'edn' ? fx.convertedToEdn : fx.convertedToJson,
  );
}
