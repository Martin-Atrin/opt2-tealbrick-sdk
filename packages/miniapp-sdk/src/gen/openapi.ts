// `tb-gen openapi`: the OpenAPI 3.1 document the server serves at `GET /tb/v1/openapi.json` (same builder, same op list).
import { withStandardOps } from "@opt2-tealbrick/manifest";
import { buildOpenApi } from "../server/openapi.ts";
import { GEN_SDK_VERSION, type GenFiles, type LoadedManifest, stableJson } from "./load.ts";

export function genOpenApi({ manifest }: LoadedManifest): GenFiles {
  return new Map([["openapi.json", stableJson(buildOpenApi(manifest, withStandardOps(manifest), GEN_SDK_VERSION))]]);
}
