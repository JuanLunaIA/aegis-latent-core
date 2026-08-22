import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

function files(root:string):string[]{return readdirSync(root).flatMap((name)=>{const path=join(root,name);return statSync(path).isDirectory()?files(path):[path];});}

describe("production source integrity",()=>{
  test("contains no random or demo runtime builders",()=>{
    const source=files(join(process.cwd(),"src")).filter((path)=>/\.(ts|tsx)$/.test(path)).map((path)=>readFileSync(path,"utf8")).join("\n");
    expect(source).not.toMatch(/Math\.random|enableDemo|sampleAudit|mockMetric/i);
    expect(source).not.toMatch(/AEGIS_DASHBOARD_API_KEY[\s\S]{0,120}NEXT_PUBLIC/);
  });
});
