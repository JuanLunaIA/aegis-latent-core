import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { axe } from "vitest-axe";

import { LedgerTable } from "../src/components/LedgerTable";
import { MetricsPanel } from "../src/components/MetricsPanel";

afterEach(()=>vi.restoreAllMocks());

describe("honest UI states",()=>{
  test("empty ledger says no rows were synthesized",()=>{
    render(<LedgerTable nodes={[]}/>);
    expect(screen.getByRole("heading",{name:"No audit nodes"})).toBeInTheDocument();
    expect(screen.getByText(/No rows are synthesized/)).toBeInTheDocument();
  });

  test("unavailable metrics is explicit and accessible",async()=>{
    vi.stubGlobal("fetch",vi.fn(async()=>new Response(JSON.stringify({state:"unavailable",samples:[]}),{status:200})));
    const {container}=render(<MetricsPanel/>);
    await screen.findByRole("heading",{name:"Telemetry unavailable"});
    expect((await axe(container,{rules:{"color-contrast":{enabled:false}}})).violations).toHaveLength(0);
  });

  test("metrics network failure exposes retry alert",async()=>{
    vi.stubGlobal("fetch",vi.fn(async()=>{throw new Error("offline");}));
    render(<MetricsPanel/>);
    await waitFor(()=>expect(screen.getByRole("alert")).toHaveTextContent("offline"));
    expect(screen.getByRole("button",{name:"Retry"})).toBeEnabled();
  });
});
