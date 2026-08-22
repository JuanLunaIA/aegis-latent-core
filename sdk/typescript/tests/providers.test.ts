import { describe, expect, test, vi } from "vitest";

import { instrumentOperation } from "../src/providers.js";

describe("instrumentOperation", () => {
  test("preserves receiver, arguments and synchronous result", () => {
    const receiver = {
      prefix: "aegis",
      execute(value: number): string {
        return `${this.prefix}:${value}`;
      },
    };
    const before = vi.fn();
    const after = vi.fn();
    const wrapped = instrumentOperation(receiver, receiver.execute, { before, after });
    const typed: (value: number) => string = wrapped;
    expect(typed(7)).toBe("aegis:7");
    expect(before).toHaveBeenCalledWith([7]);
    expect(after).toHaveBeenCalledWith("aegis:7");
  });

  test("preserves promises and reports rejection without normalization", async () => {
    const failure = new Error("provider failure");
    const receiver = {
      async execute(value: string): Promise<{ readonly value: string }> {
        if (value === "fail") throw failure;
        return { value };
      },
    };
    const onError = vi.fn();
    const wrapped = instrumentOperation(receiver, receiver.execute, { error: onError });
    const typed: (value: string) => Promise<{ readonly value: string }> = wrapped;
    await expect(typed("ok")).resolves.toEqual({ value: "ok" });
    await expect(typed("fail")).rejects.toBe(failure);
    expect(onError).toHaveBeenCalledWith(failure);
  });

  test("does not consume async iterables", async () => {
    let consumed = false;
    async function* stream(): AsyncIterable<number> {
      consumed = true;
      yield 1;
    }
    const receiver = { stream };
    const wrapped = instrumentOperation(receiver, receiver.stream, {});
    const result = wrapped();
    expect(consumed).toBe(false);
    const values: number[] = [];
    for await (const value of result) values.push(value);
    expect(values).toEqual([1]);
  });
});
