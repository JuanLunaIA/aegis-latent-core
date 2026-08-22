// Copyright (c) 2026 Juan Luna. All rights reserved.
export interface OperationHooks<TArgs extends readonly unknown[], TResult> {
  readonly before?: (args: TArgs) => void;
  readonly after?: (result: Awaited<TResult>) => void;
  readonly error?: (error: unknown) => void;
}

function promiseLike(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && "then" in value
    && typeof (value as { readonly then?: unknown }).then === "function";
}

export function instrumentOperation<TThis, TArgs extends readonly unknown[], TResult>(
  receiver: TThis,
  operation: (this: TThis, ...args: TArgs) => TResult,
  hooks: OperationHooks<TArgs, TResult>,
): (...args: TArgs) => TResult {
  return (...args: TArgs): TResult => {
    hooks.before?.(args);
    try {
      const result = operation.call(receiver, ...args);
      if (promiseLike(result)) {
        return result.then(
          (value) => {
            hooks.after?.(value as Awaited<TResult>);
            return value;
          },
          (error: unknown) => {
            hooks.error?.(error);
            throw error;
          },
        ) as TResult;
      }
      hooks.after?.(result as Awaited<TResult>);
      return result;
    } catch (error: unknown) {
      hooks.error?.(error);
      throw error;
    }
  };
}

export const instrumentOpenAIOperation = instrumentOperation;
export const instrumentAnthropicOperation = instrumentOperation;
