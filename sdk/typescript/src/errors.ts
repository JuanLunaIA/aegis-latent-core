// Copyright (c) 2026 Juan Luna. All rights reserved.
export class AegisProofError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "AegisProofError";
  }
}
