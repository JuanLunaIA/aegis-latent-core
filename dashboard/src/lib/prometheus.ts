const ALLOWED = /^aegis_(request|forward|waf|ratelimit|audit|analysis|circuit|wal|scheduling|stream)_[a-zA-Z0-9_:]+$/;

export interface MetricSample {readonly name: string; readonly labels: string; readonly value: number}

export function parsePrometheus(text: string): MetricSample[] {
  const samples: MetricSample[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$/.exec(line);
    if (!match) continue;
    const name = match[1];
    const value = Number(match[3]);
    if (name && ALLOWED.test(name) && Number.isFinite(value)) {
      samples.push({name, labels: match[2] ?? "", value});
    }
  }
  return samples;
}
