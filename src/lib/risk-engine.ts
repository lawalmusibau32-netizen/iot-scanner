export interface RiskInput {
  cveScore: number;
  exposureScore: number;
  credentialScore: number;
  networkScore: number;
}

export interface RiskOutput {
  compositeScore: number;
  cveScore: number;
  exposureScore: number;
  credentialScore: number;
  networkScore: number;
  severity: string;
  recommendation: string;
}

const WEIGHTS = {
  cve: 0.40,
  exposure: 0.25,
  credential: 0.20,
  network: 0.15,
};

export function calculateRisk(input: RiskInput): RiskOutput {
  const composite =
    input.cveScore * WEIGHTS.cve +
    input.exposureScore * WEIGHTS.exposure +
    input.credentialScore * WEIGHTS.credential +
    input.networkScore * WEIGHTS.network;

  const clamped = Math.min(10, Math.max(0, Math.round(composite * 10) / 10));

  let severity: string;
  let recommendation: string;

  if (clamped >= 8) {
    severity = "Critical";
    recommendation = "Immediate action required. Isolate device from network and apply patches.";
  } else if (clamped >= 6) {
    severity = "High";
    recommendation = "Prioritize remediation. Update firmware and change default credentials.";
  } else if (clamped >= 3) {
    severity = "Medium";
    recommendation = "Schedule remediation. Review open ports and disable unnecessary services.";
  } else {
    severity = "Low";
    recommendation = "Routine monitoring. Device appears adequately secured.";
  }

  return {
    compositeScore: clamped,
    cveScore: Math.round(input.cveScore * 10) / 10,
    exposureScore: Math.round(input.exposureScore * 10) / 10,
    credentialScore: Math.round(input.credentialScore * 10) / 10,
    networkScore: Math.round(input.networkScore * 10) / 10,
    severity,
    recommendation,
  };
}

export function calculateExposureScore(ports: { port: number; service: string }[]): number {
  if (!ports.length) return 0;
  let score = 0;
  const highRisk = [23, 21, 3389, 135, 139, 445, 1433, 3306];
  const medRisk = [22, 25, 110, 143, 993, 995, 8080, 8443];
  for (const p of ports) {
    if (highRisk.includes(p.port)) score += 2;
    else if (medRisk.includes(p.port)) score += 1;
    else if (p.port < 1024) score += 0.5;
    else score += 0.2;
  }
  return Math.min(10, score);
}

export function calculateCredentialScore(defaultCredsFound: boolean, hasAuth: boolean, weakPwd: boolean): number {
  let score = 0;
  if (defaultCredsFound) score += 5;
  if (!hasAuth) score += 3;
  if (weakPwd) score += 2;
  return Math.min(10, score);
}
