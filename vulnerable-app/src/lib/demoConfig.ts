
export const demoConfig = {
  appName: "CDF TaskFlow",
  environment: "development",
  apiBaseUrl: "https://example.invalid/api",

  analytics: {
    enabled: true,
    apiKey: "cdf_demo_private_key_NOT_REAL_12345",
  },

  debug: {
    enabled: true,
    logLevel: "verbose",
  },
};

export function getApplicationConfig() {
  return demoConfig;
}
