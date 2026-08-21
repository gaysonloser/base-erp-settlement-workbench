import { createBaseAccountSDK } from "@base-org/account";
import { createBaseAuthBrowserController } from "./browser-auth.mjs";

globalThis.BaseAuthSDK = Object.freeze({ createBaseAccountSDK });
globalThis.BaseAuthControllerFactory = ({ release } = {}) => createBaseAuthBrowserController({
  sdkFactory: createBaseAccountSDK,
  release,
  sdkOptions: { appName: "Base ERP Settlement Workbench", appLogoUrl: "", appChainIds: [8453], preference: { telemetry: false } },
});
