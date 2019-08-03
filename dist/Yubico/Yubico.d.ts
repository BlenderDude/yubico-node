import { Response } from "./Response";
export declare type SL = number | "fast" | "secure";
export interface IYubicoConstructor {
    clientId?: string;
    secret?: string;
    sl?: SL;
    timeout?: number;
    apiServers?: string[];
}
/**
 * The class that manages the Yubico requests and stores data about the
 * client such as its ID and secret
 */
export declare class Yubico {
    /**
     * The client ID obtained from Yubico
     */
    private clientId;
    /**
     * The secret obtained from Yubico
     */
    private secret;
    /**
     * The sync setting for the server to use.
     * From the Yubico Docs:
     *
     * A value 0 to 100 indicating percentage of syncing required by client,
     * or strings "fast" or "secure" to use server-configured values;
     * if absent, let the server decide
     *
     */
    private sl?;
    /**
     * The timeout to wait for sync responses. Without this parameter, the
     * Yubico server will automatically decide
     */
    private timeout?;
    /**
     * The api servers to use for the request. This is only to be used if you are running
     * your own implementation of the Yubico verification servers. Otherwise, you should
     * leave this parameter blank and it will default to Yubico's.
     */
    private apiServers;
    constructor(options?: IYubicoConstructor);
    /**
     * Verify a key against the Yubico servers
     * @param otp {string} The OTP provided from the YubiKey to use to verify
     * @returns {Promise<Response>} The response instance that can be picked apart for values like the serial number
     */
    verify(otp: string): Promise<Response>;
}
