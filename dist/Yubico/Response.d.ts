export declare enum ResponseStatus {
    OK = "OK",
    BAD_OTP = "BAD_OTP",
    REPLAYED_OTP = "REPLAYED_OTP",
    BAD_SIGNATURE = "BAD_SIGNATURE",
    MISSING_PARAMETER = "MISSING_PARAMETER",
    NO_SUCH_CLIENT = "NO_SUCH_CLIENT",
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED",
    BACKEND_ERROR = "BACKEND_ERROR",
    NOT_ENOUGH_ANSWERS = "NOT_ENOUGH_ANSWERS",
    REPLAYED_REQUEST = "REPLAYED_REQUEST"
}
export declare class Response {
    private otp;
    private nonce;
    private h;
    private t;
    private status;
    private timestamp;
    private sessioncounter;
    private sessionuse;
    private sl;
    /**
     * Creates a response from a string body
     * @param body {string} Body from the Yubico server
     * @returns {Response} Newly generated Response instance from the input
     */
    static fromRawBody(body: string): Response;
    constructor(otp: string, nonce: string, h: string, t: number, status: ResponseStatus, timestamp: string, sessioncounter: string, sessionuse: string, sl: number);
    /**
     * Validate the request against the nonce, secret, and otp
     * @param nonce {string} Nonce used during the request
     * @param secret {string} Secret used to verify against
     * @param otp {string} OTP from when the key was pressed
     */
    validate(nonce: string, secret: string, otp: string): void;
    /**
     * @returns {string} the one time password used in the request
     */
    getOneTimePassword(): string;
    /**
     * @returns {Date} Timestamp of the request in UTC
     */
    getTimestampUTC(): Date;
    /**
     * @returns {Date} YubiKey internal timestamp value when key was pressed
     */
    getTimestamp(): Date;
    /**
     * @returns {number} YubiKey internal usage counter when key was pressed
     */
    getSessionCounter(): number;
    /**
     * @returns {number} YubiKey internal session usage counter when key was pressed
     */
    getSessionUse(): number;
    /**
     * @returns {ResponseStatus} The status of the request. This will only show OK as all others will throw
     */
    getStatus(): ResponseStatus;
    /**
     * @returns {string} The public ID is the first 12 bytes of the OTP, this does not change between each request and can be used to identify users
     */
    getPublicId(): string;
    /**
     * @returns {number} The serial number of the key described as a 48 bit number
     */
    getSerialNumber(): number;
}
