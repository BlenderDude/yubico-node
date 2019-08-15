import * as crypto from "crypto";

export enum ResponseStatus {
    OK = "OK",
    BAD_OTP = "BAD_OTP",
    REPLAYED_OTP = "REPLAYED_OTP",
    BAD_SIGNATURE = "BAD_SIGNATURE",
    MISSING_PARAMETER = "MISSING_PARAMETER",
    NO_SUCH_CLIENT = "NO_SUCH_CLIENT",
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED",
    BACKEND_ERROR = "BACKEND_ERROR",
    NOT_ENOUGH_ANSWERS = "NOT_ENOUGH_ANSWERS",
    REPLAYED_REQUEST = "REPLAYED_REQUEST",
}

interface IResponse {
    otp: string;
    nonce: string;
    h: string;
    t: number;
    status: ResponseStatus;
    timestamp: string;
    sessioncounter: string;
    sessionuse: string;
    sl: number;
}

export class Response {
    /**
     * Creates a response from a string body
     * @param body {string} Body from the Yubico server
     * @returns {Response} Newly generated Response instance from the input
     */
    public static fromRawBody(body: string): Response {
        // Grab all the key balue pairs from the response and
        // split them into an array. We relace the \r\n's with \n's to
        // sanitize the response. Slice off the last 2 elements as they
        // are empty.
        const keyValuePairs = body
            .replace(/\r\n/g, "\n")
            .split("\n")
            .slice(0, -2);

        // Reduce the array in to an object that contains the key
        // value pairs from the response
        const values = keyValuePairs.reduce((accumulated, current) => {
            // Split the key and the value apart by the '='. Limit the value
            // in case the value contains an '=' in the base64 padding
            const [key, value] = current.split(/=(.+)/);

            // Add this key value pair to the object
            return Object.assign(accumulated, {
                [key]: value,
            });
        }, {}) as IResponse;

        // Return a Response instance from the parsed values
        return new Response(values.otp, values.nonce, values.h, values.t, values.status, values.timestamp, values.sessioncounter, values.sessionuse, values.sl);
    }

    constructor(
        private otp: string,
        private nonce: string,
        private h: string,
        private t: number,
        private status: ResponseStatus,
        private timestamp: string,
        private sessioncounter: string,
        private sessionuse: string,
        private sl: number,
    ) {}

    /**
     * Validate the request against the nonce, secret, and otp
     * @param nonce {string} Nonce used during the request
     * @param secret {string} Secret used to verify against
     * @param otp {string} OTP from when the key was pressed
     */
    public validate(nonce: string, secret: string, otp: string) {
        if (this.status !== ResponseStatus.OK) {
            const errorMessages = {
                [ResponseStatus.BAD_OTP]: "The OTP is invalid format",
                [ResponseStatus.REPLAYED_OTP]: "The OTP has already been seen by the service.",
                [ResponseStatus.BAD_SIGNATURE]: "The HMAC signature verification failed.",
                [ResponseStatus.MISSING_PARAMETER]: "The request lacks a parameter.",
                [ResponseStatus.NO_SUCH_CLIENT]: "The client id does not exist. If you just registered for one, please give it 10 minutes to propagate",
                [ResponseStatus.OPERATION_NOT_ALLOWED]: "The client id is not allowed to verify OTPs.",
                [ResponseStatus.BACKEND_ERROR]: "Unexpected error in our server. Please contact Yubico if you see this error.",
                [ResponseStatus.NOT_ENOUGH_ANSWERS]: "Server could not get requested number of syncs during before timeout.",
                [ResponseStatus.REPLAYED_REQUEST]: "Server has seen the OTP/Nonce combination before",
            };

            const errorMessage = errorMessages[this.status];

            if (!errorMessage) {
                throw new Error("Unknown status " + this.status);
            }

            throw new Error(errorMessage);
        }

        if (this.nonce !== nonce) {
            throw new Error("Nonces do not equal");
        }

        // Define the keys used in the hash
        const keys = ["nonce", "otp", "sessioncounter", "sessionuse", "sl", "status", "t", "timestamp"];

        // Concatenate all the keys as they would be used in a HTTP request
        const body = keys
            .filter((key) => (this as any)[key] !== undefined)
            .sort()
            .map((key) => key + "=" + (this as any)[key])
            .join("&");

        // Hash them to compare against the server's assertion
        const hash = crypto
            .createHmac("sha1", Buffer.from(secret, "base64"))
            .update(body)
            .digest("base64");

        // If the hashes diverge, the response should not be trusted and we throw an error
        if (hash !== this.h) {
            throw new Error("Hash provided from server and client hash do not match");
        }

        // If the OTPs don't match, throw an error as the response was tampered with
        // The hash should pick this up, but you can never be too sure
        if (this.otp !== otp) {
            throw new Error("OTPs do not match");
        }
    }

    /**
     * @returns {string} the one time password used in the request
     */
    public getOneTimePassword(): string {
        return this.otp;
    }

    /**
     * @returns {Date} Timestamp of the request in UTC
     */
    public getTimestampUTC(): Date {
        return new Date(this.t * 1000);
    }

    /**
     * @returns {Date} YubiKey internal timestamp value when key was pressed
     */
    public getTimestamp(): Date {
        return new Date(this.timestamp);
    }

    /**
     * @returns {number} YubiKey internal usage counter when key was pressed
     */
    public getSessionCounter(): number {
        return parseInt(this.sessioncounter, 10);
    }

    /**
     * @returns {number} YubiKey internal session usage counter when key was pressed
     */
    public getSessionUse(): number {
        return parseInt(this.sessionuse, 10);
    }

    /**
     * @returns {ResponseStatus} The status of the request. This will only show OK as all others will throw
     */
    public getStatus(): ResponseStatus {
        return this.status;
    }

    /**
     * @returns {string} The public ID is the first 12 bytes of the OTP, this does not change between each request and can be used to identify users
     */
    public getPublicId(): string {
        return this.otp.substr(0, 12);
    }

    /**
     * @returns {number} The serial number of the key described as a 48 bit number
     */
    public getSerialNumber(): number {
        const publicId = this.getPublicId();

        // Convert the modHex to a UIntBE as described here
        // https://developers.yubico.com/yubico-c/Manuals/modhex.1.html
        const modHexConversion = {
            b: "1",
            c: "0",
            d: "2",
            e: "3",
            f: "4",
            g: "5",
            h: "6",
            i: "7",
            j: "8",
            k: "9",
            l: "A",
            n: "B",
            r: "C",
            t: "D",
            u: "E",
            v: "F",
        };

        // Do the conversion and return the 48 bit integer
        return Buffer.from(
            publicId
                .split("")
                .map((char) => modHexConversion[char as keyof typeof modHexConversion])
                .join(""),
            "hex",
        ).readUIntBE(0, 6);
    }
}
