import * as crypto from "crypto";

enum ResponseStatus {
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
    public static fromRawBody(body: string) {
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
        return new Response(
            values.otp,
            values.nonce,
            values.h,
            values.t,
            values.status,
            values.timestamp,
            values.sessioncounter,
            values.sessionuse,
            values.sl,
        );
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
    ) {
        if (this.status !== ResponseStatus.OK) {
            const errorMessages = {
                [ResponseStatus.BAD_OTP]: "The OTP is invalid format",
                [ResponseStatus.REPLAYED_OTP]:
                    "The OTP has already been seen by the service.",
                [ResponseStatus.BAD_SIGNATURE]:
                    "The HMAC signature verification failed.",
                [ResponseStatus.MISSING_PARAMETER]:
                    "The request lacks a parameter.",
                [ResponseStatus.NO_SUCH_CLIENT]:
                    "The request id does not exist.",
                [ResponseStatus.OPERATION_NOT_ALLOWED]:
                    "The request id is not allowed to verify OTPs.",
                [ResponseStatus.BACKEND_ERROR]:
                    "Unexpected error in our server. Please contact Yubico if you see this error.",
                [ResponseStatus.NOT_ENOUGH_ANSWERS]:
                    "Server could not get requested number of syncs during before timeout.",
                [ResponseStatus.REPLAYED_REQUEST]:
                    "Server has seen the OTP/Nonce combination before",
            };

            const errorMessage = errorMessages[this.status];

            if (!errorMessage) {
                throw new Error("Unkown status " + this.status);
            }

            throw new Error(errorMessage);
        }
    }

    public validate(nonce: string, secret: string, otp: string) {
        if (this.nonce !== nonce) {
            throw new Error("Nonces do not equal");
        }

        const keys = [
            "nonce",
            "otp",
            "sessioncounter",
            "sessionuse",
            "sl",
            "status",
            "t",
            "timestamp",
        ];

        const body = keys
            .filter((key) => (this as any)[key] !== undefined)
            .sort()
            .map((key) => key + "=" + (this as any)[key])
            .join("&");

        const hash = crypto
            .createHmac("sha1", Buffer.from(secret, "base64"))
            .update(body)
            .digest("base64");

        if (hash !== this.h) {
            throw new Error(
                "Hash provided from server and client hash do not match",
            );
        }

        if (this.otp !== otp) {
            throw new Error("OTPs do not match");
        }
    }

    public getOneTimePassword() {
        return this.otp;
    }

    public getTimestampUTC() {
        return new Date(this.t * 1000);
    }

    public getTimestamp() {
        return new Date(this.timestamp);
    }

    public getSessionCounter() {
        return this.sessioncounter;
    }

    public getSessionUser() {
        return this.sessionuse;
    }

    public getStatus() {
        return this.status;
    }

    public getPublicId() {
        return this.otp.substr(0, 12);
    }

    public getSerialNumber() {
        const publicId = this.getPublicId();
        const modhexConversion = {
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
            m: "B",
            n: "C",
            r: "D",
            t: "E",
            u: "F",
            v: "G",
        };

        return Buffer.from(
            publicId
                .split("")
                .map((char) => (modhexConversion as any)[char])
                .join(""),
            "hex",
        ).readUIntBE(0, 6);
    }
}
