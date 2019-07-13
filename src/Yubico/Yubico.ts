import * as crypto from "crypto";
import * as https from "https";
import { Response, ResponseStatus } from "./Response";

// Default API servers provided from Yubico
const API_SERVERS = ["api.yubico.com", "api2.yubico.com", "api3.yubico.com", "api4.yubico.com", "api5.yubico.com"];

export type SL = number | "fast" | "secure";

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
export class Yubico {
    /**
     * The client ID obtained from Yubico
     */
    private clientId: string;

    /**
     * The secret obtained from Yubico
     */
    private secret: string;

    /**
     * The sync setting for the server to use.
     * From the Yubico Docs:
     *
     * A value 0 to 100 indicating percentage of syncing required by client,
     * or strings "fast" or "secure" to use server-configured values;
     * if absent, let the server decide
     *
     */
    private sl?: SL;

    /**
     * The timeout to wait for sync responses. Without this parameter, the
     * Yubico server will automatically decide
     */
    private timeout?: number;

    /**
     * The api servers to use for the request. This is only to be used if you are running
     * your own implementation of the Yubico verification servers. Otherwise, you should
     * leave this parameter blank and it will default to Yubico's.
     */
    private apiServers: string[];

    constructor(options?: IYubicoConstructor) {
        // Pull options from the constructor or from environment variables
        if (options && options.clientId) {
            this.clientId = options.clientId;
        } else {
            if (!process.env.YUBICO_CLIENT_ID) {
                throw new Error("Either clientId must be set in the constructor, or YUBICO_CLIENT_ID set as an environment variable");
            }
            this.clientId = process.env.YUBICO_CLIENT_ID;
        }

        if (options && options.secret) {
            this.secret = options.secret;
        } else {
            if (!process.env.YUBICO_SECRET) {
                throw new Error("Either clientId must be set in the constructor, or YUBICO_SECRET set as an environment variable");
            }
            this.secret = process.env.YUBICO_SECRET;
        }

        if (options && options.sl) {
            this.sl = options.sl;
        } else {
            this.sl = process.env.YUBICO_SL as SL;
        }

        if (options && options.timeout) {
            this.timeout = options.timeout;
        } else {
            this.timeout = process.env.YUBICO_TIMEOUT ? parseInt(process.env.YUBICO_TIMEOUT, 10) : undefined;
        }

        if (options && options.apiServers) {
            this.apiServers = options.apiServers;
        } else {
            this.apiServers = process.env.YUBICO_API_SERVERS ? process.env.YUBICO_API_SERVERS.split(",") : API_SERVERS;
        }
    }

    /**
     * Verify a key against the Yubico servers
     * @param otp {string} The OTP provided from the YubiKey to use to verify
     * @returns {Response} The response instance that can be picked apart for values like the serial number
     */
    public async verify(otp: string) {
        // Generate a nonce to send with the request
        // The Yubico docs state that the key can be between 16 and 40 characters long, so we
        // generate 20 bytes and convert it to 40 characters
        const nonce = crypto.randomBytes(16).toString("hex");

        // Generate the request params outside the http call so that we can generate the
        // hash for the request
        const requestParams = new URLSearchParams();

        // Append all of the required parameters
        requestParams.append("id", this.clientId);
        requestParams.append("otp", otp);
        requestParams.append("timestamp", "1");
        requestParams.append("nonce", nonce);

        if (this.sl) {
            requestParams.append("sl", this.sl as string);
        }

        if (this.timeout) {
            requestParams.append("timeout", this.timeout.toString());
        }

        // Sort them to properly allow for the security hash
        requestParams.sort();

        // Create and append the hash
        const hash = crypto
            .createHmac("sha1", Buffer.from(this.secret, "base64"))
            .update(requestParams.toString())
            .digest("base64");

        requestParams.append("h", hash);

        // Keep track of all the failed responses
        const failedResponses: Response[] = [];

        // Create an array of cancellations to allow for early stop should one server
        // respond successfully
        const cancellationCallbacks: Array<() => void> = [];

        const requestPromises = this.apiServers.map(
            (apiServer) =>
                new Promise<Response | undefined>((resolve) => {
                    // Create a URL object for the request
                    const url = new URL("https://" + apiServer + "/wsapi/2.0/verify");

                    // Set the search of the url to the request param string
                    url.search = requestParams.toString();

                    const req = https.get(url, (res) => {
                        // The data we get will be text, so parse as utf8
                        res.setEncoding("utf8");

                        // Collect the chunks of data as they come in
                        let incomingData = "";
                        res.on("data", (chunk) => {
                            incomingData += chunk;
                        });

                        // When the request is completed, check for the 200 status code and
                        // resolve with the data
                        res.on("end", () => {
                            if (res.statusCode !== 200) {
                                resolve(undefined);
                            } else {
                                resolve(Response.fromRawBody(incomingData));
                            }
                        });
                        res.on("error", () => resolve(undefined));
                    });

                    // Add a callback to allow the request to be cancelled
                    cancellationCallbacks.push(() => {
                        // Upon cancellation, abort the HTTP request and resolve
                        req.abort();
                        resolve(undefined);
                    });

                    // If the request errors, reject with the error
                    req.on("error", () => resolve(undefined));

                    // Close the write stream to send the request
                    req.end();
                }),
        );

        for await (const res of requestPromises) {
            // If there was no response, either the request was cancelled or the
            // network failed, so we can continue to the next one
            if (!res) {
                continue;
            }

            // Check the status to determine if we need to return it
            if (res.getStatus() === ResponseStatus.OK) {
                // Validate the response (this will throw if it fails)
                // If any one server fails to validate, everything should
                // fail because this means there is a possible man in the
                // middle attack.
                res.validate(nonce, this.secret, otp);
                // Cancel all of the remaining requests
                cancellationCallbacks.map((cb) => cb());

                return res;
            } else {
                // If the response status is not OK, push it on the failed responses array
                failedResponses.push(res);
            }
        }
        // If there were no failed responses (or successes as they would return)
        // throw a network error.
        if (failedResponses.length === 0) {
            throw new Error("Yubico API server network error");
        }

        // Validate one of the failed responses to throw the appropriate error
        failedResponses[0].validate(nonce, this.secret, otp);

        // Return the response if no error throws (this code should be unreachable)
        return failedResponses[0];
    }
}
