import * as crypto from "crypto";
import * as https from "https";
import { Response } from "./Response";

const API_SERVERS = [
    "api.yubico.com",
    "api2.yubico.com",
    "api3.yubico.com",
    "api4.yubico.com",
    "api5.yubico.com",
];

export type SL = number | "fast" | "secure";

export interface IYubicoConstructor {
    clientId: string;
    secret: string;
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

    constructor(input: IYubicoConstructor) {
        this.clientId = input.clientId;
        this.secret = input.secret;
        this.sl = input.sl;
        this.timeout = input.timeout;
        this.apiServers = input.apiServers ? input.apiServers : API_SERVERS;
    }

    /**
     * Verify a key against the Yubico servers
     * @param otp The OTP provided from the Yubikey to use to verify
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

        requestParams.sort();

        const hash = crypto
            .createHmac("sha1", Buffer.from(this.secret, "base64"))
            .update(requestParams.toString())
            .digest("base64");

        requestParams.append("h", hash);

        // Send an HTTPS request to the yubico servers and store the response body
        // As per the documentation, send a request to every API server and accept the first
        // response
        const body = await Promise.race(
            // Map over the servers, send a request to each host
            this.apiServers.map(
                (apiServer) =>
                    new Promise<string>((resolve, reject) => {
                        // Create a URL object for the request
                        const url = new URL(
                            "https://" + apiServer + "/wsapi/2.0/verify",
                        );

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
                                    reject(new Error("Response code not 200"));
                                } else {
                                    resolve(incomingData);
                                }
                            });
                        });

                        // If the request errors, reject with the error
                        req.on("error", reject);

                        // Close the write stream to send the request
                        req.end();
                    }),
            ),
        );

        // Create a response object from the raw body
        const response = Response.fromRawBody(body);

        // Validate the response
        response.validate(nonce, this.secret, otp);

        return response;
    }
}
